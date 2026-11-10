package main

import (
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type fakeCall struct {
	name  string
	args  []string
	stdin string
}

// fakeEnv has the given binaries on PATH and records what gets run.
func fakeEnv(present []string, vars map[string]string, tty bool, res cmdResult, runErr error) (promptEnv, *[]fakeCall, *[]string) {
	var calls []fakeCall
	var logs []string
	has := map[string]bool{}
	for _, p := range present {
		has[p] = true
	}
	return promptEnv{
		lookPath: func(n string) (string, error) {
			if has[n] {
				return "/bin/" + n, nil
			}
			return "", errors.New("not found")
		},
		getenv: func(k string) string { return vars[k] },
		run: func(_ context.Context, stdin, name string, args ...string) (cmdResult, error) {
			calls = append(calls, fakeCall{name, args, stdin})
			return res, runErr
		},
		tty:       tty,
		stdoutTTY: tty,
		stdin:     strings.NewReader(""),
		stdout:    io.Discard,
		logf:      func(f string, a ...any) { logs = append(logs, f) },
	}, &calls, &logs
}

func chosenName(t *testing.T, ap approver) string {
	t.Helper()
	switch v := ap.(type) {
	case *commandApprover:
		return v.b.name
	case *terminalApprover:
		return terminalName
	}
	t.Fatalf("unexpected approver %T", ap)
	return ""
}

func TestNewApproverSelection(t *testing.T) {
	wl := map[string]string{"WAYLAND_DISPLAY": "wayland-1"}
	all := []string{"omarchy-menu-select", "fuzzel", "wofi", "tofi", "rofi", "zenity", "kdialog"}
	tests := []struct {
		name    string
		want    string
		present []string
		env     map[string]string
		tty     bool
		pick    string // expected backend, "" when an error is expected
		errSub  string
	}{
		{"auto prefers omarchy", "auto", all, wl, false, "omarchy-menu-select", ""},
		{"auto skips missing", "auto", []string{"rofi", "zenity"}, wl, false, "rofi", ""},
		{"auto fuzzel before wofi", "auto", []string{"wofi", "fuzzel"}, wl, false, "fuzzel", ""},
		{"auto wofi before tofi", "auto", []string{"tofi", "wofi"}, wl, false, "wofi", ""},
		{"auto zenity before kdialog", "auto", []string{"kdialog", "zenity"}, wl, false, "zenity", ""},
		{"auto kdialog on X11", "auto", []string{"kdialog"}, map[string]string{"DISPLAY": ":0"}, false, "kdialog", ""},
		{"auto gui beats tty", "auto", []string{"zenity"}, wl, true, "zenity", ""},
		{"auto terminal fallback", "auto", nil, nil, true, "terminal", ""},
		{"auto nothing, no tty", "auto", nil, wl, false, "", "none of"},
		{"auto nothing, no display", "auto", nil, nil, false, "", "WAYLAND_DISPLAY"},
		{"auto binary but no display", "auto", []string{"zenity"}, nil, false, "", "WAYLAND_DISPLAY"},
		{"auto binary, no display, tty uses terminal", "auto", []string{"zenity"}, nil, true, "terminal", ""},
		{"forced overrides order", "kdialog", all, wl, false, "kdialog", ""},
		{"forced missing fails", "rofi", []string{"zenity"}, wl, false, "", "rofi not found"},
		{"forced no display", "zenity", all, nil, false, "", "WAYLAND_DISPLAY"},
		{"forced terminal", "terminal", nil, nil, true, "terminal", ""},
		{"forced terminal without tty", "terminal", nil, nil, false, "", "a TTY"},
		{"unknown", "dmenu", all, wl, true, "", "unknown -prompt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, logs := fakeEnv(tc.present, tc.env, tc.tty, cmdResult{}, nil)
			ap, err := newApprover(tc.want, env)
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err = %v, want substring %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := chosenName(t, ap); got != tc.pick {
				t.Fatalf("backend = %s, want %s", got, tc.pick)
			}
			if len(*logs) != 1 || !strings.Contains((*logs)[0], "approval prompt:") {
				t.Fatalf("expected one log line naming the backend, got %v", *logs)
			}
		})
	}
}

// The terminal backend needs stdin and stdout to both be terminals.
func TestTerminalNeedsStdinAndStdoutTTY(t *testing.T) {
	wl := map[string]string{"WAYLAND_DISPLAY": "wayland-1"}
	tests := []struct {
		name      string
		want      string
		present   []string
		env       map[string]string
		stdinTTY  bool
		stdoutTTY bool
		pick      string // expected backend, "" when an error is expected
		errSub    string
	}{
		{"auto both ttys", "auto", nil, nil, true, true, "terminal", ""},
		{"auto stdout piped", "auto", nil, wl, true, false, "", "none of"},
		{"auto stdout piped, no display", "auto", nil, nil, true, false, "", "WAYLAND_DISPLAY"},
		{"auto stdout piped, gui still used", "auto", []string{"zenity"}, wl, true, false, "zenity", ""},
		{"auto stdin piped", "auto", nil, wl, false, true, "", "none of"},
		{"forced terminal both ttys", "terminal", nil, nil, true, true, "terminal", ""},
		{"forced terminal stdout piped", "terminal", nil, nil, true, false, "", "a TTY"},
		{"forced terminal stdin piped", "terminal", nil, nil, false, true, "", "a TTY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := fakeEnv(tc.present, tc.env, tc.stdinTTY, cmdResult{}, nil)
			env.stdoutTTY = tc.stdoutTTY
			ap, err := newApprover(tc.want, env)
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err = %v, want substring %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := chosenName(t, ap); got != tc.pick {
				t.Fatalf("backend = %s, want %s", got, tc.pick)
			}
		})
	}
}

func TestPromptNamesCoverFlagDocs(t *testing.T) {
	names := promptNames()
	if names[0] != "omarchy-menu-select" || names[len(names)-1] != terminalName {
		t.Fatalf("unexpected order %v", names)
	}
}

func TestCommandApproverInvocation(t *testing.T) {
	yesNo := []string{"Use it", "Cancel"}
	rows := []string{"\talice\tabc · 2026-01-01", "\tbob\tdef"}
	tests := []struct {
		name    string
		backend string
		title   string
		choices []string
		res     cmdResult
		want    string
		args    []string
		stdin   string
	}{
		{"omarchy yes", "omarchy-menu-select", "T", yesNo, cmdResult{out: "Use it\n"}, "Use it",
			[]string{"T", "Use it", "Cancel"}, ""},
		{"omarchy keeps tab", "omarchy-menu-select", "T", rows, cmdResult{out: "alice\tabc · 2026-01-01\n"}, "alice\tabc · 2026-01-01",
			append([]string{"T"}, rows...), ""},
		{"fuzzel pick", "fuzzel", "T", yesNo, cmdResult{out: "Cancel\n"}, "Cancel",
			[]string{"--dmenu", "--prompt", "T "}, "Use it\nCancel\n"},
		{"wofi maps row back", "wofi", "T", rows, cmdResult{out: "bob def\n"}, rows[1],
			[]string{"--dmenu", "--prompt", "T "}, "alice abc · 2026-01-01\nbob def\n"},
		{"tofi", "tofi", "T", yesNo, cmdResult{out: "Use it\n"}, "Use it",
			[]string{"--prompt-text", "T "}, "Use it\nCancel\n"},
		{"rofi unknown line", "rofi", "T", yesNo, cmdResult{out: "typed junk\n"}, "",
			[]string{"-dmenu", "-p", "T "}, "Use it\nCancel\n"},
		{"zenity question", "zenity", "a<b>&", yesNo, cmdResult{}, "Use it",
			[]string{"--question", "--title=Llavero", "--text=a&lt;b&gt;&amp;", "--ok-label=Use it", "--cancel-label=Cancel"}, ""},
		{"zenity list", "zenity", "T", rows, cmdResult{out: "bob def\n"}, rows[1],
			[]string{"--list", "--title=Llavero", "--text=T", "--column=Account", "--", "alice abc · 2026-01-01", "bob def"}, ""},
		{"zenity cancel", "zenity", "T", yesNo, cmdResult{exit: 1, stderr: "Gtk-Message: noise"}, "",
			[]string{"--question", "--title=Llavero", "--text=T", "--ok-label=Use it", "--cancel-label=Cancel"}, ""},
		{"kdialog yesno", "kdialog", "T", yesNo, cmdResult{}, "Use it",
			[]string{"--title", "Llavero", "--yes-label", "Use it", "--no-label", "Cancel", "--yesno", "--", "T"}, ""},
		{"kdialog yesno dash title", "kdialog", "-T", yesNo, cmdResult{}, "Use it",
			[]string{"--title", "Llavero", "--yes-label", "Use it", "--no-label", "Cancel", "--yesno", "--", "-T"}, ""},
		{"kdialog menu", "kdialog", "T", rows, cmdResult{out: "1\n"}, rows[1],
			[]string{"--title", "Llavero", "--menu", "T", "--", "0", "alice abc · 2026-01-01", "1", "bob def"}, ""},
		{"kdialog no", "kdialog", "T", yesNo, cmdResult{exit: 1}, "",
			[]string{"--title", "Llavero", "--yes-label", "Use it", "--no-label", "Cancel", "--yesno", "--", "T"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, calls, _ := fakeEnv([]string{tc.backend}, map[string]string{"DISPLAY": ":0"}, false, tc.res, nil)
			ap, err := newApprover(tc.backend, env)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ap.confirm(tc.title, tc.choices)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("confirm = %q, want %q", got, tc.want)
			}
			c := (*calls)[0]
			if c.name != "/bin/"+tc.backend || !reflect.DeepEqual(c.args, tc.args) || c.stdin != tc.stdin {
				t.Errorf("ran %s %q stdin %q\nwant %q stdin %q", c.name, c.args, c.stdin, tc.args, tc.stdin)
			}
		})
	}
}

func TestCommandApproverFailures(t *testing.T) {
	yesNo := []string{"Use it", "Cancel"}
	tests := []struct {
		name    string
		backend string
		res     cmdResult
		runErr  error
		wantErr string // "" means a clean decline
	}{
		{"menu escape is a decision", "fuzzel", cmdResult{exit: 1}, nil, ""},
		{"menu stderr is a failure", "fuzzel", cmdResult{exit: 1, stderr: "no compositor"}, nil, "failed to run: no compositor"},
		{"launch error", "rofi", cmdResult{}, errors.New("exec failed"), "exec failed"},
		{"dialog odd exit is a failure", "zenity", cmdResult{exit: 255}, nil, "exit status 255"},
		{"dialog odd exit with stderr", "kdialog", cmdResult{exit: 2, stderr: "boom\n"}, nil, "boom"},
		{"zenity cancel with gtk noise", "zenity", cmdResult{exit: 1, stderr: "Gtk-Message: Failed to load module\n"}, nil, ""},
		{"zenity no display", "zenity", cmdResult{exit: 1, stderr: "Gtk-WARNING **: cannot open display: wayland-1\n"}, nil, "cannot open display"},
		{"zenity failed to open display", "zenity", cmdResult{exit: 1, stderr: "Failed to open display\n"}, nil, "Failed to open display"},
		{"kdialog cannot connect", "kdialog", cmdResult{exit: 1, stderr: "kdialog: Cannot connect to the X server\n"}, nil, "Cannot connect"},
		{"kdialog could not connect", "kdialog", cmdResult{exit: 1, stderr: "could not connect to bus\n"}, nil, "could not connect"},
		{"fuzzel killed by signal", "fuzzel", cmdResult{exit: -1}, nil, "killed by a signal"},
		{"rofi killed by signal", "rofi", cmdResult{exit: -1, stderr: ""}, nil, "killed by a signal"},
		{"zenity killed by signal", "zenity", cmdResult{exit: -1}, nil, "killed by a signal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := fakeEnv([]string{tc.backend}, map[string]string{"DISPLAY": ":0"}, false, tc.res, tc.runErr)
			ap, err := newApprover(tc.backend, env)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ap.confirm("T", yesNo)
			if tc.wantErr == "" {
				if err != nil || got != "" {
					t.Fatalf("got %q, %v; want a clean decline", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestTerminalApprover(t *testing.T) {
	choices := []string{"Use it", "Cancel"}
	tests := []struct {
		name, input, want string
		wantErr           bool
	}{
		{"first", "1\n", "Use it", false},
		{"second", " 2 \n", "Cancel", false},
		{"out of range declines", "3\n", "", false},
		{"junk declines", "yes\n", "", false},
		{"empty declines", "\n", "", false},
		{"eof is an error", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			ap := newTerminalApprover(strings.NewReader(tc.input), &out)
			got, err := ap.confirm("Create passkey?", choices)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %q, %v; want %q, err=%v", got, err, tc.want, tc.wantErr)
			}
			if !strings.Contains(out.String(), "Create passkey?") || !strings.Contains(out.String(), "1) Use it") {
				t.Errorf("question not shown: %q", out.String())
			}
		})
	}
}

// A row or a positional title that starts with "-" must reach zenity and
// kdialog as data, not as an option, so the builders put "--" before them.
func TestDialogBackendsTerminateOptionsBeforeRows(t *testing.T) {
	menu := []string{"--text=Approve", "--hide-header"}
	tests := []struct {
		name    string
		backend string
		title   string
		choices []string
		after   []string // arguments that must follow the "--"
	}{
		{"zenity rows", "zenity", "Sign in", menu, menu},
		{"kdialog rows", "kdialog", "Sign in", menu, menu},
		{"kdialog yesno title", "kdialog", "-Sign in", []string{"Use it", "Cancel"}, []string{"-Sign in"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b backend
			for _, cand := range backends {
				if cand.name == tc.backend {
					b = cand
				}
			}
			args, _, _ := b.build(tc.title, tc.choices)
			dd := -1
			for i, a := range args {
				if a == "--" {
					dd = i
					break
				}
			}
			if dd < 0 {
				t.Fatalf("no -- in %q", args)
			}
			for _, want := range tc.after {
				i := slices.Index(args, want)
				if i < 0 {
					t.Fatalf("%q missing from %q", want, args)
				}
				if i < dd {
					t.Errorf("%q at %d precedes -- at %d in %q", want, i, dd, args)
				}
			}
		})
	}
}
