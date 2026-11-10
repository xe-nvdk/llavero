package main

// User-facing approval. Every credential creation and every assertion goes
// through here, so that a compromised browser tab cannot silently mint or use
// a passkey.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// approvalTimeout is deliberately shorter than the browser's own WebAuthn
// timeout, so a user who walks away gets a clean decline rather than a hung
// dialog the browser has already given up on.
const approvalTimeout = 45 * time.Second

type approver interface {
	// confirm blocks until the user decides. A false return denies the
	// operation; an error means we could not ask at all, which also denies.
	confirm(title string, choices []string) (string, error)
}

// cmdResult is what a prompt command left behind. A non-zero exit is data, not
// an error, because "dismissed" and "could not launch" are told apart by it.
type cmdResult struct {
	out    string
	stderr string
	exit   int
}

// runFunc runs a prompt command. A non-nil error means it could not be run at
// all (or was cut off by ctx). It is a field so tests can fake the UI binaries.
type runFunc func(ctx context.Context, stdin, name string, args ...string) (cmdResult, error)

func execRun(ctx context.Context, stdin, name string, args ...string) (cmdResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := cmdResult{out: stdout.String(), stderr: stderr.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.exit = ee.ExitCode()
		return res, nil
	}
	return res, err
}

// backend describes how to ask one particular program.
type backend struct {
	name   string
	binary string
	// needsDisplay is false only for the terminal.
	needsDisplay bool
	// dialog backends use exit 1 for "Cancel" whatever they print to stderr
	// (GTK is chatty); any other non-zero exit is a failure. For the rest,
	// anything on stderr marks a failure and a silent non-zero exit is a
	// decision.
	dialog bool
	// build returns the arguments and stdin for one question, and a function
	// mapping the output of a successful run back to one of the choices ("" if
	// it matches none).
	build func(title string, choices []string) (args []string, stdin string, decode func(out string) string)
}

// isYesNo is the shape of every consent question: an action and "Cancel". An
// account picker also has two rows when a site has two accounts, but its rows
// never end in "Cancel".
func isYesNo(choices []string) bool {
	return len(choices) == 2 && choices[1] == "Cancel"
}

// display flattens a choice onto one visible line. The tab-separated
// label/subtext form is for omarchy-menu-select; other pickers get it spaced.
func display(choice string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(choice, "\t", "  ")), " ")
}

func displays(choices []string) []string {
	out := make([]string, len(choices))
	for i, c := range choices {
		out[i] = display(c)
	}
	return out
}

// byDisplay maps a picker's echoed line back to the original choice, so
// callers match on exactly the rows they passed in.
func byDisplay(choices []string) func(string) string {
	lines := displays(choices)
	return func(out string) string {
		out = strings.TrimSpace(out)
		for i, l := range lines {
			if l == out {
				return choices[i]
			}
		}
		return ""
	}
}

// dmenuBackend builds a backend for pickers that read rows on stdin and print
// the chosen row, with the title passed through promptFlag.
func dmenuBackend(name, binary string, fixed []string, promptFlag string) backend {
	return backend{name: name, binary: binary, needsDisplay: true,
		build: func(title string, choices []string) ([]string, string, func(string) string) {
			args := append(append([]string{}, fixed...), promptFlag, title+" ")
			return args, strings.Join(displays(choices), "\n") + "\n", byDisplay(choices)
		}}
}

// backends is in autodetection order. Titles reach zenity and kdialog as
// markup and contain site-supplied text, so those two escape them.
var backends = []backend{
	{name: "omarchy-menu-select", binary: "omarchy-menu-select", needsDisplay: true,
		build: func(title string, choices []string) ([]string, string, func(string) string) {
			return append([]string{title}, choices...), "", func(out string) string { return menuSelection([]byte(out)) }
		}},
	dmenuBackend("fuzzel", "fuzzel", []string{"--dmenu"}, "--prompt"),
	dmenuBackend("wofi", "wofi", []string{"--dmenu"}, "--prompt"),
	// tofi has no --dmenu flag; it is a dmenu-style picker whenever stdin is
	// a pipe.
	dmenuBackend("tofi", "tofi", nil, "--prompt-text"),
	dmenuBackend("rofi", "rofi", []string{"-dmenu"}, "-p"),
	{name: "zenity", binary: "zenity", needsDisplay: true, dialog: true,
		build: func(title string, choices []string) ([]string, string, func(string) string) {
			text := "--text=" + html.EscapeString(title)
			if isYesNo(choices) {
				return []string{"--question", "--title=Llavero", text,
						"--ok-label=" + choices[0], "--cancel-label=" + choices[1]},
					"", func(string) string { return choices[0] }
			}
			args := append([]string{"--list", "--title=Llavero", text, "--column=Account", "--"}, displays(choices)...)
			return args, "", byDisplay(choices)
		}},
	{name: "kdialog", binary: "kdialog", needsDisplay: true, dialog: true,
		build: func(title string, choices []string) ([]string, string, func(string) string) {
			title = html.EscapeString(title)
			if isYesNo(choices) {
				return []string{"--title", "Llavero", "--yes-label", choices[0],
						"--no-label", choices[1], "--yesno", "--", title},
					"", func(string) string { return choices[0] }
			}
			// --menu prints the tag, so use the index and map back through it.
			// "--" keeps a row that starts with "-" from being read as an option.
			args := []string{"--title", "Llavero", "--menu", title, "--"}
			for i, d := range displays(choices) {
				args = append(args, strconv.Itoa(i), d)
			}
			return args, "", func(out string) string {
				if i, err := strconv.Atoi(strings.TrimSpace(out)); err == nil && i >= 0 && i < len(choices) {
					return choices[i]
				}
				return ""
			}
		}},
}

// promptEnv is everything backend selection looks at, so it can be faked.
type promptEnv struct {
	lookPath func(string) (string, error)
	getenv   func(string) string
	run      runFunc
	tty      bool // stdin is a terminal
	// stdoutTTY is set when stdout is a terminal too. The terminal backend
	// needs both, so a daemon whose output is piped to a log is not
	// silently given a prompt nobody reads.
	stdoutTTY bool
	stdin     io.Reader
	stdout    io.Writer
	logf      func(string, ...any)
}

func osPromptEnv(logf func(string, ...any)) promptEnv {
	return promptEnv{lookPath: exec.LookPath, getenv: os.Getenv, run: execRun,
		tty: term.IsTerminal(int(os.Stdin.Fd())), stdoutTTY: term.IsTerminal(int(os.Stdout.Fd())),
		stdin: os.Stdin, stdout: os.Stdout, logf: logf}
}

// terminalName is the backend that asks on the controlling terminal.
const terminalName = "terminal"

// promptNames lists every value -prompt accepts, in autodetection order.
func promptNames() []string {
	names := make([]string, 0, len(backends)+1)
	for _, b := range backends {
		names = append(names, b.name)
	}
	return append(names, terminalName)
}

// newApprover picks the approval UI. want is "auto" (probe in the order of
// promptNames, terminal last and only with a TTY) or the name of one backend.
// It fails when nothing can show a prompt, so the daemon does not start and
// then refuse every request in a way that looks like the user clicking Cancel.
func newApprover(want string, env promptEnv) (approver, error) {
	hasDisplay := env.getenv("WAYLAND_DISPLAY") != "" || env.getenv("DISPLAY") != ""
	errNoDisplay := errors.New("no WAYLAND_DISPLAY or DISPLAY in the environment, so no prompt could be shown")

	if want == terminalName {
		if !env.tty || !env.stdoutTTY {
			return nil, errors.New("-prompt terminal needs stdin and stdout to be a TTY (run the daemon in a terminal)")
		}
		env.logf("approval prompt: %s (forced)", terminalName)
		return newTerminalApprover(env.stdin, env.stdout), nil
	}
	for _, b := range backends {
		if want != "auto" && want != b.name {
			continue
		}
		path, err := env.lookPath(b.binary)
		if err != nil {
			if want == "auto" {
				continue
			}
			return nil, fmt.Errorf("%s not found on PATH", b.binary)
		}
		if !hasDisplay {
			if want == "auto" {
				continue // the terminal below may still work
			}
			return nil, errNoDisplay
		}
		if want == "auto" {
			env.logf("approval prompt: %s (autodetected, %s)", b.name, path)
		} else {
			env.logf("approval prompt: %s (forced, %s)", b.name, path)
		}
		return &commandApprover{b: b, path: path, run: env.run}, nil
	}
	if want != "auto" {
		return nil, fmt.Errorf("unknown -prompt value %q (want auto or one of %s)", want, strings.Join(promptNames(), ", "))
	}
	if env.tty && env.stdoutTTY {
		env.logf("approval prompt: %s (autodetected, no graphical prompt found)", terminalName)
		return newTerminalApprover(env.stdin, env.stdout), nil
	}
	if !hasDisplay {
		return nil, errNoDisplay
	}
	return nil, errors.New("none of " + strings.Join(promptNames(), ", ") + " is available")
}

// displayFailureMarkers are stderr fragments showing a dialog never reached
// a display, so its exit 1 is not a Cancel. Matched case-insensitively. Keep
// this list small; anything unmatched on a dialog exit 1 is a decline.
var displayFailureMarkers = []string{"open display", "cannot connect", "could not connect"}

func isDisplayFailure(stderr string) bool {
	s := strings.ToLower(stderr)
	for _, m := range displayFailureMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// commandApprover shows the prompt by running an external program.
type commandApprover struct {
	b    backend
	path string
	run  runFunc
}

func (c *commandApprover) confirm(title string, choices []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), approvalTimeout)
	defer cancel()

	args, stdin, decode := c.b.build(title, choices)
	res, err := c.run(ctx, stdin, c.path, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("timed out waiting for approval")
	}
	if err != nil {
		return "", err
	}
	if res.exit != 0 {
		// A non-zero exit means either "dismissed" or "could not launch".
		// Those must not be conflated: the first is a decision, the second
		// is a broken prompt that would silently refuse every request.
		msg := strings.TrimSpace(res.stderr)
		if c.b.dialog && res.exit == 1 && !isDisplayFailure(msg) {
			return "", nil
		}
		// A negative exit means the process was killed by a signal, which
		// is never a decision.
		if res.exit < 0 || c.b.dialog || msg != "" {
			if msg == "" {
				msg = fmt.Sprintf("exit status %d", res.exit)
				if res.exit < 0 {
					msg = "killed by a signal"
				}
			}
			return "", fmt.Errorf("approval prompt failed to run: %s", msg)
		}
		return "", nil
	}
	return decode(res.out), nil
}

// terminalApprover asks on the terminal the daemon runs in.
type terminalApprover struct {
	lines chan string
	out   io.Writer
}

func newTerminalApprover(in io.Reader, out io.Writer) *terminalApprover {
	t := &terminalApprover{lines: make(chan string, 16), out: out}
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			t.lines <- sc.Text()
		}
		close(t.lines)
	}()
	return t
}

func (t *terminalApprover) confirm(title string, choices []string) (string, error) {
	// Drop anything typed while no question was pending, such as a reply
	// that arrived after the previous prompt timed out.
	for drained := false; !drained; {
		select {
		case <-t.lines:
		default:
			drained = true
		}
	}
	fmt.Fprintf(t.out, "\n%s\n", title)
	for i, d := range displays(choices) {
		fmt.Fprintf(t.out, "  %d) %s\n", i+1, d)
	}
	fmt.Fprintf(t.out, "choice [1-%d, anything else declines]: ", len(choices))

	select {
	case line, ok := <-t.lines:
		if !ok {
			return "", errors.New("terminal closed while waiting for approval")
		}
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && n >= 1 && n <= len(choices) {
			return choices[n-1], nil
		}
		return "", nil
	case <-time.After(approvalTimeout):
		return "", errors.New("timed out waiting for approval")
	}
}

// menuSelection keeps the picker result intact, including a trailing subtext.
// omarchy-menu-select returns "label\tsubtext" for three-field rows so callers
// can tell same-named entries apart. Stripping the subtext here would throw
// that key away and collapse two "alice" rows into the first one.
func menuSelection(out []byte) string {
	return strings.TrimSpace(string(out))
}

// autoApprover approves everything. Intended for headless testing only; main
// refuses to select it without an explicit flag.
type autoApprover struct{}

func (autoApprover) confirm(title string, choices []string) (string, error) {
	return choices[0], nil
}
