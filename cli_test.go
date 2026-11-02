package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain lets a test run the real binary entry point, flag parsing and
// all, by re-executing the test binary with LLAVERO_RUN_MAIN set.
func TestMain(m *testing.M) {
	if os.Getenv("LLAVERO_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type cliResult struct {
	out  string
	code int
}

// runCLI runs llavero with args. Each passphrase is fed on its own pipe, as
// fd 3, 4, ... in order. XDG_DATA_HOME points at dataHome so the default
// vault is a test file, never the real one.
func runCLI(t *testing.T, dataHome string, passphrases []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-mlock=false"}, args...)...)
	cmd.Env = append(os.Environ(), "LLAVERO_RUN_MAIN=1", "XDG_DATA_HOME="+dataHome)
	for _, p := range passphrases {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(p + "\n")); err != nil {
			t.Fatal(err)
		}
		w.Close()
		defer r.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return cliResult{out: buf.String(), code: code}
}

// Go's flag package stops at the first non-flag argument, so flags after the
// command used to be silently ignored: "import b.pkv -vault X" merged into the
// default vault, and "export f -force" ran without -force.
func TestCLIRejectsFlagsAfterCommand(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other.pkv")
	backup := filepath.Join(dir, "backup.pkv")
	seedPassphraseVault(t, other, []byte("other-pass"), testStoredCred("example.test", "alice", 1, "alice"))
	seedPassphraseVault(t, backup, []byte("backup-pass"), testStoredCred("other.test", "bob", 1, "bob"))

	r := runCLI(t, dir, []string{"other-pass", "backup-pass"},
		"-passphrase-fd", "3", "-new-passphrase-fd", "4", "import", backup, "-vault", other)
	if r.code == 0 {
		t.Fatalf("import with a trailing -vault succeeded:\n%s", r.out)
	}
	if !strings.Contains(r.out, "before the command") {
		t.Fatalf("unhelpful error:\n%s", r.out)
	}
	if _, err := os.Stat(defaultVaultPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("import touched the default vault")
	}
	if _, err := os.Stat(filepath.Join(dir, "llavero")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("import created the default vault directory")
	}

	r = runCLI(t, dir, []string{"other-pass", "new-backup-pass"},
		"-vault", other, "-passphrase-fd", "3", "-new-passphrase-fd", "4", "export", backup, "-force")
	if r.code == 0 || !strings.Contains(r.out, "before the command") {
		t.Fatalf("export with a trailing -force: code %d\n%s", r.code, r.out)
	}
}

func TestParseCommand(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		cmd     string
		wantErr string
	}{
		{nil, "", ""},
		{[]string{"export", "f"}, "export", ""},
		{[]string{"import", "f"}, "import", ""},
		{[]string{"export"}, "", "usage: llavero [flags] export FILE"},
		{[]string{"import", "f", "-vault", "x"}, "", "before the command"},
		{[]string{"export", "f", "g"}, "", "exactly one FILE"},
		{[]string{"frobnicate"}, "", "unknown command"},
	} {
		cmd, _, err := parseCommand(tc.args)
		if tc.wantErr == "" {
			if err != nil || cmd != tc.cmd {
				t.Errorf("%v: cmd %q err %v", tc.args, cmd, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%v: err %v, want %q", tc.args, err, tc.wantErr)
		}
	}
}

// Importing into a path with no vault creates one. That must be said
// plainly, since a typo in -vault would otherwise look like a normal restore.
func TestCLIImportReportsNewVault(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "backup.pkv")
	seedPassphraseVault(t, backup, []byte("backup-pass"), testStoredCred("other.test", "bob", 1, "bob"))
	fresh := filepath.Join(dir, "fresh.pkv")

	r := runCLI(t, dir, []string{"fresh-pass1", "backup-pass"},
		"-vault", fresh, "-passphrase-fd", "3", "-new-passphrase-fd", "4", "import", backup)
	if r.code != 0 {
		t.Fatalf("import into a fresh vault failed:\n%s", r.out)
	}
	if !strings.Contains(r.out, "into a NEW vault at "+fresh) {
		t.Fatalf("import did not report creating a new vault:\n%s", r.out)
	}
}
