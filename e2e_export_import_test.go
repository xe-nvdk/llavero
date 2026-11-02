package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End to end through the real CLI: credentials minted by addCredential, the
// way registration stores them, exported, imported into a fresh vault,
// re-imported, and the -force misuse cases.
func TestE2EExportImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir) // match the child, see runCLI
	const srcPass, bakPass, freshPass = "source-pass1", "backup-pass1", "fresh-pass1"
	src := filepath.Join(dir, "src.pkv")
	backup := filepath.Join(dir, "backup.pkv")
	fresh := filepath.Join(dir, "fresh.pkv")

	sv, err := createVault(src, modePassphrase, []byte(srcPass))
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := sv.addCredential(rpEntity{ID: "example.test"}, userEntity{ID: []byte("u-alice"), Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sv.addCredential(rpEntity{ID: "other.test"}, userEntity{ID: []byte("u-bob"), Name: "bob"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := sv.bumpSignCount(a.ID); err != nil {
			t.Fatal(err)
		}
	}

	mustOK := func(r cliResult, want ...string) {
		t.Helper()
		if r.code != 0 {
			t.Fatalf("exit %d:\n%s", r.code, r.out)
		}
		for _, w := range want {
			if !strings.Contains(r.out, w) {
				t.Fatalf("output lacks %q:\n%s", w, r.out)
			}
		}
	}
	mustFail := func(r cliResult, want string) {
		t.Helper()
		if r.code == 0 || !strings.Contains(r.out, want) {
			t.Fatalf("want failure mentioning %q, got exit %d:\n%s", want, r.code, r.out)
		}
	}
	pfd := []string{"-passphrase-fd", "3", "-new-passphrase-fd", "4"}
	cli := func(passes []string, args ...string) cliResult {
		return runCLI(t, dir, passes, args...)
	}

	// Export, then the backup lists under its own passphrase.
	mustOK(cli([]string{srcPass, bakPass}, append(append([]string{"-vault", src}, pfd...), "export", backup)...),
		"exported 2 passkey(s)", "verified")
	mustOK(cli([]string{bakPass}, "-vault", backup, "-passphrase-fd", "3", "-list"), "2 passkey(s)")

	// Import into a vault that does not exist yet.
	mustOK(cli([]string{freshPass, bakPass}, append(append([]string{"-vault", fresh}, pfd...), "import", backup)...),
		"into a NEW vault", "2 added, 0 counter(s) raised, 0 unchanged, 0 invalid skipped")

	// Re-import is a no-op and writes nothing, so no backup appears.
	freshBefore, _ := os.ReadFile(fresh)
	mustOK(cli([]string{freshPass, bakPass}, append(append([]string{"-vault", fresh}, pfd...), "import", backup)...),
		"0 added, 0 counter(s) raised, 2 unchanged")
	if got, _ := os.ReadFile(fresh); !bytes.Equal(got, freshBefore) {
		t.Fatal("no-op re-import rewrote the vault")
	}
	if baks, _ := filepath.Glob(fresh + ".bak-*"); len(baks) != 0 {
		t.Fatalf("no-op re-import wrote a backup: %v", baks)
	}

	// The imported keys are the source's keys, byte for byte.
	fv, err := openVault(fresh, []byte(freshPass))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{}
	for _, c := range sv.list() {
		want[string(c.ID)] = c.PrivateKey
	}
	for _, c := range fv.list() {
		if !bytes.Equal(want[string(c.ID)], c.PrivateKey) {
			t.Fatalf("imported key %x differs from the source", c.ID[:4])
		}
		if _, err := parsePrivateKey(c.PrivateKey); err != nil {
			t.Fatal(err)
		}
	}

	// Use alice on the source again, refresh the backup with -force (an
	// existing backup is a legitimate target), and import: the counter rises,
	// and this time the existing vault is backed up first.
	if _, err := sv.bumpSignCount(a.ID); err != nil {
		t.Fatal(err)
	}
	mustOK(cli([]string{srcPass, bakPass}, append(append([]string{"-vault", src, "-force"}, pfd...), "export", backup)...),
		"exported 2 passkey(s)")
	mustOK(cli([]string{freshPass, bakPass}, append(append([]string{"-vault", fresh}, pfd...), "import", backup)...),
		"0 added, 1 counter(s) raised, 1 unchanged", "backed up the existing vault")
	if baks, _ := filepath.Glob(fresh + ".bak-*"); len(baks) != 1 {
		t.Fatalf("backups after a changing import: %v", baks)
	}

	// Misuse. Snapshot everything that must survive.
	defaultVault := defaultVaultPath()
	if _, err := createVault(defaultVault, modePassphrase, []byte("default-pass")); err != nil {
		t.Fatal(err)
	}
	tpmDest := filepath.Join(dir, "tpmbound.pkv")
	os.WriteFile(tpmDest, []byte("tpm-vault"), 0o600)
	os.WriteFile(tpmBlobPath(tpmDest), []byte("sealed"), 0o600)
	snap := map[string][]byte{}
	for _, p := range []string{src, backup, fresh, defaultVault, tpmDest, tpmBlobPath(tpmDest)} {
		snap[p], _ = os.ReadFile(p)
	}

	exp := func(dest string, extra ...string) cliResult {
		args := append(append([]string{"-vault", src}, extra...), pfd...)
		return cli([]string{srcPass, bakPass}, append(args, "export", dest)...)
	}
	mustFail(exp(backup), "pass -force")
	mustFail(exp(src, "-force"), "refusing to export onto")
	mustFail(exp(defaultVault, "-force"), "refusing to export onto")
	mustFail(exp(tpmDest, "-force"), "TPM-bound")
	mustFail(cli([]string{srcPass, bakPass}, append(append([]string{"-vault", src}, pfd...), "export", backup, "-force")...),
		"flags must come before the command")
	mustFail(cli([]string{freshPass, bakPass}, append(pfd, "import", backup, "-vault", fresh)...),
		"flags must come before the command")
	mustFail(cli([]string{freshPass, freshPass}, append(append([]string{"-vault", fresh}, pfd...), "import", fresh)...),
		"into itself")

	for p, b := range snap {
		if got, _ := os.ReadFile(p); !bytes.Equal(got, b) {
			t.Fatalf("%s changed during the misuse cases", p)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".llavero-export-*")); len(left) != 0 {
		t.Fatalf("temporary export files left behind: %v", left)
	}
}
