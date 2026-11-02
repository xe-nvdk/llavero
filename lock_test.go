package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.pkv")

	first, err := lockVault(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if !vaultInUse(vaultPath) {
		t.Fatal("vaultInUse = false while the lock is held")
	}
	if _, err := lockVault(vaultPath); !errors.Is(err, errVaultLocked) {
		t.Fatalf("second lockVault: err = %v, want errVaultLocked", err)
	}

	// Every spelling of the path must map to the same lock.
	link := filepath.Join(dir, "link.pkv")
	if err := os.WriteFile(vaultPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(vaultPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := lockVault(link); !errors.Is(err, errVaultLocked) {
		t.Fatalf("lockVault via symlink: err = %v, want errVaultLocked", err)
	}

	first.unlock()
	if vaultInUse(vaultPath) {
		t.Fatal("vaultInUse = true after unlock")
	}
	again, err := lockVault(vaultPath)
	if err != nil {
		t.Fatalf("relock after unlock: %v", err)
	}
	again.unlock()
}

func TestVaultInUseWithoutLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pkv")
	if vaultInUse(path) {
		t.Fatal("vaultInUse = true with no lock file")
	}
	if _, err := os.Stat(lockPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("vaultInUse must not create a lock file")
	}
}

// holdLock simulates a running daemon on vaultPath for the rest of the test.
func holdLock(t *testing.T, vaultPath string) {
	t.Helper()
	l, err := lockVault(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.unlock)
}

func TestWritersRefuseLockedVault(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.pkv")
	backup := filepath.Join(dir, "backup.pkv")
	seedPassphraseVault(t, vaultPath, []byte("vault-passphrase"), testStoredCred("example.test", "alice", 1, "cred-alice"))
	seedPassphraseVault(t, backup, []byte("backup-passphrase"), testStoredCred("example.test", "bob", 1, "cred-bob"))
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	holdLock(t, vaultPath)

	opts, closeFDs := importOpts(t, vaultPath, "vault-passphrase", "backup-passphrase")
	defer closeFDs()
	if err := runImport(opts, backup); err == nil || !strings.Contains(err.Error(), "refusing to import") {
		t.Fatalf("import into a locked vault: err = %v", err)
	}

	forgetFD, closeForget := pipePassphrase(t, "vault-passphrase")
	defer closeForget()
	if err := runForget(options{vaultPath: vaultPath, passFD: forgetFD, forget: "example.test"}); err == nil ||
		!strings.Contains(err.Error(), "refusing to forget") {
		t.Fatalf("-forget on a locked vault: err = %v", err)
	}

	rekeyFD, closeRekey := pipePassphrase(t, "vault-passphrase")
	defer closeRekey()
	newFD, closeNew := pipePassphrase(t, "another-passphrase")
	defer closeNew()
	// The lock is taken before the vault is even opened, so a same-mode rekey
	// (otherwise a no-op) is enough to see the refusal without a TPM.
	if err := runRekey(options{vaultPath: vaultPath, passFD: rekeyFD, newPassFD: newFD, rekeyTo: "passphrase"}); err == nil ||
		!strings.Contains(err.Error(), "refusing to rekey") {
		t.Fatalf("-rekey on a locked vault: err = %v", err)
	}

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused writer still changed the vault")
	}
	matches, _ := filepath.Glob(vaultPath + ".bak-*")
	if len(matches) != 0 {
		t.Fatalf("a refused writer left backups: %v", matches)
	}
}

func TestExportRefusesLockedDestinationEvenWithForce(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.pkv")
	other := filepath.Join(dir, "elsewhere.pkv") // a service on a custom -vault
	seedPassphraseVault(t, src, []byte("source-passphrase"), testStoredCred("example.test", "alice", 1, "cred-alice"))
	seedPassphraseVault(t, other, []byte("other-passphrase"), testStoredCred("example.test", "carol", 9, "cred-carol"))
	before, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	holdLock(t, other)

	opts, closeFDs := exportOpts(t, src, "source-passphrase", "backup-passphrase", true)
	defer closeFDs()
	if err := runExport(opts, other); err == nil || !strings.Contains(err.Error(), "running llavero has it open") {
		t.Fatalf("export -force onto a locked vault: err = %v", err)
	}
	after, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("export -force replaced a vault a running llavero holds")
	}
}
