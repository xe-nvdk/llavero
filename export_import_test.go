package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStoredCred(rp, user string, count uint32, id string) storedCredential {
	return storedCredential{
		ID:         []byte(id),
		RPID:       rp,
		UserID:     []byte(user),
		UserName:   user,
		PrivateKey: []byte("pkcs8-" + id),
		SignCount:  count,
		CreatedAt:  time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
	}
}

func seedPassphraseVault(t *testing.T, path string, pass []byte, creds ...storedCredential) *vault {
	t.Helper()
	v, err := createVault(path, modePassphrase, pass)
	if err != nil {
		t.Fatal(err)
	}
	v.contents.Credentials = append([]storedCredential(nil), creds...)
	if err := v.save(); err != nil {
		t.Fatal(err)
	}
	return v
}

// pipePassphrase writes one line to a pipe and returns the read end as an fd
// for -passphrase-fd / -new-passphrase-fd. The File is kept alive so the fd
// is not closed by the garbage collector mid-test.
func pipePassphrase(t *testing.T, phrase string) (fd int, closer func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(phrase + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return int(r.Fd()), func() { r.Close() }
}

func exportOpts(t *testing.T, vaultPath string, vaultPass, backupPass string, force bool) (options, func()) {
	t.Helper()
	srcFD, srcClose := pipePassphrase(t, vaultPass)
	newFD, newClose := pipePassphrase(t, backupPass)
	return options{
		vaultPath: vaultPath,
		passFD:    srcFD,
		newPassFD: newFD,
		force:     force,
	}, func() {
		srcClose()
		newClose()
	}
}

func TestExportRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.pkv")
	dest := filepath.Join(dir, "backup.pkv")
	srcPass := "source-passphrase"
	seedPassphraseVault(t, src, []byte(srcPass), testStoredCred("example.test", "alice", 3, "cred-alice"))

	original := []byte("do-not-clobber")
	if err := os.WriteFile(dest, original, 0o600); err != nil {
		t.Fatal(err)
	}

	opts, closeFDs := exportOpts(t, src, srcPass, "backup-passphrase", false)
	defer closeFDs()
	err := runExport(opts, dest)
	if !errors.Is(err, errExportExists) {
		t.Fatalf("export without -force: err = %v, want %v", err, errExportExists)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("destination was overwritten without -force: %q", got)
	}

	opts, closeFDs = exportOpts(t, src, srcPass, "backup-passphrase", true)
	defer closeFDs()
	if err := runExport(opts, dest); err != nil {
		t.Fatalf("export -force: %v", err)
	}
	if _, err := openVault(dest, []byte("backup-passphrase")); err != nil {
		t.Fatalf("forced export did not write a readable vault: %v", err)
	}
}

func TestExportVerifiesBeforeSuccess(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.pkv")
	dest := filepath.Join(dir, "backup.pkv")
	srcPass := "source-passphrase"
	backupPass := "backup-passphrase"
	alice := testStoredCred("example.test", "alice", 4, "cred-alice")
	bob := testStoredCred("other.test", "bob", 1, "cred-bob")
	seedPassphraseVault(t, src, []byte(srcPass), alice, bob)

	opts, closeFDs := exportOpts(t, src, srcPass, backupPass, false)
	defer closeFDs()
	if err := runExport(opts, dest); err != nil {
		t.Fatal(err)
	}

	// Success means dest reopened under the backup passphrase with the same
	// credentials. The source vault must still open under the original one.
	check, err := openVault(dest, []byte(backupPass))
	if err != nil {
		t.Fatalf("exported vault will not reopen: %v", err)
	}
	if check.mode != modePassphrase {
		t.Fatalf("export mode = %s, want passphrase", check.mode)
	}
	if got := check.count(); got != 2 {
		t.Fatalf("exported count = %d, want 2", got)
	}
	if _, err := openVault(dest, []byte(srcPass)); err == nil {
		t.Fatal("exported vault opened with the source passphrase; it was not re-encrypted")
	}
	source, err := openVault(src, []byte(srcPass))
	if err != nil {
		t.Fatalf("source vault no longer opens: %v", err)
	}
	if source.count() != 2 {
		t.Fatalf("source count = %d, want 2 (export must be read-only)", source.count())
	}

	if err := verifyPortableExport(dest, []byte(backupPass), []storedCredential{alice, bob}); err != nil {
		t.Fatalf("verify of a good export: %v", err)
	}

	corrupt := filepath.Join(dir, "corrupt.pkv")
	if err := os.WriteFile(corrupt, []byte("not a vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPortableExport(corrupt, []byte(backupPass), []storedCredential{alice}); err == nil {
		t.Fatal("verifyPortableExport accepted a corrupt file")
	}
}

func TestExportLeavesNoTpmOrBak(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.pkv")
	dest := filepath.Join(dir, "backup.pkv")
	srcPass := "source-passphrase"
	seedPassphraseVault(t, src, []byte(srcPass), testStoredCred("example.test", "alice", 1, "cred-alice"))

	// Plant the leftovers the old copy-then-rekey workaround used to leave.
	if err := os.WriteFile(tpmBlobPath(dest), []byte("sealed-blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	staleBak := dest + ".bak-20200101-000000"
	if err := os.WriteFile(staleBak, []byte("old-backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("stale-export"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts, closeFDs := exportOpts(t, src, srcPass, "backup-passphrase", true)
	defer closeFDs()
	if err := runExport(opts, dest); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(tpmBlobPath(dest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("export left a TPM blob at %s", tpmBlobPath(dest))
	}
	if _, err := os.Stat(staleBak); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("export left %s", staleBak)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.bak-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("export left stray bak files: %v", matches)
	}
	matches, err = filepath.Glob(filepath.Join(dir, "*.tpm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("export left stray tpm files: %v", matches)
	}
}

func TestImportMergePrefersHigherCounter(t *testing.T) {
	dir := t.TempDir()
	current := seedPassphraseVault(t, filepath.Join(dir, "vault.pkv"), []byte("current-pass"),
		testStoredCred("example.test", "alice", 3, "local-alice"),
		testStoredCred("example.test", "bob", 8, "local-bob"),
		testStoredCred("example.test", "carol", 4, "local-carol"),
	)
	incoming := []storedCredential{
		testStoredCred("example.test", "alice", 9, "backup-alice"),
		testStoredCred("example.test", "bob", 2, "backup-bob"),
		testStoredCred("example.test", "carol", 4, "backup-carol"),
	}

	added, replaced, kept, err := current.mergeCredentials(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || replaced != 1 || kept != 2 {
		t.Fatalf("merge stats added=%d replaced=%d kept=%d, want 0/1/2", added, replaced, kept)
	}

	byUser := map[string]storedCredential{}
	for _, c := range current.list() {
		byUser[string(c.UserID)] = c
	}
	alice := byUser["alice"]
	if alice.SignCount != 9 || string(alice.ID) != "backup-alice" {
		t.Fatalf("alice = id %q count %d, want backup-alice / 9", alice.ID, alice.SignCount)
	}
	bob := byUser["bob"]
	if bob.SignCount != 8 || string(bob.ID) != "local-bob" {
		t.Fatalf("bob = id %q count %d, want local-bob / 8 (higher local counter)", bob.ID, bob.SignCount)
	}
	carol := byUser["carol"]
	if carol.SignCount != 4 || string(carol.ID) != "local-carol" {
		t.Fatalf("carol = id %q count %d, want local-carol / 4 (equal counter keeps current)", carol.ID, carol.SignCount)
	}
}

func TestImportMergeNonCollision(t *testing.T) {
	dir := t.TempDir()
	current := seedPassphraseVault(t, filepath.Join(dir, "vault.pkv"), []byte("current-pass"),
		testStoredCred("example.test", "alice", 2, "local-alice"),
	)
	incoming := []storedCredential{
		testStoredCred("other.test", "bob", 5, "backup-bob"),
	}

	added, replaced, kept, err := current.mergeCredentials(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || replaced != 0 || kept != 0 {
		t.Fatalf("merge stats added=%d replaced=%d kept=%d, want 1/0/0", added, replaced, kept)
	}

	got := current.list()
	if len(got) != 2 {
		t.Fatalf("count = %d, want 2", len(got))
	}
	ids := map[string]bool{}
	for _, c := range got {
		ids[string(c.ID)] = true
	}
	if !ids["local-alice"] || !ids["backup-bob"] {
		t.Fatalf("credentials = %v, want both local-alice and backup-bob", ids)
	}
}

func TestImportMergesThroughCommand(t *testing.T) {
	dir := t.TempDir()
	srcPass := "source-passphrase"
	backupPass := "backup-passphrase"
	currentPath := filepath.Join(dir, "vault.pkv")
	backupPath := filepath.Join(dir, "backup.pkv")
	seedPassphraseVault(t, currentPath, []byte(srcPass),
		testStoredCred("example.test", "alice", 1, "local-alice"),
	)
	seedPassphraseVault(t, backupPath, []byte(backupPass),
		testStoredCred("example.test", "alice", 6, "backup-alice"),
		testStoredCred("other.test", "carol", 1, "backup-carol"),
	)

	srcFD, srcClose := pipePassphrase(t, srcPass)
	defer srcClose()
	newFD, newClose := pipePassphrase(t, backupPass)
	defer newClose()
	err := runImport(options{vaultPath: currentPath, passFD: srcFD, newPassFD: newFD}, backupPath)
	if err != nil {
		t.Fatal(err)
	}

	got, err := openVault(currentPath, []byte(srcPass))
	if err != nil {
		t.Fatal(err)
	}
	if got.count() != 2 {
		t.Fatalf("count = %d, want 2", got.count())
	}
	var alice storedCredential
	for _, c := range got.list() {
		if string(c.UserID) == "alice" {
			alice = c
		}
	}
	if alice.SignCount != 6 || string(alice.ID) != "backup-alice" {
		t.Fatalf("alice = id %q count %d, want the imported higher-counter credential", alice.ID, alice.SignCount)
	}
}

func TestExportUsageAndSelfPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.pkv")
	if err := runExport(options{vaultPath: src}, ""); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("empty dest: %v", err)
	}
	seedPassphraseVault(t, src, []byte("source-passphrase"))
	opts, closeFDs := exportOpts(t, src, "source-passphrase", "backup-passphrase", true)
	defer closeFDs()
	if err := runExport(opts, src); err == nil || !strings.Contains(err.Error(), "live vault") {
		t.Fatalf("export onto self: %v", err)
	}
}
