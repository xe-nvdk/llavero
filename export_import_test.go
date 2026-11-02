package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCredID derives a 32-byte credential id from a readable label, so tests
// can build realistic records and still assert on them by name.
func testCredID(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

// testStoredCred builds a record shaped like one addCredential writes: a
// 32-byte id and a real P-256 PKCS#8 key.
func testStoredCred(rp, user string, count uint32, id string) storedCredential {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return storedCredential{
		ID:         testCredID(id),
		RPID:       rp,
		UserID:     []byte(user),
		UserName:   user,
		PrivateKey: pkcs8,
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
	opts := options{vaultPath: vaultPath, passFD: srcFD, newPassFD: newFD, force: force}
	return opts, func() { srcClose(); newClose() }
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

func TestImportMergeNonCollision(t *testing.T) {
	dir := t.TempDir()
	current := seedPassphraseVault(t, filepath.Join(dir, "vault.pkv"), []byte("current-pass"),
		testStoredCred("example.test", "alice", 2, "local-alice"),
	)
	incoming := []storedCredential{
		testStoredCred("other.test", "bob", 5, "backup-bob"),
	}

	res, err := current.mergeCredentials(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if res != (mergeResult{Added: 1}) {
		t.Fatalf("merge stats %+v, want 1 added", res)
	}

	got := current.list()
	if len(got) != 2 {
		t.Fatalf("count = %d, want 2", len(got))
	}
	ids := map[string]bool{}
	for _, c := range got {
		ids[string(c.ID)] = true
	}
	if !ids[string(testCredID("local-alice"))] || !ids[string(testCredID("backup-bob"))] {
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
	// The local and backup keys for alice are different ids, so both stay.
	if got.count() != 3 {
		t.Fatalf("count = %d, want 3", got.count())
	}
	ids := map[string]bool{}
	for _, c := range got.list() {
		ids[string(c.ID)] = true
	}
	for _, want := range []string{"local-alice", "backup-alice", "backup-carol"} {
		if !ids[string(testCredID(want))] {
			t.Fatalf("missing %s after import", want)
		}
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

// A re-registered passkey starts at counter 0 under a new id. An older backup
// of the same account must not displace it: counters of different ids are not
// comparable, and losing the local key can lock the user out.
func TestImportNeverDisplacesLocalKey(t *testing.T) {
	dir := t.TempDir()
	local := testStoredCred("example.test", "alice", 0, "new-alice")
	current := seedPassphraseVault(t, filepath.Join(dir, "vault.pkv"), []byte("current-pass"), local)
	backup := testStoredCred("example.test", "alice", 9, "old-alice")

	res, err := current.mergeCredentials([]storedCredential{backup})
	if err != nil {
		t.Fatal(err)
	}
	if res != (mergeResult{Added: 1}) {
		t.Fatalf("merge stats %+v, want 1 added", res)
	}

	got := map[string]storedCredential{}
	for _, c := range current.list() {
		got[string(c.ID)] = c
	}
	l, ok := got[string(local.ID)]
	if !ok {
		t.Fatal("import destroyed the local re-registered key")
	}
	if !bytes.Equal(l.PrivateKey, local.PrivateKey) || l.SignCount != 0 {
		t.Fatal("import altered the local key")
	}
	if _, ok := got[string(backup.ID)]; !ok {
		t.Fatal("import dropped the backup key for the same account; both should be kept")
	}
	// The local key must stay the one a discoverable sign-in picks.
	if m := current.findForRP("example.test", nil); len(m) != 2 || !bytes.Equal(m[0].ID, local.ID) {
		t.Fatalf("findForRP order: local key is not preferred")
	}
}

// Same credential id: one copy, the higher counter, and the local key bytes.
func TestImportSameIDTakesMaxCounter(t *testing.T) {
	dir := t.TempDir()
	a := testStoredCred("example.test", "alice", 3, "cred-alice")
	b := testStoredCred("example.test", "bob", 5, "cred-bob")
	current := seedPassphraseVault(t, filepath.Join(dir, "vault.pkv"), []byte("current-pass"), a, b)

	aBackup := cloneCredential(a)
	aBackup.SignCount = 9
	aBackup.PrivateKey = testStoredCred("x", "x", 0, "x").PrivateKey
	bBackup := cloneCredential(b)
	bBackup.SignCount = 1

	res, err := current.mergeCredentials([]storedCredential{aBackup, bBackup})
	if err != nil {
		t.Fatal(err)
	}
	if res != (mergeResult{Updated: 1, Unchanged: 1}) {
		t.Fatalf("merge stats %+v, want 1 updated, 1 unchanged", res)
	}
	got := current.list()
	if len(got) != 2 {
		t.Fatalf("count = %d, want 2 (same id must not duplicate)", len(got))
	}
	for _, c := range got {
		switch {
		case bytes.Equal(c.ID, a.ID):
			if c.SignCount != 9 || !bytes.Equal(c.PrivateKey, a.PrivateKey) {
				t.Fatalf("alice: count %d (want 9), key replaced=%v", c.SignCount, !bytes.Equal(c.PrivateKey, a.PrivateKey))
			}
		case bytes.Equal(c.ID, b.ID):
			if c.SignCount != 5 {
				t.Fatalf("bob: count %d, want 5 (counter must never go down)", c.SignCount)
			}
		}
	}
}
