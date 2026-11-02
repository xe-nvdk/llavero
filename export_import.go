package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errExportExists = errors.New("destination already exists (pass -force to overwrite)")

// runExport writes a passphrase-backed portable vault. The live file is only
// read, so this is safe while the service is running.
func runExport(opts options, dest string) error {
	dest, err := normalizePortablePath(dest, "export")
	if err != nil {
		return err
	}
	if _, err := os.Stat(opts.vaultPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("vault %s does not exist", opts.vaultPath)
	}
	if err := checkExportDest(dest, opts.vaultPath, opts.force); err != nil {
		return err
	}

	v, err := loadVault(opts)
	if err != nil {
		return err
	}
	want := v.list()

	newPass, err := readPassphrase(opts.newPassFD, true, "backup ", "")
	if err != nil {
		return err
	}
	defer zero(newPass)
	// The terminal prompt already enforces this; a passphrase from a file
	// descriptor does not, and a backup is the one copy of the vault that an
	// attacker can take away and guess at offline.
	if len(newPass) < minPassphraseLen {
		return fmt.Errorf("backup %w", errPassphraseTooShort)
	}

	// Write and verify under a temporary name in dest's directory, then
	// rename over dest. Until the rename, an existing dest is untouched, and
	// on any failure only the temporary file is removed.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".llavero-export-*.pkv")
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := v.exportPortable(tmpPath, newPass); err != nil {
		return fmt.Errorf("export failed: %w", err)
	}
	if err := verifyExport(tmpPath, newPass, want); err != nil {
		return err
	}
	// Re-check right before replacing anything, in case dest changed while
	// the passphrase was being typed.
	if err := checkExportDest(dest, opts.vaultPath, opts.force); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("export failed: %w", err)
	}
	committed = true
	syncDir(filepath.Dir(dest))
	logf("exported %d passkey(s) to %s", len(want), dest)
	logf("verified: the backup reopens under the new passphrase and is not TPM-bound")
	return nil
}

// runImport merges a portable backup into the current vault. It only adds
// credentials or raises counters; it never removes a local key.
func runImport(opts options, src string) error {
	src, err := normalizePortablePath(src, "import")
	if err != nil {
		return err
	}
	if sameFile(src, opts.vaultPath) || sameInode(src, opts.vaultPath) {
		return errors.New("refusing to import a vault into itself")
	}
	// Only a passphrase-only file is a portable backup. Anything else would
	// send openVault to this machine's TPM for a blob sealed somewhere else.
	// Checked before any passphrase is asked for.
	mode, err := readVaultHeader(src)
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	if mode != modePassphrase {
		return fmt.Errorf("%s is a %s vault, not a portable backup; create one with  llavero export FILE", src, mode)
	}
	lock, err := lockForWrite(opts.vaultPath, "import")
	if err != nil {
		return err
	}
	defer lock.unlock()

	_, statErr := os.Stat(opts.vaultPath)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	isNew := errors.Is(statErr, os.ErrNotExist)

	v, err := loadVault(opts)
	if err != nil {
		return err
	}

	backupPass, err := readPassphrase(opts.newPassFD, false, "", "Backup passphrase: ")
	if err != nil {
		return err
	}
	defer zero(backupPass)

	incoming, err := openVault(src, backupPass)
	if err != nil {
		return fmt.Errorf("opening backup %s: %w", src, err)
	}

	// Copy the vault aside before it is rewritten, as -rekey does. A freshly
	// created vault holds nothing worth keeping.
	var saved string
	beforeWrite := func() error {
		if isNew {
			return nil
		}
		b, err := backupVaultFile(opts.vaultPath)
		if err != nil {
			return fmt.Errorf("could not back up the vault, refusing to import: %w", err)
		}
		saved = b
		logf("backed up the existing vault to %s", b)
		return nil
	}
	res, err := v.mergeCredentials(incoming.list(), beforeWrite)
	if err != nil {
		if saved != "" {
			return fmt.Errorf("import failed (your backup at %s is still good): %w", saved, err)
		}
		return err
	}
	for _, why := range res.Invalid {
		logf("skipped invalid record in backup: %s", why)
	}
	for _, why := range res.Conflicts {
		logf("skipped conflicting record in backup: %s", why)
	}
	target := opts.vaultPath
	if isNew {
		target = "a NEW vault at " + opts.vaultPath + " (no vault existed there)"
	}
	logf("imported %s into %s: %d added, %d counter(s) raised, %d unchanged, %d invalid skipped, %d conflicting skipped",
		src, target, res.Added, res.Updated, res.Unchanged, len(res.Invalid), len(res.Conflicts))
	return nil
}

func normalizePortablePath(path, cmd string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("usage: llavero %s FILE", cmd)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs, nil
}

// verifyPortableExport reopens dest the way -rekey proves the rewrite worked.
// Success also requires a passphrase-only file with no sibling TPM blob.
func verifyPortableExport(dest string, passphrase []byte, want []storedCredential) error {
	check, err := openVault(dest, passphrase)
	if err != nil {
		return fmt.Errorf("the exported vault does not reopen: %w", err)
	}
	if check.mode != modePassphrase {
		return fmt.Errorf("exported vault is %s-locked; a portable backup must be passphrase-only", check.mode)
	}
	if _, err := os.Stat(tpmBlobPath(dest)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("exported vault still has a sealed TPM blob at %s", tpmBlobPath(dest))
	}
	got := check.list()
	if len(got) != len(want) {
		return fmt.Errorf("credential count changed during export (%d → %d)", len(want), len(got))
	}
	// Compare whole records, not just ids: a backup is only proof of
	// anything if every key, user handle and counter comes back exactly.
	wantByID := make(map[string][]byte, len(want))
	for _, c := range want {
		enc, err := json.Marshal(c)
		if err != nil {
			return err
		}
		wantByID[string(c.ID)] = enc
	}
	for _, c := range got {
		enc, err := json.Marshal(c)
		if err != nil {
			return err
		}
		w, ok := wantByID[string(c.ID)]
		if !ok || !bytes.Equal(w, enc) {
			return fmt.Errorf("exported credential %x does not match the source", c.ID[:4])
		}
		delete(wantByID, string(c.ID))
	}
	if len(wantByID) != 0 {
		return errors.New("exported vault is missing credentials from the source")
	}
	return nil
}

// verifyExport is verifyPortableExport, swappable so tests can make it fail.
var verifyExport = verifyPortableExport

// checkExportDest refuses destinations that are, or look like, a vault in
// use. Some of these hold even with -force, because overwriting them would
// destroy passkeys rather than a stale backup:
//
//   - the source vault, by any path (symlink, hardlink, relative spelling);
//   - the default vault, which is what the service runs against;
//   - any file with a <dest>.tpm beside it, i.e. a TPM-bound vault;
//   - any vault a running llavero holds the lock on, whatever its path.
//
// An existing file is otherwise only replaced with -force.
func checkExportDest(dest, source string, force bool) error {
	for _, live := range []struct{ path, what string }{
		{source, "the live vault being exported"},
		{defaultVaultPath(), "the default vault (the one the service uses)"},
	} {
		if sameFile(dest, live.path) || sameInode(dest, live.path) {
			return fmt.Errorf("refusing to export onto %s (%s); pick a different path", live.path, live.what)
		}
	}
	if vaultInUse(dest) {
		return fmt.Errorf("refusing to export onto %s: a running llavero has it open; pick a different path", dest)
	}
	if _, err := os.Lstat(tpmBlobPath(dest)); err == nil {
		return fmt.Errorf("refusing to export to %s: %s exists, so it is a TPM-bound vault; pick a different path",
			dest, tpmBlobPath(dest))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	fi, err := os.Stat(dest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to export to %s: not a regular file", dest)
	}
	if !force {
		if _, herr := readVaultHeader(dest); herr == nil {
			return fmt.Errorf("%s is a llavero vault: %w", dest, errExportExists)
		}
		return fmt.Errorf("%s: %w", dest, errExportExists)
	}
	return nil
}

// sameInode reports whether two existing paths are the same file, which also
// catches hardlinks that path comparison misses.
func sameInode(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// backupVaultFile copies the vault to <vault>.bak-<timestamp>. It never
// overwrites an existing file: a second backup in the same second gets a
// numeric suffix instead of replacing the first.
func backupVaultFile(vaultPath string) (string, error) {
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", err
	}
	base := fmt.Sprintf("%s.bak-%s", vaultPath, time.Now().Format("20060102-150405"))
	for i := 0; i < 100; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			os.Remove(name)
			return "", err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(name)
			return "", err
		}
		if err := f.Close(); err != nil {
			os.Remove(name)
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("too many backups named %s*", base)
}

// syncDir makes a rename durable. Failure is not fatal: the file is already
// in place, and some filesystems do not support syncing a directory.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
