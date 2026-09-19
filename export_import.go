package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var errExportExists = errors.New("destination already exists (pass -force to overwrite)")

// runExport writes a passphrase-backed portable vault. The live file is only
// read, so this is safe while the service is running.
func runExport(opts options, dest string) error {
	dest, err := normalizePortablePath(dest, "export")
	if err != nil {
		return err
	}
	if sameFile(dest, opts.vaultPath) {
		return errors.New("refusing to export onto the live vault; pick a different path")
	}
	if _, err := os.Stat(opts.vaultPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("vault %s does not exist", opts.vaultPath)
	}
	if _, err := os.Stat(dest); err == nil && !opts.force {
		return fmt.Errorf("%s: %w", dest, errExportExists)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
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

	if err := v.exportPortable(dest, newPass); err != nil {
		cleanupExportSiblings(dest)
		return fmt.Errorf("export failed: %w", err)
	}
	cleanupExportSiblings(dest)

	if err := verifyPortableExport(dest, newPass, want); err != nil {
		_ = os.Remove(dest)
		cleanupExportSiblings(dest)
		return err
	}
	logf("exported %d passkey(s) to %s", len(want), dest)
	logf("verified: the backup reopens under the new passphrase and is not TPM-bound")
	return nil
}

// runImport merges a portable backup into the current vault. Colliding
// (rpId, userId) pairs keep the credential with the higher signature counter.
func runImport(opts options, src string) error {
	src, err := normalizePortablePath(src, "import")
	if err != nil {
		return err
	}
	if sameFile(src, opts.vaultPath) {
		return errors.New("refusing to import a vault into itself")
	}
	if serviceHasOpen(opts.vaultPath) {
		return errors.New("the llavero service is running against this vault and holds its own\n" +
			"       copy in memory, so its next write would overwrite anything imported here.\n" +
			"       Stop it first:  systemctl --user stop llavero.service")
	}

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

	added, replaced, kept, err := v.mergeCredentials(incoming.list())
	if err != nil {
		return err
	}
	logf("imported %s: %d added, %d replaced (higher sign count), %d kept",
		src, added, replaced, kept)
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
	wantIDs := make(map[string]struct{}, len(want))
	for _, c := range want {
		wantIDs[string(c.ID)] = struct{}{}
	}
	for _, c := range got {
		if _, ok := wantIDs[string(c.ID)]; !ok {
			return errors.New("exported vault credentials do not match the source")
		}
	}
	return nil
}

// cleanupExportSiblings removes the leftovers the old copy-then-rekey
// workaround left behind: a sealed blob and timestamped .bak-* files.
func cleanupExportSiblings(dest string) {
	_ = os.Remove(tpmBlobPath(dest))
	matches, err := filepath.Glob(dest + ".bak-*")
	if err != nil {
		return
	}
	for _, m := range matches {
		_ = os.Remove(m)
	}
}
