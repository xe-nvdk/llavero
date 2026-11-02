package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Every process that writes a vault holds an exclusive flock on a sidecar
// <vault>.lock for as long as it might write: the daemon for its lifetime,
// import, -forget and -rekey for the duration of the command. The daemon
// keeps the vault in memory and rewrites it on every sign-in, so an offline
// edit made while it runs would be silently overwritten by its next save.
//
// The lock is on a sidecar rather than the vault itself because save()
// renames a fresh file over the vault, which would leave a lock on the vault
// inode guarding a file that no longer has a name. flock is released by the
// kernel when the process exits, however it exits, so a crash never leaves a
// vault locked. The lock file itself is left in place; it holds no data.

var errVaultLocked = errors.New("vault is in use by another llavero process")

type vaultLock struct{ f *os.File }

func lockPath(vaultPath string) string { return canonicalVaultPath(vaultPath) + ".lock" }

// canonicalVaultPath resolves symlinks so that every spelling of a vault
// path maps to the same lock file. A path that does not exist yet is made
// absolute, with its directory resolved if that exists.
func canonicalVaultPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(dir, filepath.Base(p))
	}
	return filepath.Clean(p)
}

// lockVault takes the writer lock on vaultPath without waiting. It fails with
// errVaultLocked if another process holds it.
func lockVault(vaultPath string) (*vaultLock, error) {
	path := lockPath(vaultPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening vault lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errVaultLocked
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return &vaultLock{f: f}, nil
}

func (l *vaultLock) unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	l.f.Close()
	l.f = nil
}

// vaultInUse reports whether some process holds the writer lock on
// vaultPath, without taking it. A path with no lock file has no writer.
func vaultInUse(vaultPath string) bool {
	f, err := os.Open(lockPath(vaultPath))
	if err != nil {
		return false
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.Is(err, unix.EWOULDBLOCK)
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return false
}

// lockForWrite is lockVault with an error message that tells the user what
// to do. what names the command, e.g. "import".
//
// The systemd check stays as a second guard after the lock is taken: a
// daemon from a build before the vault lock holds no lock at all, so until
// it is restarted on a new binary only the old check can see it.
func lockForWrite(vaultPath, what string) (*vaultLock, error) {
	l, err := lockVault(vaultPath)
	if errors.Is(err, errVaultLocked) {
		hint := "another llavero process"
		if serviceHasOpen(vaultPath) {
			hint = "the llavero service"
		}
		return nil, fmt.Errorf("refusing to %s: %s has %s open and holds its own copy\n"+
			"       in memory, so its next write would overwrite this one. Stop it first,\n"+
			"       e.g.  systemctl --user stop llavero.service", what, hint, vaultPath)
	}
	if err != nil {
		return nil, err
	}
	if serviceHasOpen(vaultPath) {
		l.unlock()
		return nil, fmt.Errorf("refusing to %s: llavero.service is running on %s without\n"+
			"       holding the vault lock (an older build?), and its next write would\n"+
			"       overwrite this one. Stop it first:  systemctl --user stop llavero.service",
			what, vaultPath)
	}
	return l, nil
}
