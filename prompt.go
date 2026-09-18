package main

// User-facing approval. Every credential creation and every assertion goes
// through here, so that a compromised browser tab cannot silently mint or use
// a passkey.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
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

// menuApprover drives Omarchy's native picker, so the dialog matches the rest
// of the desktop instead of introducing another toolkit.
type menuApprover struct {
	binary string
}

func newMenuApprover() (*menuApprover, error) {
	path, err := exec.LookPath("omarchy-menu-select")
	if err != nil {
		return nil, errors.New("omarchy-menu-select not found on PATH")
	}
	// Without a display the picker cannot appear, and every request would be
	// refused with no visible reason. Catch that here rather than letting it
	// look like the user declining over and over.
	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		return nil, errors.New("no WAYLAND_DISPLAY or DISPLAY in the environment, so no prompt could be shown")
	}
	return &menuApprover{binary: path}, nil
}

func (m *menuApprover) confirm(title string, choices []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), approvalTimeout)
	defer cancel()

	args := append([]string{title}, choices...)
	cmd := exec.CommandContext(ctx, m.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("timed out waiting for approval")
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// A non-zero exit means either "dismissed with Escape" or "could
			// not launch". Those must not be conflated: the first is a
			// decision, the second is a broken prompt that would silently
			// refuse every request. Anything on stderr means the latter.
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return "", fmt.Errorf("approval prompt failed to run: %s", msg)
			}
			return "", nil
		}
		return "", err
	}
	return menuSelection(out), nil
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
