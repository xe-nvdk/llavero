package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func TestFormatVersion(t *testing.T) {
	got := formatVersion("v0.1.0", "230caa9", "2026-09-17")
	want := "llavero v0.1.0 (230caa9, 2026-09-17)"
	if got != want {
		t.Fatalf("formatVersion = %q, want %q", got, want)
	}
	if got := formatVersion("", "", ""); got != "llavero dev (none, unknown)" {
		t.Fatalf("empty fields = %q, want the documented defaults", got)
	}
}

func TestApplyBuildInfoFillsDefaults(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.2.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "230caa9abcdef0123456789"},
			{Key: "vcs.time", Value: "2026-09-17T21:12:23Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	version, commit, date := applyBuildInfo("dev", "none", "unknown", info)
	if version != "v0.2.0" {
		t.Errorf("version = %q, want v0.2.0 from Main.Version", version)
	}
	if commit != "230caa9" {
		t.Errorf("commit = %q, want the short vcs.revision", commit)
	}
	if date != "2026-09-17" {
		t.Errorf("date = %q, want 2026-09-17 from vcs.time", date)
	}
}

func TestApplyBuildInfoMarksDirtyAndIgnoresDevel(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef1"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	version, commit, date := applyBuildInfo("dev", "none", "unknown", info)
	if version != "dev" {
		t.Errorf("version = %q, want dev; (devel) is not a real version", version)
	}
	if commit != "abcdef1-dirty" {
		t.Errorf("commit = %q, want abcdef1-dirty", commit)
	}
	if date != "unknown" {
		t.Errorf("date = %q, want unknown when vcs.time is missing", date)
	}
}

func TestApplyBuildInfoDoesNotOverrideLdflags(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "ffffffff"},
			{Key: "vcs.time", Value: "1999-01-01T00:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	version, commit, date := applyBuildInfo("v0.1.0", "230caa9", "2026-09-17", info)
	if version != "v0.1.0" || commit != "230caa9" || date != "2026-09-17" {
		t.Fatalf("ldflags were overwritten: version=%q commit=%q date=%q", version, commit, date)
	}
}

func TestApplyBuildInfoReadsGoInstallPseudoVersion(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-20260917121223-230caa9abcdef"},
	}
	version, commit, date := applyBuildInfo("dev", "none", "unknown", info)
	if version != "v0.0.0-20260917121223-230caa9abcdef" {
		t.Errorf("version = %q, want the module pseudo-version", version)
	}
	if commit != "230caa9" {
		t.Errorf("commit = %q, want the short hash from the pseudo-version", commit)
	}
	if date != "2026-09-17" {
		t.Errorf("date = %q, want 2026-09-17 from the pseudo-version timestamp", date)
	}
}

func TestParsePseudoVersion(t *testing.T) {
	tests := []struct {
		in         string
		wantCommit string
		wantDate   string
		ok         bool
	}{
		{"v0.0.0-20260917121223-230caa9abcdef", "230caa9", "2026-09-17", true},
		{"v0.1.1-0.20260917121223-230caa9abcdef", "230caa9", "2026-09-17", true},
		{"v0.1.0", "", "", false},
		{"dev", "", "", false},
		{"v0.1.0-rc.1", "", "", false},
	}
	for _, tt := range tests {
		commit, date, ok := parsePseudoVersion(tt.in)
		if ok != tt.ok || commit != tt.wantCommit || date != tt.wantDate {
			t.Errorf("parsePseudoVersion(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, commit, date, ok, tt.wantCommit, tt.wantDate, tt.ok)
		}
	}
}

// TestVersionFlagWithLdflags builds a real binary the way a release would, so
// a mistake in the -X paths or the flag name cannot hide behind a unit test
// that never reaches main().
func TestVersionFlagWithLdflags(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "llavero")
	ldflags := "-X main.version=v0.1.0 -X main.commit=230caa9 -X main.date=2026-09-17"
	build := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, ".")
	build.Env = append(os.Environ(), "GOFLAGS=")
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "-version")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("llavero -version: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	want := "llavero v0.1.0 (230caa9, 2026-09-17)"
	if got != want {
		t.Fatalf("llavero -version printed %q, want %q", got, want)
	}
}
