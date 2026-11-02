package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if got := formatVersion("0.1.0", "230caa9", "2026-09-17"); got != want {
		t.Fatalf("missing v prefix: got %q, want %q", got, want)
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
	version, commit, commitDate := applyBuildInfo("dev", "none", "unknown", info)
	if version != "v0.2.0" {
		t.Errorf("version = %q, want v0.2.0 from Main.Version", version)
	}
	if commit != "230caa9" {
		t.Errorf("commit = %q, want the short vcs.revision", commit)
	}
	if commitDate != "2026-09-17" {
		t.Errorf("commitDate = %q, want 2026-09-17 from vcs.time", commitDate)
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
	version, commit, commitDate := applyBuildInfo("dev", "none", "unknown", info)
	if version != "dev" {
		t.Errorf("version = %q, want dev; (devel) is not a real version", version)
	}
	if commit != "abcdef1-dirty" {
		t.Errorf("commit = %q, want abcdef1-dirty", commit)
	}
	if commitDate != "unknown" {
		t.Errorf("commitDate = %q, want unknown when vcs.time is missing", commitDate)
	}
}

// A dirty local build on Go 1.24+ gets +dirty on the module version and
// vcs.modified=true. The line should say dirty once, on the commit.
func TestApplyBuildInfoSaysDirtyOnce(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-20260917121223-05aa67b1c2d3+dirty"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "05aa67b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7"},
			{Key: "vcs.time", Value: "2026-09-17T12:12:23Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	got := formatVersion(applyBuildInfo("dev", "none", "unknown", info))
	want := "llavero v0.0.0-20260917121223-05aa67b1c2d3 (05aa67b-dirty, 2026-09-17)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if n := strings.Count(got, "dirty"); n != 1 {
		t.Fatalf("%q mentions dirty %d times, want once", got, n)
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
	version, commit, commitDate := applyBuildInfo("v0.1.0", "230caa9", "2026-09-17", info)
	if version != "v0.1.0" || commit != "230caa9" || commitDate != "2026-09-17" {
		t.Fatalf("ldflags were overwritten: version=%q commit=%q commitDate=%q", version, commit, commitDate)
	}
}

func TestApplyBuildInfoReadsGoInstallPseudoVersion(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-20260917121223-230caa9abcde"},
	}
	version, commit, commitDate := applyBuildInfo("dev", "none", "unknown", info)
	if version != "v0.0.0-20260917121223-230caa9abcde" {
		t.Errorf("version = %q, want the module pseudo-version", version)
	}
	if commit != "230caa9" {
		t.Errorf("commit = %q, want the short hash from the pseudo-version", commit)
	}
	if commitDate != "2026-09-17" {
		t.Errorf("commitDate = %q, want 2026-09-17 from the pseudo-version timestamp", commitDate)
	}
}

func TestParsePseudoVersion(t *testing.T) {
	tests := []struct {
		in         string
		wantCommit string
		wantDate   string
		ok         bool
	}{
		{"v0.0.0-20260917121223-230caa9abcde", "230caa9", "2026-09-17", true},
		{"v0.1.1-0.20260917121223-230caa9abcde", "230caa9", "2026-09-17", true},
		{"v0.0.0-20260917121223-230caa9abcde+dirty", "230caa9", "2026-09-17", true},
		{"v2.0.1-0.20260917121223-230caa9abcde+incompatible", "230caa9", "2026-09-17", true},
		{"v2.0.1-0.20260917121223-230caa9abcde+incompatible.dirty", "230caa9", "2026-09-17", true},
		{"v0.1.0+dirty", "", "", false},
		{"v0.1.0", "", "", false},
		{"dev", "", "", false},
		{"v0.1.0-rc.1", "", "", false},
	}
	for _, tt := range tests {
		commit, commitDate, ok := parsePseudoVersion(tt.in)
		if ok != tt.ok || commit != tt.wantCommit || commitDate != tt.wantDate {
			t.Errorf("parsePseudoVersion(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, commit, commitDate, ok, tt.wantCommit, tt.wantDate, tt.ok)
		}
	}
}

// TestVersionFlagWithLdflags builds a real binary the way a release would, so
// a mistake in the -X paths or the flag name cannot hide behind a unit test
// that never reaches main().
// It does a full build, so -short skips it.
func TestVersionFlagWithLdflags(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary; skipped with -short")
	}
	bin := filepath.Join(t.TempDir(), "llavero")
	ldflags := "-X main.version=v0.1.0 -X main.commit=230caa9 -X main.commitDate=2026-09-17"
	// The toolchain running this test, not whatever "go" is first on PATH.
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	build := exec.Command(goBin, "build", "-ldflags", ldflags, "-o", bin, ".")
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
