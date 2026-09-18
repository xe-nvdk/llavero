package main

// Build identity. These three strings are the single source for the -version
// flag and the startup journal line. A later CTAP 2.1 getInfo field can read
// the same `version` rather than inventing a second constant.
//
// Release builds stamp them with -ldflags:
//
//	-X main.version=v0.1.0
//	-X main.commit=$(git rev-parse --short HEAD)
//	-X main.date=$(date -u +%Y-%m-%d)
//
// A plain `go build` or `go install` leaves the defaults. applyBuildInfo then
// fills what it can from the metadata Go embeds, so both paths give a bug
// report something it can name.

import (
	"fmt"
	"runtime/debug"
	"strings"
	"time"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func loadBuildInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	version, commit, date = applyBuildInfo(version, commit, date, info)
}

// applyBuildInfo fills any still-default field from Go's embedded build
// info. Values already set by -ldflags are left alone, so a release binary
// cannot be overwritten by whatever the linker happened to embed.
func applyBuildInfo(version, commit, date string, info *debug.BuildInfo) (string, string, string) {
	if info == nil {
		return version, commit, date
	}

	if isDefault(version, "dev") {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			version = v
		}
	}

	var (
		rev      string
		vcsTime  string
		modified bool
	)
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	if isDefault(commit, "none") && rev != "" {
		commit = shortRev(rev)
		if modified {
			commit += "-dirty"
		}
	}
	if isDefault(date, "unknown") && vcsTime != "" {
		date = formatVCSTime(vcsTime)
	}

	// go install from a module proxy usually has a version (often a
	// pseudo-version) but no vcs.* settings. Pull commit and date out of
	// the pseudo-version so those builds are not "none" / "unknown".
	if pseudoCommit, pseudoDate, ok := parsePseudoVersion(version); ok {
		if isDefault(commit, "none") {
			commit = pseudoCommit
		}
		if isDefault(date, "unknown") {
			date = pseudoDate
		}
	}

	return version, commit, date
}

func isDefault(val, fallback string) bool {
	return val == "" || val == fallback
}

func shortRev(rev string) string {
	if len(rev) > 7 {
		return rev[:7]
	}
	return rev
}

func formatVCSTime(vcsTime string) string {
	if t, err := time.Parse(time.RFC3339, vcsTime); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	return vcsTime
}

// parsePseudoVersion recognises the go-install form
// vX.Y.Z-yyyymmddhhmmss-<12 hex> (and the -0.yyyymmddhhmmss- variant).
func parsePseudoVersion(v string) (commit, date string, ok bool) {
	v = strings.TrimSuffix(v, "+incompatible")
	revSep := strings.LastIndexByte(v, '-')
	if revSep < 0 || len(v)-revSep-1 != 12 || !isLowerHex(v[revSep+1:]) {
		return "", "", false
	}
	rest := v[:revSep]
	tsSep := strings.LastIndexByte(rest, '-')
	if tsSep < 0 {
		return "", "", false
	}
	ts := rest[tsSep+1:]
	if strings.HasPrefix(ts, "0.") {
		ts = ts[2:]
	}
	if len(ts) != 14 || !isDigits(ts) {
		return "", "", false
	}
	return shortRev(v[revSep+1:]), ts[:4] + "-" + ts[4:6] + "-" + ts[6:8], true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return s != ""
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// versionLine is what -version prints and what the journal logs:
//
//	llavero v0.1.0 (230caa9, 2026-09-17)
func versionLine() string {
	return formatVersion(version, commit, date)
}

func formatVersion(version, commit, date string) string {
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "none"
	}
	if date == "" {
		date = "unknown"
	}
	return fmt.Sprintf("llavero %s (%s, %s)", version, commit, date)
}
