package main

import (
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	origVersion := version
	origCommit := commit
	origDate := date
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
	}()

	tests := []struct {
		name     string
		v        string
		c        string
		d        string
		expected string
	}{
		{
			name:     "all fields populated",
			v:        "v0.1.0",
			c:        "230caa9",
			d:        "2026-09-17",
			expected: "llavero v0.1.0 (230caa9, 2026-09-17)",
		},
		{
			name:     "commit only",
			v:        "dev",
			c:        "abcdef1",
			d:        "unknown",
			expected: "llavero dev (abcdef1)",
		},
		{
			name:     "defaults",
			v:        "dev",
			c:        "none",
			d:        "unknown",
			expected: "llavero dev",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			version = tc.v
			commit = tc.c
			date = tc.d
			got := versionString()
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
			if !strings.HasPrefix(got, "llavero ") {
				t.Fatalf("expected prefix 'llavero ', got %q", got)
			}
		})
	}
}
