package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestModulePathAllowsGoInstall(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.fatal(err)
	}
	const want = "module github.com/xe-nvdk/llavero\n"
	if !strings.HasPrefix(string(data), want) {
		t.Fatalf("go.mod must start with %q so go install github.com/xe-nvdk/llavero@latest resolves", strings.TrimSuffix(want, "\n"))
	}
}

func TestPackagingDocsCoverFlags(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.fatal(err)
	}
	flags := flagsDeclaredIn(string(src))
	if len(flags) == 0 {
		t.fatal("parsed no flags from main.go")
	}

	files := []string{
		"packaging/llavero.1",
		"packaging/completions/llavero.bash",
		"packaging/completions/_llavero",
		"packaging/completions/llavero.fish",
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body := string(data)
		for _, flag := range flags {
			if !docsCoverFlag(body, flag) {
				t.Errorf("%s: missing -%s", path, flag)
			}
		}
	}
}

var (
	flagNoVar = regexp.MustCompile(`flag\.(?:Bool|String|Int|Duration)\("([a-z0-9-]+)"`)
	flagVar   = regexp.MustCompile(`flag\.(?:Bool|String|Int|Duration)Var\([^,]+,\s*"([a-z0-9-]+)"`)
)

func flagsDeclaredIn(src string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(matches [][]string) {
		for _, m := range matches {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	add(flagNoVar.FindAllStringSubmatch(src, -1))
	add(flagVar.FindAllStringSubmatch(src, -1))
	return out
}

func docsCoverFlag(body, name string) bool {
	if strings.Contains(body, "-"+name) {
		return true
	}
	// fish completions use `complete -c llavero -o vault` for `-vault`.
	return strings.Contains(body, "-o "+name)
}
