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
		t.Fatal(err)
	}
	const want = "module github.com/xe-nvdk/llavero\n"
	if !strings.HasPrefix(string(data), want) {
		t.Fatalf("go.mod must start with %q so go install github.com/xe-nvdk/llavero@latest resolves", strings.TrimSuffix(want, "\n"))
	}
}

func TestPackagingDocsCoverFlags(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	flags := flagsDeclaredIn(string(src))
	if len(flags) == 0 {
		t.Fatal("parsed no flags from main.go")
	}

	files := map[string]func(body, name string) bool{
		"packaging/llavero.1":                manCoversFlag,
		"packaging/completions/llavero.bash": bashCoversFlag,
		"packaging/completions/_llavero":     zshCoversFlag,
		"packaging/completions/llavero.fish": fishCoversFlag,
	}
	for path, covers := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body := string(data)
		for _, flag := range flags {
			if !covers(body, flag) {
				t.Errorf("%s: missing -%s", path, flag)
			}
		}
	}
}

// The matchers below look for a whole flag token in each format, so that
// -vault does not count as documenting -v, nor -uv-strict as -uv.

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

// manCoversFlag wants an option entry: a .TP followed by .B or .BI \-name.
func manCoversFlag(body, name string) bool {
	re := regexp.MustCompile(`(?m)^\.TP\n\.BI? \\-` + regexp.QuoteMeta(name) + `(?:\s|$)`)
	return re.MatchString(body)
}

// bashCoversFlag wants -name (or -name=value) as a word of the opts list.
func bashCoversFlag(body, name string) bool {
	m := regexp.MustCompile(`(?s)local opts="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		return false
	}
	for _, w := range strings.Fields(m[1]) {
		if w == "-"+name || strings.HasPrefix(w, "-"+name+"=") {
			return true
		}
	}
	return false
}

// zshCoversFlag wants an _arguments spec starting '-name[ or '-name=.
func zshCoversFlag(body, name string) bool {
	return strings.Contains(body, "'-"+name+"[") || strings.Contains(body, "'-"+name+"=")
}

// fishCoversFlag wants `-o name` followed by whitespace or end of line.
func fishCoversFlag(body, name string) bool {
	re := regexp.MustCompile(`-o ` + regexp.QuoteMeta(name) + `(?:\s|$)`)
	return re.MatchString(body)
}
