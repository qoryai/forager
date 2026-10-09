package importrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// parts are the module's parts, by the first element of a package's path in the module.
// Every other package is the core's.
var parts = []string{"gateway", "wall", "session", "e2e"}

// part is the part a package belongs to, by its path in the module; "" is the core.
func part(rel string) string {
	first, _, _ := strings.Cut(rel, "/")
	if slices.Contains(parts, first) {
		return first
	}
	return ""
}

// coreInternal reports whether a path in the module is one of the core's internal
// packages.
func coreInternal(rel string) bool { return rel == "internal" || strings.HasPrefix(rel, "internal/") }

// allowed reports whether the package at from may import the package at to, both paths
// in the module.
func allowed(from, to string) bool {
	pf, pt := part(from), part(to)
	switch {
	case pf == "e2e":
		return true
	case pf == "":
		return pt == ""
	case pf == pt:
		return true
	case pt == "":
		return !coreInternal(to)
	case pf == "session":
		return pt == "wall" || to == "gateway"
	}
	return false
}

// pkg is what go list says of one package.
type pkg struct {
	ImportPath   string
	Imports      []string
	TestImports  []string
	XTestImports []string
}

// list returns the module's path and its packages.
func list(t *testing.T) (string, []pkg) {
	t.Helper()
	mod, err := exec.Command("go", "list", "-m").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	dir, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	cmd := exec.Command("go", "list", "-json=ImportPath,Imports,TestImports,XTestImports", "./...")
	cmd.Dir = strings.TrimSpace(string(dir))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list ./...: %v", err)
	}
	var pkgs []pkg
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p pkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("reading go list: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return strings.TrimSpace(string(mod)), pkgs
}

// rel is path's path in the module, and whether it is in the module.
func rel(module, path string) (string, bool) {
	if path == module {
		return "", true
	}
	return strings.CutPrefix(path, module+"/")
}

// testFixture reports whether a package of the core's is a fixture any part's tests
// may import, and no part's code: a fake gateway's link.
func testFixture(rel string) bool { return rel == "internal/linktest" }

// gatewayTestImport reports whether package gateway's tests may import the package at
// to, which its code may not: a session and its wall, so a real session runs against a
// real gateway serving its one address, with the gateway's own test seam deciding the
// run credentials, as a session test may start a real gateway.
func gatewayTestImport(from, to string) bool {
	return from == "gateway" && (to == "session" || to == "wall")
}

func TestThePartsImportWhatTheRulesAllow(t *testing.T) {
	module, pkgs := list(t)
	if len(pkgs) == 0 {
		t.Fatal("go list found no packages")
	}
	for _, p := range pkgs {
		from, ok := rel(module, p.ImportPath)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, imp := range slices.Concat(p.Imports, p.TestImports, p.XTestImports) {
			to, ok := rel(module, imp)
			if !ok || to == from || seen[to] {
				continue
			}
			seen[to] = true
			if (testFixture(to) || gatewayTestImport(from, to)) && !slices.Contains(p.Imports, imp) {
				continue
			}
			if !allowed(from, to) {
				t.Errorf("%s imports %s, which the import rules forbid", from, to)
			}
		}
	}
}

func TestTheRulesHoldTheirCases(t *testing.T) {
	for _, c := range []struct {
		from, to string
		ok       bool
	}{
		{"policy", "accesskey", true},
		{"policy", "internal/jcs", true},
		{"policy", "session", false},
		{"link", "gateway", false},
		{"runcredential", "server", true},
		{"runcredential", "refusal", true},
		{"runcredential", "gateway", false},
		{"runcredential", "session", false},
		{"gateway", "policy", true},
		{"gateway", "link", true},
		{"gateway", "runcredential", true},
		{"gateway", "gateway/internal/proxy", true},
		{"gateway", "internal/jcs", false},
		{"gateway", "session", false},
		{"gateway", "wall", false},
		{"wall", "link", true},
		{"wall", "program", true},
		{"wall", "gateway", false},
		{"wall", "session", false},
		{"session", "wall", true},
		{"session", "gateway", true},
		{"session", "runcredential", true},
		{"session", "gateway/internal/proxy", false},
		{"session", "internal/jcs", false},
		{"session/runtimes", "session/internal/descriptor", true},
		{"e2e", "session", true},
		{"e2e", "gateway", true},
		{"e2e", "wall", true},
	} {
		if got := allowed(c.from, c.to); got != c.ok {
			t.Errorf("allowed(%q, %q) = %v, want %v", c.from, c.to, got, c.ok)
		}
	}
	for _, c := range []struct {
		from, to string
		ok       bool
	}{
		{"gateway", "session", true},
		{"gateway", "wall", true},
		{"gateway", "session/runtimes", false},
		{"gateway/internal/proxy", "session", false},
		{"wall", "session", false},
	} {
		if got := gatewayTestImport(c.from, c.to); got != c.ok {
			t.Errorf("gatewayTestImport(%q, %q) = %v, want %v", c.from, c.to, got, c.ok)
		}
	}
}
