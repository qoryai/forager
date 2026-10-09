package importrules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// gatewaySurface is package gateway's whole exported surface: what starts a gateway, its
// configuration and what closes it, the resend that is a run's close-out and the lines
// it reports, and the types their fields need. A method is its type's name, a dot and
// its own. A new export needs an edit here, made on purpose.
var gatewaySurface = []string{
	"Start", "Config", "Server", "TLS", "RunsConfig",
	"Gateway", "Gateway.Addr", "Gateway.LocalLink", "Gateway.Close", "Gateway.Wait",
	"Gateway.String", "Gateway.Format", "Gateway.GoString", "Gateway.LogValue",
	"Resend", "ResendConfig", "Delivery", "ErrRunning", "ResendTorn", "ResendNoServer", "ResendNotOpened",
	"Policy", "Policy.Under", "ReadPolicy", "PolicyEgress", "PolicyCredential", "PolicyTool",
	"Credential", "Credential.Check", "Tool", "Tool.Check", "Discovery", "Image", "Image.Check",
}

// What each rule requires, as every failure of it says.
const (
	surfaceRule = "package gateway exports only what starts a gateway, configures it and closes it: " +
		"Start, Config, Gateway with Addr, LocalLink, Close, Wait and the methods that print it, Resend and the lines it reports, and the types their fields need"
	linkRule = "the session reaches a gateway over the gateway's link alone, the local link on one machine " +
		"or a separate gateway's one address over TLS, so no file of session/ but a test imports a gateway package"
	testRule = "a session test may start a real gateway, " +
		"with package gateway's surface alone: Start, Config, Gateway, Resend and the types their fields need"
)

// moduleDir is the module's path and its directory.
func moduleDir(t *testing.T) (string, string) {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Path}} {{.Dir}}").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	path, dir, ok := strings.Cut(strings.TrimSpace(string(out)), " ")
	if !ok {
		t.Fatalf("go list -m: %q", out)
	}
	return path, dir
}

// parseDir parses the Go files of dir, whatever their build constraints, the tests' or
// the code's as tests says.
func parseDir(t *testing.T, fset *token.FileSet, dir string, tests bool) []*ast.File {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") != tests {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files = append(files, f)
	}
	return files
}

// receiver is the name of the type a method is declared on.
func receiver(fn *ast.FuncDecl) string {
	x := fn.Recv.List[0].Type
	if star, ok := x.(*ast.StarExpr); ok {
		x = star.X
	}
	switch x := x.(type) {
	case *ast.IndexExpr:
		return x.X.(*ast.Ident).Name
	case *ast.IndexListExpr:
		return x.X.(*ast.Ident).Name
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// methods are the exported methods declared on each exported type of files.
func methods(files []*ast.File) map[string][]string {
	m := map[string][]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() {
				continue
			}
			if r := receiver(fn); ast.IsExported(r) {
				m[r] = append(m[r], fn.Name.Name)
			}
		}
	}
	return m
}

// imports maps each import's name in f to its path.
func imports(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		m[name] = path
	}
	return m
}

// exports lists the exported names of the package in dir: its constants, variables,
// types and functions, and the methods of its types, "Type.Method". A type that aliases
// one of the module's own packages' types has that type's methods too, which are the
// package's surface as well.
func exports(t *testing.T, module, dir, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	files := parseDir(t, fset, dir, false)
	var names []string
	for typ, ms := range methods(files) {
		for _, m := range ms {
			names = append(names, typ+"."+m)
		}
	}
	aliased := map[string]map[string][]string{}
	for _, f := range files {
		imps := imports(f)
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.IsExported() {
					names = append(names, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								names = append(names, n.Name)
							}
						}
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						names = append(names, s.Name.Name)
						sel, ok := s.Type.(*ast.SelectorExpr)
						if !s.Assign.IsValid() || !ok {
							continue
						}
						pkg, ok := sel.X.(*ast.Ident)
						if !ok {
							continue
						}
						rel, ok := strings.CutPrefix(imps[pkg.Name], module+"/")
						if !ok {
							continue
						}
						if aliased[rel] == nil {
							aliased[rel] = methods(parseDir(t, token.NewFileSet(), filepath.Join(root, rel), false))
						}
						for _, m := range aliased[rel][sel.Sel.Name] {
							names = append(names, s.Name.Name+"."+m)
						}
					}
				}
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func TestPackageGatewayExportsItsSurfaceAlone(t *testing.T) {
	module, root := moduleDir(t)
	names := exports(t, module, filepath.Join(root, "gateway"), root)
	if !slices.Contains(names, "Start") {
		t.Fatalf("package gateway's exports, %v, hold no Start: the test reads the wrong files", names)
	}
	for _, n := range names {
		if !slices.Contains(gatewaySurface, n) {
			t.Errorf("package gateway exports %s, outside its surface: %s. "+
				"Unexport it or move it under gateway/internal/, or add it to gatewaySurface on purpose", n, surfaceRule)
		}
	}
	for _, n := range gatewaySurface {
		if !slices.Contains(names, n) {
			t.Errorf("gatewaySurface lists %s, which package gateway does not export: drop it from the list", n)
		}
	}
}

// sessionFiles parses every Go file under the module's session/, the tests' or the
// code's as tests says, skipping what the go command skips: testdata and directories
// whose name starts with a dot or an underscore.
func sessionFiles(t *testing.T, root string, tests bool) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	err := filepath.WalkDir(filepath.Join(root, "session"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if n := d.Name(); n == "testdata" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") {
			return filepath.SkipDir
		}
		files = append(files, parseDir(t, fset, path, tests)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no Go files under session/")
	}
	return fset, files
}

// gatewayPackage reports whether path is package gateway or one of its packages.
func gatewayPackage(module, path string) bool {
	return path == module+"/gateway" || strings.HasPrefix(path, module+"/gateway/")
}

func TestSessionCodeImportsNoGateway(t *testing.T) {
	module, root := moduleDir(t)
	fset, files := sessionFiles(t, root, false)
	for _, f := range files {
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); gatewayPackage(module, path) {
				t.Errorf("%s imports %s: %s", fset.Position(imp.Pos()), path, linkRule)
			}
		}
	}
}

func TestSessionTestsUseTheGatewaySurfaceAlone(t *testing.T) {
	module, root := moduleDir(t)
	fset, files := sessionFiles(t, root, true)
	for _, f := range files {
		name := ""
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !gatewayPackage(module, path) {
				continue
			}
			switch {
			case path != module+"/gateway":
				t.Errorf("%s imports %s: %s", fset.Position(imp.Pos()), path, testRule)
			case imp.Name != nil && (imp.Name.Name == "." || imp.Name.Name == "_"):
				t.Errorf("%s imports package gateway as %s, which hides what it uses of it: %s",
					fset.Position(imp.Pos()), imp.Name.Name, testRule)
			case imp.Name != nil:
				name = imp.Name.Name
			default:
				name = "gateway"
			}
		}
		if name == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == name && !slices.Contains(gatewaySurface, sel.Sel.Name) {
				t.Errorf("%s uses gateway.%s, outside package gateway's surface: %s",
					fset.Position(sel.Pos()), sel.Sel.Name, testRule)
			}
			return true
		})
	}
}
