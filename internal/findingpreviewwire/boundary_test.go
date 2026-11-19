package findingpreviewwire

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// boundaryPackage groups the parsed files of one package (test-local
// replacement for the deprecated go/ast.Package).
type boundaryPackage struct {
	Files map[string]*ast.File
}

func TestW09ProductionBoundary(t *testing.T) {
	allowed := map[string]bool{"bytes": true, "encoding/json": true, "io": true, "strconv": true, "strings": true, "time": true, "unicode": true, "unicode/utf8": true, "github.com/g-kari/dependabot-alert-notice/internal/findingpreview": true, "github.com/g-kari/dependabot-alert-notice/internal/model": true}
	files := map[string]*boundaryPackage{}
	{
		// parser.ParseDir is deprecated; read and parse the package directory directly.
		fset := token.NewFileSet()
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") {
				continue
			}
			file, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			pkg := files[file.Name.Name]
			if pkg == nil {
				pkg = &boundaryPackage{Files: map[string]*ast.File{}}
				files[file.Name.Name] = pkg
			}
			pkg.Files[name] = file
		}
	}
	calls := 0
	for _, pkg := range files {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			for _, imp := range file.Imports {
				path, e := strconv.Unquote(imp.Path.Value)
				if e != nil || !allowed[path] || imp.Name != nil {
					t.Fatal("unexpected production import")
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if f, ok := n.(*ast.FuncDecl); ok && f.Name.Name == "init" {
					t.Error("init forbidden")
				}
				if _, ok := n.(*ast.GoStmt); ok {
					t.Error("goroutine forbidden")
				}
				if s, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := s.X.(*ast.Ident); ok {
						if id.Name == "time" && s.Sel.Name != "ParseInLocation" && s.Sel.Name != "UTC" && s.Sel.Name != "RFC3339Nano" && s.Sel.Name != "Time" {
							t.Errorf("unexpected time selector %s", s.Sel.Name)
						}
						if id.Name == "io" && s.Sel.Name != "EOF" {
							t.Error("I/O forbidden")
						}
						if id.Name == "findingpreview" && s.Sel.Name != "Input" && s.Sel.Name != "Binding" && s.Sel.Name != "Result" && s.Sel.Name != "Calculate" {
							t.Error("unexpected adapter selector")
						}
					}
				}
				if c, ok := n.(*ast.CallExpr); ok {
					if s, ok := c.Fun.(*ast.SelectorExpr); ok {
						if id, ok := s.X.(*ast.Ident); ok && id.Name == "findingpreview" && s.Sel.Name == "Calculate" {
							calls++
						}
					}
					if id, ok := c.Fun.(*ast.Ident); ok && (id.Name == "print" || id.Name == "println" || id.Name == "panic") {
						t.Error("output/panic forbidden")
					}
				}
				return true
			})
		}
	}
	if calls != 1 {
		t.Fatalf("expected one adapter call site, got %d", calls)
	}
}
