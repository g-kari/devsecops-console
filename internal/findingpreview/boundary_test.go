package findingpreview

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Keep this internal preview from silently gaining operational dependencies.
// Reading its source here is test-only; production inputs remain in memory.
// boundaryPackage groups the parsed files of one package (test-local
// replacement for the deprecated go/ast.Package).
type boundaryPackage struct {
	Files map[string]*ast.File
}

func TestProductionBoundaryHasNoOperationalImportsOrClock(t *testing.T) {
	allowed := map[string]bool{"fmt": true, "maps": true, "math": true, "regexp": true, "slices": true, "time": true,
		"github.com/g-kari/dependabot-alert-notice/internal/model":   true,
		"github.com/g-kari/dependabot-alert-notice/internal/scoring": true}
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
	for _, pkg := range files {
		for name, file := range pkg.Files {
			if len(name) >= 8 && name[len(name)-8:] == "_test.go" {
				continue
			}
			for _, imp := range file.Imports {
				path, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if !allowed[path] || imp.Name != nil {
					t.Fatalf("production import outside pure boundary: %s", path)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if f, ok := n.(*ast.FuncDecl); ok && f.Name.Name == "init" {
					t.Error("production init is not allowed")
				}
				s, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := s.X.(*ast.Ident)
				if !ok {
					return true
				}
				if id.Name == "time" && (s.Sel.Name == "Now" || s.Sel.Name == "Since" || s.Sel.Name == "Until" || s.Sel.Name == "After" || s.Sel.Name == "Sleep" || s.Sel.Name == "NewTicker" || s.Sel.Name == "NewTimer" || s.Sel.Name == "AfterFunc" || s.Sel.Name == "Tick") {
					t.Errorf("implicit clock operation: %s", s.Sel.Name)
				}
				if id.Name == "scoring" && s.Sel.Name != "Calculate" && s.Sel.Name != "NormalizeCVSS" && s.Sel.Name != "ModelVersion" {
					t.Errorf("non-preview scoring operation: %s", s.Sel.Name)
				}
				if id.Name == "fmt" && s.Sel.Name != "Errorf" {
					t.Errorf("non-error formatting operation: %s", s.Sel.Name)
				}
				return true
			})
		}
	}
}
