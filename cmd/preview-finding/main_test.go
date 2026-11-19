package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewwire"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

func fixture(t *testing.T, schema string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + schema + ".json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func parity(t *testing.T, schema string, b []byte) {
	t.Helper()
	dec := map[string]func([]byte) (findingpreview.Result, error){"base": findingpreviewwire.Decode, "profile": findingpreviewwire.DecodeProfile, "assessment": findingpreviewwire.DecodeAssessment}[schema]
	result, err := dec(b)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(output{outputVersion, warning, result})
	if err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if status := run([]string{"--schema", schema}, bytes.NewReader(b), &out, &diag); status != 0 || diag.Len() != 0 {
		t.Fatalf("status=%d diagnostics=%q", status, diag.String())
	}
	if !bytes.Equal(out.Bytes(), append(want, '\n')) {
		t.Fatal("full Result or envelope differs")
	}
	var decoded output
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Result.PreviewOnly {
		t.Fatal("not preview")
	}
}

func TestCLIAllSchemasPreserveFullResult(t *testing.T) {
	for _, s := range []string{"base", "profile", "assessment"} {
		t.Run(s, func(t *testing.T) { parity(t, s, fixture(t, s)) })
	}
}
func TestCLIExpiryAndUnsupportedParity(t *testing.T) {
	b := fixture(t, "assessment")
	for _, expiry := range []string{"2026-11-07T23:59:59Z", "2026-11-08T00:00:00Z", "2026-11-08T00:00:01Z"} {
		for _, app := range []string{"affected", "not_affected", "unknown"} {
			x := bytes.ReplaceAll(b, []byte("2026-11-09T00:00:00Z"), []byte(expiry))
			x = bytes.ReplaceAll(x, []byte(`"affected"`), []byte(strconv.Quote(app)))
			parity(t, "assessment", x)
		}
	}
	for _, s := range []string{"base", "profile", "assessment"} {
		x := bytes.ReplaceAll(fixture(t, s), []byte(`"vulnerability"`), []byte(`"secret"`))
		parity(t, s, x)
	}
}
func TestCLIRejectsWithoutEchoOrPartialResult(t *testing.T) {
	b := fixture(t, "base")
	cases := [][]byte{nil, []byte(" "), append(append([]byte{}, b...), b...), []byte("[]"), []byte("null"), []byte{0xff}, bytes.Replace(b, []byte(`"asset-a"`), []byte(`"wrong"`), 1), bytes.Replace(b, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)}
	for _, field := range []string{`"private-sentinel":"private-sentinel",`, `"schema_version":"private-sentinel",`, `"\u0073chema_version":"private-sentinel",`, `"cvss":{},`, `"facts":{},`, `"secret":null,`, `"secret":"\ud800",`} {
		cases = append(cases, append([]byte("{"+field), b[1:]...))
	}
	for i, b := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var out, diag bytes.Buffer
			if run([]string{"--schema", "base"}, bytes.NewReader(b), &out, &diag) != 1 || out.Len() != 0 || diag.String() != "preview-finding: input\n" {
				t.Fatalf("out=%q diag=%q", out.String(), diag.String())
			}
		})
	}
	for _, s := range []string{"base", "profile", "assessment"} {
		for _, other := range []string{"base", "profile", "assessment"} {
			if s == other {
				continue
			}
			var out, diag bytes.Buffer
			if run([]string{"--schema", s}, bytes.NewReader(fixture(t, other)), &out, &diag) != 1 || out.Len() != 0 {
				t.Fatal("version auto-upgraded")
			}
		}
	}
}

type countingReader struct{ total int }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.total += len(p)
	return len(p), nil
}

type failureReader struct{}

func (failureReader) Read([]byte) (int, error) { return 0, errors.New("private-sentinel") }

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) { return w.Buffer.Write(p[:len(p)/2]) }

type failureWriter struct{}

func (failureWriter) Write([]byte) (int, error) { return 0, errors.New("private-sentinel") }

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("unexpected read") }

func TestCLIBoundedReadAndIOFailures(t *testing.T) {
	b := fixture(t, "base")
	exact := append(append([]byte{}, b...), bytes.Repeat([]byte(" "), findingpreviewwire.MaxBytes-len(b))...)
	parity(t, "base", exact)
	var out, diag bytes.Buffer
	r := &countingReader{}
	if run([]string{"--schema", "base"}, r, &out, &diag) != 1 || r.total != findingpreviewwire.MaxBytes+1 || out.Len() != 0 || diag.String() != "preview-finding: size\n" {
		t.Fatal("unbounded read")
	}
	out.Reset()
	diag.Reset()
	if run([]string{"--schema", "base"}, failureReader{}, &out, &diag) != 1 || out.Len() != 0 || diag.String() != "preview-finding: read\n" {
		t.Fatal("read failure leaked")
	}
	for _, w := range []io.Writer{&shortWriter{}, failureWriter{}} {
		diag.Reset()
		if run([]string{"--schema", "base"}, bytes.NewReader(b), w, &diag) != 1 || diag.String() != "preview-finding: output\n" {
			t.Fatal("write failure ignored")
		}
	}
	if run(nil, panicReader{}, &out, failureWriter{}) != 1 {
		t.Fatal("diagnostic writer failure ignored")
	}
}
func TestCLIArgumentsAndHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"--schema"}, {"--schema", "private-sentinel"}, {"--schema=base"}, {"--schema", "base", "extra"}, {"--input", "private-sentinel"}, {"--schema", "base", "--schema", "base"}, {"--help", "extra"}} {
		var out, diag bytes.Buffer
		if run(args, panicReader{}, &out, &diag) != 2 || out.Len() != 0 || diag.String() != "preview-finding: arguments\n" {
			t.Fatal("argument failure")
		}
	}
	var out, diag bytes.Buffer
	if run([]string{"--help"}, panicReader{}, &out, &diag) != 0 || out.String() != usage || diag.Len() != 0 {
		t.Fatal("help")
	}
	if run([]string{"--help"}, panicReader{}, failureWriter{}, &diag) != 1 {
		t.Fatal("help writer failure")
	}
}

// boundaryPackage groups the parsed files of one package (test-local
// replacement for the deprecated go/ast.Package).
type boundaryPackage struct {
	Files map[string]*ast.File
}

func TestCLIProductionBoundary(t *testing.T) {
	allowed := map[string]bool{"encoding/json": true, "io": true, "os": true, "github.com/g-kari/dependabot-alert-notice/internal/findingpreview": true, "github.com/g-kari/dependabot-alert-notice/internal/findingpreviewwire": true}
	pkgs := map[string]*boundaryPackage{}
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
			pkg := pkgs[file.Name.Name]
			if pkg == nil {
				pkg = &boundaryPackage{Files: map[string]*ast.File{}}
				pkgs[file.Name.Name] = pkg
			}
			pkg.Files[name] = file
		}
	}
	for _, p := range pkgs {
		for name, f := range p.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			for _, imp := range f.Imports {
				path, e := strconv.Unquote(imp.Path.Value)
				if e != nil || !allowed[path] || imp.Name != nil {
					t.Fatal("unexpected import")
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.Name == "init" {
					t.Error("init forbidden")
				}
				if _, ok := n.(*ast.GoStmt); ok {
					t.Error("goroutine forbidden")
				}
				if s, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := s.X.(*ast.Ident); ok && id.Name == "os" {
						if !map[string]bool{"Exit": true, "Args": true, "Stdin": true, "Stdout": true, "Stderr": true}[s.Sel.Name] {
							t.Error("unexpected OS access")
						}
					}
				}
				return true
			})
		}
	}
}
