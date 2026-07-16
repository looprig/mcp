// This file guards the module's central architectural invariant: the MCP Go SDK
// is an implementation detail. It is enforced here, in the one package that is
// allowed to name SDK types, so that breaking the boundary breaks a test rather
// than a downstream consumer's build.
//
// Two independent checks, deliberately not sharing a mechanism:
//
//   - TestSDKImportsAreAllowlisted — which packages may import the SDK at all.
//   - TestNoSDKTypesInExportedAPI — whether an SDK type reaches an exported
//     declaration of a pkg/... package.
//
// The first is coarse and total; the second is what actually protects
// consumers. A package on the import allowlist still fails the second check if
// it leaks, which is the point: transports import the SDK to speak to it, not
// to hand it out.

package protocol_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// sdkModulePath is the SDK's module path. Any import path containing it is
	// an SDK import, whatever subpackage it names.
	sdkModulePath = "github.com/modelcontextprotocol/go-sdk"

	// modulePath is this module. Note it is a *prefix* of nothing in the SDK
	// and the SDK is not a prefix of it, so the two never confuse each other —
	// but modulePath must be matched with the trailing slash, because
	// "github.com/looprig/mcp" is also its own bare import path.
	modulePath = "github.com/looprig/mcp"

	// pkgPrefix marks the packages whose exported API is a consumer contract.
	pkgPrefix = modulePath + "/pkg/"

	// goToolTimeout bounds every `go` invocation this file makes.
	goToolTimeout = 90 * time.Second
)

// sdkImportAllowlist is the exhaustive set of packages permitted to import the
// MCP Go SDK. Everything else in the module must reach the protocol through
// internal/protocol's neutral types.
//
// Membership is a deliberate act: adding an entry here means "this package
// speaks SDK". It does NOT mean the package may expose SDK types —
// TestNoSDKTypesInExportedAPI still applies, and applies most sharply to the
// transports, which exist precisely to keep the SDK on their inside.
//
// The transports are pre-authorized because the boundary was designed with
// them in mind; they are not yet implemented, and an allowlist entry for a
// package that does not exist is inert.
var sdkImportAllowlist = map[string]struct{}{
	// The SDK <-> neutral conversion layer. The only such site today.
	modulePath + "/internal/protocol": {},

	// Transports (Tasks 2.x). Each wraps an SDK transport implementation.
	modulePath + "/pkg/transport/stdio":          {},
	modulePath + "/pkg/transport/streamablehttp": {},
	modulePath + "/pkg/transport/sse":            {},
}

// listedPackage is the slice of `go list -json` output this guard consumes.
// The go tool's schema is much larger; naming only these fields keeps the
// dependency on it explicit and narrow.
type listedPackage struct {
	Dir        string   `json:"Dir"`
	ImportPath string   `json:"ImportPath"`
	GoFiles    []string `json:"GoFiles"`
	Imports    []string `json:"Imports"`
	// Test imports are held to the same rule as production ones: a test that
	// names an SDK type in a package that must not know about the SDK is the
	// same boundary break, one commit early.
	TestImports  []string `json:"TestImports"`
	XTestImports []string `json:"XTestImports"`
}

// importGroups returns p's import lists paired with a label for the failure
// message, in a fixed order so output is deterministic.
func (p listedPackage) importGroups() []struct {
	Kind    string
	Imports []string
} {
	return []struct {
		Kind    string
		Imports []string
	}{
		{"imports", p.Imports},
		{"test imports", p.TestImports},
		{"xtest imports", p.XTestImports},
	}
}

// moduleRoot returns the directory holding this module's go.mod, asking the go
// tool rather than assuming a path relative to the test's working directory.
func moduleRoot(ctx context.Context, t *testing.T) string {
	t.Helper()
	out, err := runGo(ctx, "", "env", "GOMOD")
	if err != nil {
		t.Fatalf("locating module root: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Fatal("no go.mod found: the guard cannot determine the module root")
	}
	return filepath.Dir(gomod)
}

// runGo execs the go tool with an explicit argv (never a shell string) and
// returns its stdout.
func runGo(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- fixed argv, no external input
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, ee.Stderr)
		}
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// listPackages enumerates this module's packages. `go list -json` emits a
// stream of concatenated JSON objects rather than an array, so it is decoded as
// one.
func listPackages(ctx context.Context, t *testing.T, root string) []listedPackage {
	t.Helper()
	out, err := runGo(ctx, root, "list", "-json", "./...")
	if err != nil {
		t.Fatalf("listing packages: %v", err)
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var p listedPackage
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decoding go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages: the guard would vacuously pass")
	}
	return pkgs
}

// isSDKImport reports whether an import path names the MCP Go SDK.
func isSDKImport(path string) bool {
	return strings.HasPrefix(path, sdkModulePath+"/") || path == sdkModulePath
}

// TestSDKImportsAreAllowlisted fails if any package in this module imports the
// SDK without being on sdkImportAllowlist. Test imports count: a test that
// names an SDK type in a package that must not know about the SDK is the same
// boundary break, one commit early.
func TestSDKImportsAreAllowlisted(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), goToolTimeout)
	defer cancel()

	root := moduleRoot(ctx, t)
	pkgs := listPackages(ctx, t, root)

	checked := 0
	for _, p := range pkgs {
		if !strings.HasPrefix(p.ImportPath, modulePath+"/") && p.ImportPath != modulePath {
			continue // not ours (go list ./... should not emit these, but be explicit)
		}
		checked++
		if _, allowed := sdkImportAllowlist[p.ImportPath]; allowed {
			// Allowed to import the SDK — but still bound by
			// TestNoSDKTypesInExportedAPI, which is what stops it leaking.
			continue
		}

		for _, g := range p.importGroups() {
			for _, imp := range g.Imports {
				if !isSDKImport(imp) {
					continue
				}
				t.Errorf("package %s %s the SDK (%q) but is not on sdkImportAllowlist.\n"+
					"Only internal/protocol and pkg/transport/* may import the SDK; everything else "+
					"must use internal/protocol's neutral types. If this package genuinely must speak "+
					"SDK, add it to sdkImportAllowlist deliberately.",
					p.ImportPath, g.Kind, imp)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no packages of this module were checked: the guard would vacuously pass")
	}
	t.Logf("checked %d package(s) against the SDK import allowlist", checked)
}

// TestNoSDKTypesInExportedAPI fails if an SDK type is reachable from the
// exported API of any pkg/... package. internal/... is exempt: naming SDK types
// is its job.
//
// The check is syntactic, over each package's own source: it finds the local
// name each file binds to an SDK import, then walks every exported declaration's
// *type* syntax (never function bodies — an SDK value used internally is fine)
// looking for a selector qualified by one of those names. Unexported types are
// walked too, but only when reachable from exported syntax, so an exported field
// of an unexported struct that embeds an SDK type is still caught.
//
// Syntax rather than go/types keeps the guard dependency-free and fast. Its
// blind spot is a leak that no source file in the package spells — an exported
// alias of another module's alias of an SDK type — which no code here can
// produce without an SDK import that Check A already fails.
func TestNoSDKTypesInExportedAPI(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), goToolTimeout)
	defer cancel()

	root := moduleRoot(ctx, t)
	pkgs := listPackages(ctx, t, root)

	checked := 0
	for _, p := range pkgs {
		if !strings.HasPrefix(p.ImportPath, pkgPrefix) {
			continue
		}
		checked++
		for _, leak := range findExportedSDKLeaks(t, p) {
			t.Errorf("package %s leaks an SDK type through its exported API: %s.\n"+
				"No consumer of this module may be forced to name an SDK type. Convert at the "+
				"boundary (see internal/protocol) and expose a neutral type instead.",
				p.ImportPath, leak)
		}
	}
	if checked == 0 {
		t.Log("no pkg/... packages found yet; guard is inert until one exists")
	} else {
		t.Logf("checked the exported API of %d pkg/... package(s)", checked)
	}
}

// leakSite describes one exported-API reference to an SDK type.
type leakSite struct {
	Decl string // the exported declaration the reference is reachable from
	Expr string // the offending qualified name, e.g. "mcp.Tool"
	Pos  string // file:line:col
}

func (l leakSite) String() string {
	return fmt.Sprintf("%s references %s (%s)", l.Decl, l.Expr, l.Pos)
}

// findExportedSDKLeaks parses p's non-test source and reports every SDK type
// reachable from an exported declaration.
func findExportedSDKLeaks(t *testing.T, p listedPackage) []string {
	t.Helper()
	fset := token.NewFileSet()

	type parsedFile struct {
		file *ast.File
		// sdkNames are the identifiers this file binds to an SDK import: the
		// alias if one is given, else the package's assumed name. Per-file,
		// because an alias binds only in the file that writes it.
		sdkNames map[string]string // ident -> import path
	}
	var files []parsedFile
	// localTypes indexes the package's own type declarations by name, so a
	// reference to an unexported type can be followed into its definition.
	localTypes := map[string]*ast.TypeSpec{}

	for _, name := range p.GoFiles {
		path := filepath.Join(p.Dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		pf := parsedFile{file: f, sdkNames: map[string]string{}}
		for _, imp := range f.Imports {
			ipath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("bad import path literal in %s: %v", path, err)
			}
			if !isSDKImport(ipath) {
				continue
			}
			name := filepath.Base(ipath) // go-sdk/mcp -> "mcp"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name == "_" || name == "." {
				// A dot-import would make SDK names unqualified and defeat this
				// walk; a blank import cannot leak. Neither is acceptable here.
				t.Errorf("package %s uses a %q import of %s; the leak guard requires a named SDK import",
					p.ImportPath, name, ipath)
				continue
			}
			pf.sdkNames[name] = ipath
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					localTypes[ts.Name.Name] = ts
				}
			}
		}
		files = append(files, pf)
	}

	// The worklist is the transitive closure of type syntax reachable from
	// exported declarations. Each entry pairs an expression to walk with the
	// exported declaration that made it reachable, so the failure names the API
	// a consumer would actually touch — not the private type in the middle.
	type work struct {
		expr    ast.Expr
		rootFor string
		names   map[string]string
	}
	var queue []work
	visited := map[string]bool{}

	push := func(e ast.Expr, root string, names map[string]string) {
		if e != nil {
			queue = append(queue, work{expr: e, rootFor: root, names: names})
		}
	}

	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				// A method on an unexported type is unreachable for a consumer;
				// a method on an exported one is part of that type's API.
				if !exportedFunc(d) {
					continue
				}
				// Signature only. The body may hold SDK values freely.
				push(d.Type, declName(d), pf.sdkNames)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						push(s.Type, "type "+s.Name.Name, pf.sdkNames)
					case *ast.ValueSpec:
						if !anyExported(s.Names) {
							continue
						}
						push(s.Type, "var/const "+s.Names[0].Name, pf.sdkNames)
						// A var's initializer can name a type too:
						// `var X = mcp.Tool{}` has no Type field at all.
						for _, v := range s.Values {
							push(v, "var/const "+s.Names[0].Name, pf.sdkNames)
						}
					}
				}
			}
		}
	}

	var leaks []string
	for len(queue) > 0 {
		w := queue[0]
		queue = queue[1:]
		if w.expr == nil {
			continue
		}
		ast.Inspect(w.expr, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				// A qualified name: pkg.Type. Only a bare identifier on the
				// left is a package qualifier; `x.f.T` is a field access.
				id, ok := e.X.(*ast.Ident)
				if !ok {
					return true
				}
				if _, isSDK := w.names[id.Name]; !isSDK {
					return true
				}
				leaks = append(leaks, leakSite{
					Decl: w.rootFor,
					Expr: id.Name + "." + e.Sel.Name,
					Pos:  fset.Position(e.Pos()).String(),
				}.String())
				return false
			case *ast.Ident:
				// A reference to one of the package's own types: follow it, so
				// an exported func returning an unexported struct that embeds
				// an SDK type is still a leak.
				ts, ok := localTypes[e.Name]
				if !ok {
					return true
				}
				key := w.rootFor + "\x00" + e.Name
				if visited[key] {
					return true
				}
				visited[key] = true
				// The referenced type's own file binds its own SDK names.
				for _, pf := range files {
					if withinFile(fset, pf.file, ts.Pos()) {
						push(ts.Type, w.rootFor, pf.sdkNames)
						break
					}
				}
				return true
			}
			return true
		})
	}
	return leaks
}

// withinFile reports whether pos falls inside f.
func withinFile(fset *token.FileSet, f *ast.File, pos token.Pos) bool {
	return fset.Position(pos).Filename == fset.Position(f.Pos()).Filename
}

// exportedFunc reports whether a function or method is part of the package's
// exported API.
func exportedFunc(d *ast.FuncDecl) bool {
	if d.Recv == nil {
		return d.Name.IsExported()
	}
	if !d.Name.IsExported() {
		return false
	}
	if len(d.Recv.List) == 0 {
		return false
	}
	return exportedReceiver(d.Recv.List[0].Type)
}

// exportedReceiver reports whether a receiver type expression names an exported
// type, unwrapping the pointer and any generic instantiation.
func exportedReceiver(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.StarExpr:
		return exportedReceiver(t.X)
	case *ast.IndexExpr:
		return exportedReceiver(t.X)
	case *ast.IndexListExpr:
		return exportedReceiver(t.X)
	case *ast.Ident:
		return t.IsExported()
	default:
		return false
	}
}

func anyExported(names []*ast.Ident) bool {
	for _, n := range names {
		if n.IsExported() {
			return true
		}
	}
	return false
}

func declName(d *ast.FuncDecl) string {
	if d.Recv != nil && len(d.Recv.List) > 0 {
		return "method " + recvString(d.Recv.List[0].Type) + "." + d.Name.Name
	}
	return "func " + d.Name.Name
}

func recvString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + recvString(t.X)
	case *ast.IndexExpr:
		return recvString(t.X)
	case *ast.IndexListExpr:
		return recvString(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return "?"
	}
}
