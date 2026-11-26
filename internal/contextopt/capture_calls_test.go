// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCaptureCallsUseCheckedIO inspects all capture backends, including files
// excluded by the host build tags. Shared files contribute their capture functions.
func TestCaptureCallsUseCheckedIO(t *testing.T) {
	files := map[string]string{
		"../hisscoverage/corpus.go":         "",
		"../hisscoverage/snapshot_store.go": "save readSpill",
		"../util/absent_dir.go":             "",
		"artifacts.go":                      "OpenDirectory",
		"winfileid/query_windows.go":        "",
		"snapshot_directory.go":             "",
		"source.go":                         "openDirectory openCheckedRoot Read stableCopy statCopySource checkOpenedSource",
	}
	for _, pattern := range []string{"dirent_*.go", "listing_*.go", "open_*.go", "stat_*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range matches {
			if !strings.HasSuffix(path, "_test.go") {
				files[path] = ""
			}
		}
	}
	for path, functions := range files {
		t.Run(path, func(t *testing.T) {
			for _, pos := range uncheckedCaptureCalls(t, path, nil, functions) {
				t.Errorf("%s: native fixture operation outside checked callback", pos)
			}
		})
	}
}

// TestCaptureCallGuardPlantsBypasses rejects direct calls, eager arguments and
// escaped method values even when a checked operation occurs in the same function.
func TestCaptureCallGuardPlantsBypasses(t *testing.T) {
	const src = `package fixture
func capture() {
	util.CheckedIO(ctx, file.Stat)
	retryInterrupted(ctx, func() (int, error) { return unix.ReadDirent(fd, buf) })
	file.Stat()
	util.CheckedIO(ctx, wrap(unix.Fstat(fd, st)))
	late := file.Stat
	late()
	util.CheckedIO(ctx, func() { file.Stat(); file.Stat() })
	util.CheckedIO(ctx, func() { for range 2 { file.Stat() } })
}`
	if got := uncheckedCaptureCalls(t, "planted.go", src, ""); len(got) != 5 {
		t.Fatalf("wanted five unchecked native operations, found %v", got)
	}
}

// uncheckedCaptureCalls reports native references and injected calls in the selected functions.
func uncheckedCaptureCalls(t *testing.T, path string, src any, functions string) []token.Position {
	t.Helper()
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, path, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var unchecked []token.Position
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || functions != "" && !slices.Contains(strings.Fields(functions), fn.Name.Name) {
			continue
		}
		used := make(map[*ast.FuncLit]bool)
		ast.PreorderStack(fn.Body, nil, func(node ast.Node, stack []ast.Node) bool {
			if uncheckedUnixStat(path, node) || nativeCaptureOperation(node) && !checkedCaptureOperation(node, stack, used) {
				unchecked = append(unchecked, positions.Position(node.Pos()))
			}
			return true
		})
	}
	return unchecked
}

// uncheckedUnixStat rejects even a wrapped os.File.Stat in the native Unix backend:
// the Go descriptor implementation retries EINTR inside the call.
func uncheckedUnixStat(path string, node ast.Node) bool {
	sel, ok := node.(*ast.SelectorExpr)
	return path == "listing_unix.go" && ok && sel.Sel.Name == "Stat"
}

// nativeCaptureOperation covers OS entry points and the injected native callbacks.
func nativeCaptureOperation(node ast.Node) bool {
	const selectors = "Openat Fstat Fstatat Fstatfs Syscall Syscall6 ReadDirent Readdir Readdirnames ReadDir Stat Lstat OpenRoot Open EvalSymlinks NtCreateFile GetFileInformationByHandleEx Read ReadAt WriteAt CreateTemp Abs DirectoryAbsent"
	const callbacks = "openat fstatat fstat statfs stat lookup read call"
	switch n := node.(type) {
	case *ast.SelectorExpr:
		return slices.Contains(strings.Fields(selectors), n.Sel.Name)
	case *ast.CallExpr:
		id, ok := n.Fun.(*ast.Ident)
		return ok && slices.Contains(strings.Fields(callbacks), id.Name)
	default:
		return false
	}
}

// checkedCaptureOperation admits function values forwarded to checked adapters
// and operations executed inside their callback bodies. Eager arguments remain visible.
func checkedCaptureOperation(node ast.Node, stack []ast.Node, used map[*ast.FuncLit]bool) bool {
	if len(stack) == 0 {
		return false
	}
	if arg, ok := node.(ast.Expr); ok && captureCallbackArgument(arg, stack[len(stack)-1]) {
		return true
	}
	for i := len(stack) - 1; i > 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			return false
		case *ast.FuncLit:
			if used[parent] || !captureCallbackArgument(parent, stack[i-1]) {
				return false
			}
			used[parent] = true
			return true
		}
	}
	return false
}

// captureCallbackArgument recognizes only the deferred callback argument, which
// is last in each adapter. A call expression in that slot still evaluates eagerly.
func captureCallbackArgument(expr ast.Expr, parent ast.Node) bool {
	if _, eager := expr.(*ast.CallExpr); eager {
		return false
	}
	call, ok := parent.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 || call.Args[len(call.Args)-1] != expr {
		return false
	}
	var name string
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		name = fn.Name
	case *ast.SelectorExpr:
		name = fn.Sel.Name
	}
	const adapters = "CheckedIO retryInterrupted statUnixFD openUnixLeaf statUnixDescriptor statUnixListedName readDarwinDirents directoryAbsentContext"
	return slices.Contains(strings.Fields(adapters), name)
}
