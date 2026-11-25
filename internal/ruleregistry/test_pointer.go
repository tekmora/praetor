// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>

package ruleregistry

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/hiss"
	"github.com/cordanaLLM/praetor/internal/util"
)

// isTestName applies cmd/go's Test prefix rule to a Go identifier.
func isTestName(name string) bool {
	suffix, ok := strings.CutPrefix(name, "Test")
	if !ok || !token.IsIdentifier(name) {
		return false
	}
	if suffix == "" {
		return true
	}
	first, _ := utf8.DecodeRuneInString(suffix)
	return !unicode.IsLower(first)
}

// resolveTest checks for a named test declaration in the indicated package directory.
func resolveTest(ctx context.Context, root, value string) (err error) {
	index := strings.LastIndexByte(value, '.')
	if index < 1 || !safeRelative(value[:index]) || !isTestName(value[index+1:]) {
		return fmt.Errorf("unresolved evidence pointer %q", "test:"+value)
	}
	ctx, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	dir, err := contextopt.OpenDirectoryIn(ctx, root, filepath.FromSlash(value[:index]))
	if err != nil {
		return fmt.Errorf("open package for test:%s: %w", value, err)
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	found, err := packageHasTest(ctx, dir, value[index+1:])
	if err != nil {
		return fmt.Errorf("resolve test:%s: %w", value, err)
	}
	if !found {
		return fmt.Errorf("unresolved evidence pointer %q", "test:"+value)
	}
	return nil
}

// packageHasTest checks every candidate so that an earlier match cannot hide a read or parse error.
func packageHasTest(ctx context.Context, dir *os.Root, name string) (bool, error) {
	files, err := packageGoFiles(ctx, dir)
	if err != nil {
		return false, fmt.Errorf("list package files: %w", err)
	}
	evidence := testEvidence{aliases: make(map[testTypeName]bool)}
	for i := 0; i < len(files) && i < util.DefaultDiscoveryEntries; i++ {
		if err := evidence.readFile(ctx, dir, files[i], name); err != nil {
			return false, err
		}
	}
	return evidence.hasTest(), ctx.Err()
}

// packageGoFiles lists visible Go sources and preserves the separate limit on test files.
func packageGoFiles(ctx context.Context, dir *os.Root) (names []string, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listing, err := dir.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, listing.Close()) }()
	entries, err := listing.ReadDir(util.DefaultDiscoveryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > util.DefaultDiscoveryEntries {
		return nil, fmt.Errorf("package exceeds %d directory entries", util.DefaultDiscoveryEntries)
	}
	return visiblePackageFiles(entries)
}

// visiblePackageFiles returns sorted source names, enforcing the test file bound before parsing.
func visiblePackageFiles(entries []os.DirEntry) ([]string, error) {
	var names []string
	testFiles := 0
	for i := 0; i < len(entries) && i < util.DefaultDiscoveryEntries; i++ {
		entry := entries[i]
		name := entry.Name()
		if entry.IsDir() || name[0] == '.' || name[0] == '_' || !strings.HasSuffix(name, ".go") {
			continue
		}
		names = append(names, name)
		if strings.HasSuffix(name, "_test.go") {
			testFiles++
		}
	}
	if testFiles > maxTestFiles {
		return nil, fmt.Errorf("package exceeds %d test files (found %d)", maxTestFiles, testFiles)
	}
	slices.Sort(names)
	return names, nil
}

// testTypeName identifies a type in its declaring package. An empty name denotes a direct *testing.T parameter.
type testTypeName struct {
	pkg, name string
}

// testEvidence retains only package identities, type bindings and the requested test's parameter.
type testEvidence struct {
	pkg        string
	aliases    map[testTypeName]bool
	parameters []testTypeName
}

// hasTest resolves candidates after every file has contributed its package and aliases.
func (e *testEvidence) hasTest() bool {
	if e.pkg == "" {
		return false
	}
	return slices.ContainsFunc(e.parameters, func(param testTypeName) bool {
		return (param.pkg == e.pkg || param.pkg == e.pkg+"_test") && (param.name == "" || e.aliases[param])
	})
}

// readFile collects evidence from one unconstrained file and establishes the non-test package.
func (e *testEvidence) readFile(ctx context.Context, dir *os.Root, file, name string) error {
	data, err := contextopt.ReadRootSnapshot(ctx, dir, file)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), file, data, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse %s: %w", file, err)
	}
	pkg := parsed.Name.Name
	if pkg == "documentation" || hasBuildConstraint(parsed) {
		return nil
	}
	isTest := strings.HasSuffix(file, "_test.go")
	if !isTest {
		if e.pkg != "" && e.pkg != pkg {
			return fmt.Errorf("conflicting non-test package %s in %s (previously %s)", pkg, file, e.pkg)
		}
		e.pkg = pkg
	}
	e.collect(parsed, name, isTest)
	return nil
}

// hasBuildConstraint recognizes both build directive spellings in Go line comments.
func hasBuildConstraint(file *ast.File) bool {
	return slices.ContainsFunc(file.Comments, func(group *ast.CommentGroup) bool {
		return slices.ContainsFunc(group.List, func(comment *ast.Comment) bool {
			return constraint.IsGoBuild(comment.Text) || constraint.IsPlusBuild(comment.Text)
		})
	})
}

// collect indexes top-level type declarations and matching test functions in one file.
func (e *testEvidence) collect(file *ast.File, name string, isTest bool) {
	imports := hiss.FileImports(file)
	pkg := file.Name.Name
	for i := 0; i < len(file.Decls) && i < contextopt.MaxSourceBytes; i++ {
		switch decl := file.Decls[i].(type) {
		case *ast.GenDecl:
			if decl.Tok == token.TYPE {
				e.recordTypes(pkg, decl, imports)
			}
		case *ast.FuncDecl:
			if !isTest || decl.Recv != nil || decl.Name.Name != name {
				continue
			}
			if param, ok := testParameter(decl.Type, imports); ok {
				e.parameters = append(e.parameters, testTypeName{pkg, param})
			}
		}
	}
}

// recordTypes accepts only a unique direct alias of the imported testing.T in this package.
func (e *testEvidence) recordTypes(pkg string, decl *ast.GenDecl, imports hiss.GoImports) {
	for i := 0; i < len(decl.Specs) && i < contextopt.MaxSourceBytes; i++ {
		spec, ok := decl.Specs[i].(*ast.TypeSpec)
		if !ok {
			continue
		}
		key := testTypeName{pkg, spec.Name.Name}
		_, duplicate := e.aliases[key]
		e.aliases[key] = !duplicate && spec.Assign.IsValid() && spec.TypeParams == nil && importedTestingT(spec.Type, imports)
	}
}

// testParameter returns an empty name for imported testing.T or "T" for a candidate package-level alias.
func testParameter(signature *ast.FuncType, imports hiss.GoImports) (string, bool) {
	if signature.TypeParams != nil || signature.Results.NumFields() != 0 || signature.Params.NumFields() != 1 {
		return "", false
	}
	ptr, ok := signature.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return "", false
	}
	if importedTestingT(ptr.X, imports) {
		return "", true
	}
	ident, ok := ptr.X.(*ast.Ident)
	if !ok || ident.Name != "T" {
		return "", false
	}
	_, bound := imports.Path(ident.Name)
	return ident.Name, !bound
}

// importedTestingT resolves T only through this file's qualified or dot import of testing.
func importedTestingT(expr ast.Expr, imports hiss.GoImports) bool {
	switch typ := expr.(type) {
	case *ast.Ident:
		return typ.Name == "T" && imports.DotImports("testing")
	case *ast.SelectorExpr:
		pkg, ok := typ.X.(*ast.Ident)
		return ok && typ.Sel.Name == "T" && imports.Binds(pkg.Name, "testing")
	default:
		return false
	}
}
