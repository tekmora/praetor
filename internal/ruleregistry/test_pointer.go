// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>

package ruleregistry

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

var testName = regexp.MustCompile(`^Test[A-Z0-9_][A-Za-z0-9_]*$`)

// resolveTest checks for a named test declaration in the indicated package directory.
func resolveTest(ctx context.Context, root, value string) (err error) {
	index := strings.LastIndexByte(value, '.')
	if index < 1 || !safeRelative(value[:index]) || !testName.MatchString(value[index+1:]) {
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
	files, err := packageTestFiles(ctx, dir)
	if err != nil {
		return false, fmt.Errorf("list test files: %w", err)
	}
	found := false
	for i := 0; i < len(files) && i < maxTestFiles; i++ {
		match, err := fileHasTest(ctx, dir, files[i], name)
		if err != nil {
			return false, err
		}
		found = found || match
	}
	return found, nil
}

// packageTestFiles lists the Go test files of one pinned package directory within the listing bound.
func packageTestFiles(ctx context.Context, dir *os.Root) (names []string, err error) {
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
	for i := 0; i < len(entries) && i < util.DefaultDiscoveryEntries; i++ {
		entry := entries[i]
		if isPackageTestFile(entry) {
			names = append(names, entry.Name())
		}
	}
	if len(names) > maxTestFiles {
		return nil, fmt.Errorf("package exceeds %d test files", maxTestFiles)
	}
	slices.Sort(names)
	return names, ctx.Err()
}

// isPackageTestFile reports whether a directory entry is a _test.go file the go tool would build.
func isPackageTestFile(entry os.DirEntry) bool {
	name := entry.Name()
	return !entry.IsDir() && name[0] != '.' && name[0] != '_' && strings.HasSuffix(name, "_test.go")
}

// fileHasTest parses one test file and reports whether it declares the named top-level test function.
func fileHasTest(ctx context.Context, dir *os.Root, file, name string) (bool, error) {
	data, err := contextopt.ReadRootSnapshot(ctx, dir, file)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", file, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), file, data, parser.SkipObjectResolution)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", file, err)
	}
	return slices.ContainsFunc(parsed.Decls, func(decl ast.Decl) bool {
		fn, ok := decl.(*ast.FuncDecl)
		return ok && fn.Recv == nil && fn.Name.Name == name && hasTestSignature(fn.Type)
	}), nil
}

// hasTestSignature follows cmd/go's syntactic test for a single *T or *pkg.T parameter.
func hasTestSignature(signature *ast.FuncType) bool {
	if signature.TypeParams != nil || signature.Results.NumFields() != 0 || signature.Params.NumFields() != 1 {
		return false
	}
	ptr, ok := signature.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch typ := ptr.X.(type) {
	case *ast.Ident:
		return typ.Name == "T"
	case *ast.SelectorExpr:
		return typ.Sel.Name == "T"
	default:
		return false
	}
}
