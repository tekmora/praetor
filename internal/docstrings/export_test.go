// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package docstrings

import "context"

// TargetFileReaderFunc is the signature for reading a file at a target ref.
type TargetFileReaderFunc = func(ctx context.Context, repoDir, headRef, rel string) ([]byte, bool, error)

// ReadTargetFileDefault exposes the default targetFileReader for test wrappers.
var ReadTargetFileDefault = readTargetFile

// ParseRemoteDefaultBranchForTest exposes parseRemoteDefaultBranch for boundary testing.
var ParseRemoteDefaultBranchForTest = parseRemoteDefaultBranch

// SkipPythonDecoratorForTest exposes the decorator scan separately from Python body docstrings.
func SkipPythonDecoratorForTest(lines []string, idx int) (int, bool) {
	return skipAttributesAbove(lines, idx, "python")
}

// SetTargetFileReaderForTest replaces targetFileReader and returns a restore function.
func SetTargetFileReaderForTest(fn TargetFileReaderFunc) func() {
	orig := targetFileReader
	targetFileReader = fn
	return func() {
		targetFileReader = orig
	}
}
