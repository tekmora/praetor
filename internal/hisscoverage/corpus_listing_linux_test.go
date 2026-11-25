//go:build linux

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestVerifyCountsVanishingBufferedName exercises Go's Linux directory buffer with a real
// 4097-name bucket. The cursor's kernel read already includes the regular file we unlink.
func TestVerifyCountsVanishingBufferedName(t *testing.T) {
	root := t.TempDir()
	bucket := bucketPath(root, "HISS-01", "go", bucketNegative)
	stageNumberedFixtures(t, bucket, "a", cleanGo, 63)
	stageNumberedSubdirs(t, bucket, "dir", 4033)
	control := verifySnapshot(t, t.Context(), root)
	if !control.Passed() || control.Fixtures != 63 {
		t.Fatalf("4096 stable names: %+v", control)
	}
	writeCorpusFixture(t, root, "HISS-01", "go", bucketNegative, "a-final.go", cleanGo)
	prefix, victim := bufferedRegularName(t, bucket)
	next := vanishingFileReader(t, bucket, prefix, victim)
	ctx := context.WithValue(t.Context(), bucketReaderKey{}, next)
	report := verifySnapshot(t, ctx, root)
	var overflow, disappeared bool
	for _, finding := range report.Findings {
		overflow = overflow || strings.Contains(finding.Detail, "exceeds 4096 directory entries")
		disappeared = disappeared || finding.Fixture == victim && strings.Contains(finding.Detail, "changed during verification")
	}
	if !overflow || !disappeared {
		t.Fatalf("4097 listed names, then %q disappeared: %+v", victim, report)
	}
}

// bufferedRegularName finds a regular record following another record in the same kernel
// read. The directory offset advances only on refill. This measures the buffer boundary
// independently of directory order, entry size and Go's chosen read size.
func bufferedRegularName(t *testing.T, bucket string) (int, string) {
	t.Helper()
	cursor := listingCursor(t, bucket)
	offset := directoryOffset(t, cursor.File)
	for prefix := 0; prefix < 4097; prefix++ {
		names, err := cursor.Readdirnames(1)
		if err != nil || len(names) != 1 {
			t.Fatalf("read name at %d: %v, %v", prefix, names, err)
		}
		after := directoryOffset(t, cursor.File)
		if prefix > 0 && offset == after && strings.HasPrefix(names[0], "a-") {
			return prefix, names[0]
		}
		offset = after
	}
	t.Fatal("no regular entry was buffered after its predecessor")
	return 0, ""
}

// directoryOffset observes the kernel offset without clearing os.File's directory buffer.
func directoryOffset(t *testing.T, file *os.File) int64 {
	t.Helper()
	fd := file.Fd()
	if fd > math.MaxInt {
		t.Fatalf("invalid directory descriptor %d", fd)
	}
	offset, err := unix.Seek(int(fd), 0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	return offset
}

// vanishingFileReader returns a short first batch on the real cursor, then unlinks the
// buffered name before the second batch performs any per-name lookup.
func vanishingFileReader(t *testing.T, bucket string, prefix int, victim string) func(string, int) ([]os.DirEntry, error) {
	t.Helper()
	cursor := listingCursor(t, bucket)
	first := true
	return func(path string, n int) ([]os.DirEntry, error) {
		if path != bucket {
			t.Fatalf("unexpected bucket %q", path)
		}
		if first {
			first = false
			entries, err := cursor.ReadEntries(t.Context(), prefix)
			if err != nil || len(entries) != prefix {
				t.Fatalf("read prefix of %d names: got %d, %v", prefix, len(entries), err)
			}
			if err := os.Remove(filepath.Join(bucket, victim)); err != nil {
				t.Fatal(err)
			}
			return entries, nil
		}
		return cursor.ReadEntries(t.Context(), n)
	}
}
