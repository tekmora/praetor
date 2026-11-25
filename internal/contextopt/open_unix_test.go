//go:build unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestNonblockingOpenRejectsFileReplacedByFIFO(t *testing.T) {
	root := contextFixture(t, map[string][]byte{"policy.md": []byte("before")})
	path := filepath.Join(root, "policy.md")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pinned.Close(); err != nil {
			t.Error(err)
		}
	})
	done := make(chan error, 1)
	go func() {
		file, err := openSource(pinned, "policy.md")
		if err != nil {
			done <- err
			return
		}
		_, readErr := stableRead(context.Background(), file, before)
		if err := file.Close(); err != nil {
			done <- err
			return
		}
		done <- readErr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO replacement was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("source open blocked on FIFO")
	}
}

// TestOpenSourceRefusesReplacementSymlink checks the open itself when the relative link
// points to the very inode already inspected. An identity comparison alone accepts it.
func TestOpenSourceRefusesReplacementSymlink(t *testing.T) {
	dir := contextFixture(t, map[string][]byte{"fixture.go": []byte("original")})
	root := snapshotDirectory(t, dir)
	const name = "fixture.go"
	if _, err := root.Lstat(name); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename(name, "original.go"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("original.go", name); err != nil {
		t.Fatal(err)
	}
	file, err := openSource(root, name)
	if file != nil {
		t.Errorf("opened a fixture through a replacement link")
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Path != name {
		t.Fatalf("want the refused leaf's open error, got %v", err)
	}
}

// listedTestBucket renames the original directory before the next no-follow acquisition.
func listedTestBucket(t *testing.T) (*SnapshotDirectory, string) {
	t.Helper()
	dir := t.TempDir()
	root := snapshotDirectory(t, dir)
	if err := root.Mkdir("bucket", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("bucket", "original"); err != nil {
		t.Fatal(err)
	}
	parent, err := OpenSnapshotDirectoryIn(t.Context(), dir, ".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := parent.Close(); err != nil {
			t.Error(err)
		}
	})
	return parent, filepath.Join(dir, "bucket")
}

// openReplacedBucket attempts a fresh no-follow acquisition and releases any accepted handle.
func openReplacedBucket(ctx context.Context, parent *SnapshotDirectory) error {
	child, err := OpenChildDirectory(ctx, parent, "bucket")
	if err != nil {
		return err
	}
	return child.Close()
}

// TestListedDirectoryRefusesReplacementLink rejects a link back to the original directory.
func TestListedDirectoryRefusesReplacementLink(t *testing.T) {
	parent, path := listedTestBucket(t)
	if err := os.Symlink("original", path); err != nil {
		t.Fatal(err)
	}
	if err := openReplacedBucket(t.Context(), parent); err == nil {
		t.Fatal("opened the original directory through its replacement link")
	}
}

// TestListedDirectoryRefusesReplacementFIFO requires the acquisition to finish while
// the FIFO has no writer. A failing blocking opener is released during cleanup.
func TestListedDirectoryRefusesReplacementFIFO(t *testing.T) {
	parent, path := listedTestBucket(t)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- openReplacedBucket(ctx, parent) }()
	select {
	case err := <-done:
		if err == nil || ctx.Err() != nil {
			t.Fatalf("expected an open error before the deadline, got %v (context %v)", err, ctx.Err())
		}
	case <-ctx.Done():
		releaseBlockedBucket(t, path, done)
		t.Fatal("directory open blocked on a FIFO until the context expired")
	}
}

// releaseBlockedBucket pairs with a blocked read open before the test closes its parent.
func releaseBlockedBucket(t *testing.T, path string, done <-chan error) {
	t.Helper()
	writer, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	select {
	case err := <-done:
		t.Logf("released directory opener returned %v", err)
	case <-time.After(time.Second):
		t.Error("directory opener still running after FIFO release")
	}
}
