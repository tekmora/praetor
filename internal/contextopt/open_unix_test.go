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
