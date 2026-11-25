//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// direntBlockSize matches the block used by os.File's Unix directory cursor.
const direntBlockSize = 8192

// maxEmptyDirentBlocks limits consecutive native reads that yield only unused slots.
const maxEmptyDirentBlocks = 256

// readNames returns at most n names, retaining surplus records for the next bounded read.
func (dir *SnapshotDirectory) readNames(ctx context.Context, n int) ([]listedName, error) {
	// A block of tombstones or dot entries can precede ordinary names or EOF.
	for skipped := 0; len(dir.pending) == 0 && skipped < maxEmptyDirentBlocks; skipped++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		batch, err := dir.readDirentBlock(ctx)
		if err != nil {
			return nil, err
		}
		dir.pending = batch
	}
	if len(dir.pending) == 0 {
		return nil, io.ErrNoProgress
	}
	count := min(n, len(dir.pending))
	names := dir.pending[:count:count]
	dir.pending = dir.pending[count:]
	return names, nil
}

// readDirentBlock reads one block through the held file without opening a second directory cursor.
func (dir *SnapshotDirectory) readDirentBlock(ctx context.Context) ([]listedName, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	var buf [direntBlockSize]byte
	var size int
	var readErr error
	if err := conn.Control(func(fd uintptr) { size, readErr = readNativeDirents(fd, buf[:]) }); err != nil {
		return nil, err
	}
	if readErr != nil {
		return nil, &os.PathError{Op: "readdirent", Path: dir.Name(), Err: readErr}
	}
	if size == 0 {
		return nil, io.EOF
	}
	if size < 0 || size > len(buf) {
		return nil, io.ErrUnexpectedEOF
	}
	return dir.decodeDirents(ctx, buf[:size])
}

// decodeDirents pairs each parsed name with the type byte from that same native record.
func (dir *SnapshotDirectory) decodeDirents(ctx context.Context, buf []byte) ([]listedName, error) {
	var names []listedName
	// SAFETY: Both offsets are compile-time constants. The native header precedes d_name.
	const (
		nameOffset = int(unsafe.Offsetof(unix.Dirent{}.Name))
		typeOffset = unsafe.Offsetof(unix.Dirent{}.Type)
	)
	for offset := 0; offset < len(buf); {
		record := buf[offset:]
		if len(record) <= nameOffset {
			return nil, io.ErrUnexpectedEOF
		}
		size := direntRecordSize(record)
		if size <= nameOffset || size > len(record) {
			return nil, io.ErrUnexpectedEOF
		}
		offset += size
		var slot [1]string
		_, _, parsed := unix.ParseDirent(record[:size], 1, slot[:0])
		if len(parsed) == 0 { // Native dot entries and unused directory slots.
			continue
		}
		names = append(names, dir.observeDirent(ctx, parsed[0], record[typeOffset]))
	}
	return names, nil
}

// direntKinds maps the d_type vocabulary to the same file kinds as a relative lstat.
var direntKinds = map[byte]os.FileMode{
	unix.DT_REG:  0,
	unix.DT_DIR:  os.ModeDir,
	unix.DT_LNK:  os.ModeSymlink,
	unix.DT_CHR:  os.ModeDevice | os.ModeCharDevice,
	unix.DT_BLK:  os.ModeDevice,
	unix.DT_FIFO: os.ModeNamedPipe,
	unix.DT_SOCK: os.ModeSocket,
}

// observeDirent takes an immediate relative lstat only when the record supplies no type.
func (dir *SnapshotDirectory) observeDirent(ctx context.Context, name string, typ byte) listedName {
	if typ == unix.DT_UNKNOWN {
		return dir.observeUntypedName(ctx, name)
	}
	kind, ok := direntKinds[typ]
	if !ok {
		kind = os.ModeIrregular
	}
	return listedName{name: name, kind: kind}
}
