//go:build (linux && !android) || (darwin && !ios)

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/cordanaLLM/praetor/internal/util"
	"golang.org/x/sys/unix"
)

// direntBlockSize matches the block used by os.File's Unix directory cursor.
const direntBlockSize = 8192

// direntNameOffset is the native header length preceding the first name byte.
// SAFETY: Offsetof is a compile-time ABI constant and accesses no memory.
const direntNameOffset = int(unsafe.Offsetof(unix.Dirent{}.Name))

// maxEmptyDirentBlocks limits consecutive native reads that yield only unused slots.
const maxEmptyDirentBlocks = 256

// maxDirentReadAttempts includes the initial read and bounds retries during a signal storm.
const maxDirentReadAttempts = 8

// readNames returns at most n names, retaining surplus records for the next bounded read.
func (dir *SnapshotDirectory) readNames(ctx context.Context, n int) ([]listedName, error) {
	// A block of tombstones or dot entries can precede ordinary names or EOF.
	for skipped := 0; len(dir.pending) == 0 && skipped < maxEmptyDirentBlocks; skipped++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		batch, err := dir.readDirentBlock(ctx, readNativeDirents)
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
func (dir *SnapshotDirectory) readDirentBlock(ctx context.Context, read func(uintptr, []byte) (int, error)) ([]listedName, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	var buf [direntBlockSize]byte
	var size int
	var readErr error
	if err := conn.Control(func(fd uintptr) {
		size, readErr = retryDirentRead(ctx, func() (int, error) { return read(fd, buf[:]) })
	}); err != nil {
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

// retryDirentRead retries only an isolated EINTR without bytes. Native syscall wrappers
// may return -1 on failure. Cancellation and exhaustion retain the last interruption.
func retryDirentRead(ctx context.Context, read func() (int, error)) (int, error) {
	var n int
	var err error
	for range maxDirentReadAttempts {
		select {
		case <-ctx.Done():
			return n, errors.Join(err, ctx.Err())
		default:
		}
		n, err = read()
		if n < -1 || n > 0 || !errors.Is(util.SoleCause(err), unix.EINTR) {
			return n, err
		}
	}
	return n, err
}

// decodeDirents pairs each parsed name with the type byte from that same native record.
func (dir *SnapshotDirectory) decodeDirents(ctx context.Context, buf []byte) ([]listedName, error) {
	var names []listedName
	// SAFETY: This compile-time offset lies in the checked native header.
	const typeOffset = unsafe.Offsetof(unix.Dirent{}.Type)
	for offset := 0; offset < len(buf); {
		record := buf[offset:]
		if len(record) <= direntNameOffset {
			return nil, io.ErrUnexpectedEOF
		}
		size := direntRecordSize(record)
		if size <= direntNameOffset || size > len(record) {
			return nil, io.ErrUnexpectedEOF
		}
		record = record[:size]
		if !direntNameFits(record) {
			err := fmt.Errorf("d_namlen exceeds the %d-byte name payload at offset %d", size-direntNameOffset, offset)
			return nil, &os.PathError{Op: "decode dirent", Path: dir.Name(), Err: err}
		}
		offset += size
		var slot [1]string
		_, _, parsed := unix.ParseDirent(record, 1, slot[:0])
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

// direntRecordSize reads d_reclen from the native header preceding d_name.
func direntRecordSize(record []byte) int {
	// SAFETY: This compile-time offset precedes d_name in the checked native header.
	return int(binary.NativeEndian.Uint16(record[unsafe.Offsetof(unix.Dirent{}.Reclen):]))
}

// observeUntypedName takes the first relative lstat when a record supplies no kind.
// A failed observation keeps the name in its directory slot.
func (dir *SnapshotDirectory) observeUntypedName(ctx context.Context, name string) listedName {
	if err := ctx.Err(); err != nil {
		return listedName{name: name, err: err}
	}
	info, err := dir.statListedName(name)
	listed := listedName{name: name, observed: info, err: err}
	if err == nil {
		listed.kind = info.Mode().Type()
	}
	return listed
}
