// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package hisscoverage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cordanaLLM/praetor/internal/contextopt"
)

// maxRetainedFixtureBytes caps backing arrays retained between fixture reads across a corpus.
const maxRetainedFixtureBytes = contextopt.MaxSourceBytes

// fixtureStore shares one retention budget and one lazy private spill file across all buckets.
type fixtureStore struct {
	retained int
	spill    fixtureSpill
	end      int64
}

// fixtureSpill is the owned random-access file used for ranges outside the resident budget.
type fixtureSpill interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Name() string
}

// capturedFixture holds either resident bytes or a range in the snapshot's private spill file.
type capturedFixture struct {
	name   string
	data   []byte
	offset int64
	size   int
}

// save keeps the entire backing array within budget or appends the bytes to the spill handle.
func (s *fixtureStore) save(ctx context.Context, name string, data []byte) (capturedFixture, error) {
	file := capturedFixture{name: name, size: len(data)}
	if err := ctx.Err(); err != nil {
		return file, err
	}
	if cap(data) <= maxRetainedFixtureBytes-s.retained {
		s.retained += cap(data)
		file.data = data
		return file, nil
	}
	if s.spill == nil {
		spill, err := os.CreateTemp("", "hiss-corpus-*")
		if err != nil {
			return file, fmt.Errorf("create fixture spill: %w", errors.Join(err, ctx.Err()))
		}
		s.spill = spill
	}
	if err := ctx.Err(); err != nil {
		return capturedFixture{}, err
	}
	file.offset = s.end
	n, writeErr := s.spill.WriteAt(data, file.offset)
	if err := errors.Join(writeErr, ctx.Err()); err != nil {
		return capturedFixture{}, fmt.Errorf("spill fixture: %w", err)
	}
	s.end += int64(n)
	return file, nil
}

// load retrieves the captured bytes of one fixture without consulting its original path.
func (s *fixtureStore) load(ctx context.Context, file capturedFixture) ([]byte, error) {
	if file.data != nil || file.size == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return file.data, nil
	}
	return file.readSpill(ctx, s.spill)
}

// readSpill checks cancellation around the synchronous read of one captured range.
func (file capturedFixture) readSpill(ctx context.Context, spill io.ReaderAt) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data := make([]byte, file.size)
	_, readErr := spill.ReadAt(data, file.offset)
	if err := errors.Join(readErr, ctx.Err()); err != nil {
		return nil, fmt.Errorf("read spilled fixture: %w", err)
	}
	return data, nil
}

// close releases the spill handle before unlinking its file on every platform.
func (s *fixtureStore) close() error {
	if s.spill == nil {
		return nil
	}
	return errors.Join(s.spill.Close(), os.Remove(s.spill.Name()))
}
