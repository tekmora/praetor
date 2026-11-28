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
	"github.com/cordanaLLM/praetor/internal/util"
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
		spill, err := util.CheckedIO(ctx, func() (*os.File, error) { return os.CreateTemp("", "hiss-corpus-*") })
		if spill != nil {
			s.spill = spill // The store also owns a spill acquired after cancellation.
		}
		if err != nil {
			return file, fmt.Errorf("create fixture spill: %w", err)
		}
	}
	file.offset = s.end
	n, err := util.CheckedIO(ctx, func() (int, error) { return s.spill.WriteAt(data, file.offset) })
	if err != nil {
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

// readSpill bounds one synchronous range read and rejects bytes returned after its deadline.
func (file capturedFixture) readSpill(ctx context.Context, spill io.ReaderAt) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data := make([]byte, file.size)
	_, err := util.CheckedIO(ctx, func() (int, error) { return spill.ReadAt(data, file.offset) })
	if err != nil {
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
