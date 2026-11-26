// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//go:build unix

package util

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcStartTick extracts the start tick from a bounded proc stat record and rejects malformed or missing data.
func ProcStartTick(root string, pid int) (uint64, error) {
	data, err := ReadFileLimited(filepath.Join(root, strconv.Itoa(pid), "stat"), 65536)
	if err != nil {
		return 0, fmt.Errorf("read process start tick: %w", err)
	}
	pos := strings.LastIndex(string(data), ") ")
	if pos < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data)[pos+2:])
	if len(fields) < 20 {
		return 0, errors.New("short process stat")
	}
	tick, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid process start tick: %w", err)
	}
	return tick, nil
}
