//go:build !unix

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>

package contextopt

import (
	"context"
	"os"

	"github.com/cordanaLLM/praetor/internal/util"
)

// statDescriptor checks metadata on platforms without a native descriptor reader.
func statDescriptor(ctx context.Context, file *os.File) (os.FileInfo, error) {
	return util.CheckedIO(ctx, file.Stat)
}
