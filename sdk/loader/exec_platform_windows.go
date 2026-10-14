// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

//go:build windows

package loader

import (
	"fmt"
	"os"
	"path/filepath"
)

// platformPrepareExec writes decrypted executable bytes to a secure
// temporary file with a .exe extension.
//
// Windows locks running executables, so the cleanup function should
// be called after the process exits (cmd.Wait). If the file is still
// locked, removal is best-effort.
func platformPrepareExec(data []byte) (execPath string, cleanup func(), err error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("ironclad-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	f, err := os.CreateTemp(dir, "exec-*.exe")
	if err != nil {
		os.Remove(dir)
		return "", nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()

	cleanupAll := func() {
		os.Remove(tmpPath)
		os.Remove(dir)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanupAll()
		return "", nil, fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanupAll()
		return "", nil, fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, 0500); err != nil {
		cleanupAll()
		return "", nil, fmt.Errorf("chmod temp file: %w", err)
	}

	return tmpPath, cleanupAll, nil
}
