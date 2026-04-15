//go:build darwin

package loader

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// platformPrepareExec writes decrypted executable bytes to a secure
// temporary file with ad-hoc code signing.
//
// macOS requires code signing for execution. The plaintext exists on
// disk briefly in a restrictive per-process directory. The returned
// cleanup function unlinks the file — safe to call after cmd.Start()
// because the OS retains the inode while the process has it mapped.
func platformPrepareExec(data []byte) (execPath string, cleanup func(), err error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("ironclad-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	f, err := os.CreateTemp(dir, "exec-*")
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

	// Ad-hoc codesign — required by macOS for execution
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "codesign", "-s", "-", tmpPath).Run(); err != nil {
		cleanupAll()
		return "", nil, fmt.Errorf("codesign: %w (is Xcode Command Line Tools installed?)", err)
	}

	return tmpPath, cleanupAll, nil
}
