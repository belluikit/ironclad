//go:build darwin

package loader

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"plugin"
	"time"
)

// platformLoad loads decrypted shared library bytes as a Go plugin
// using a secure temporary file with ad-hoc code signing.
//
// macOS requires dlopen targets to be code-signed. The plaintext
// exists on disk briefly in a restrictive per-process directory
// and is deleted immediately after loading.
//
// Flow:
//  1. Create a per-process temp directory with 0700 permissions
//  2. Write decrypted bytes to a temp file, set permissions to 0500
//  3. Ad-hoc codesign the file (required by macOS for dlopen)
//  4. plugin.Open(path) — dlopen maps the file
//  5. os.Remove(path) — unlink immediately; dlopen holds the fd
//  6. Clean up the temp directory
func platformLoad(data []byte) (*plugin.Plugin, error) {
	// Create per-process secure temp directory
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("ironclad-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	// Write to temp file
	f, err := os.CreateTemp(dir, "plugin-*.dylib")
	if err != nil {
		os.Remove(dir)
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()

	// Cleanup helper for error paths
	cleanup := func() {
		os.Remove(tmpPath)
		os.Remove(dir)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	// Set restrictive permissions (read + execute only)
	if err := os.Chmod(tmpPath, 0500); err != nil {
		cleanup()
		return nil, fmt.Errorf("chmod temp file: %w", err)
	}

	// Ad-hoc codesign — required by macOS for dlopen
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "codesign", "-s", "-", tmpPath).Run(); err != nil {
		cleanup()
		return nil, fmt.Errorf("codesign: %w (is Xcode Command Line Tools installed?)", err)
	}

	// Load the plugin
	p, err := plugin.Open(tmpPath)

	// Immediately unlink — dlopen holds its own fd to the inode
	os.Remove(tmpPath)
	os.Remove(dir) // best-effort; succeeds if empty

	if err != nil {
		return nil, fmt.Errorf("plugin.Open: %w", err)
	}
	return p, nil
}
