//go:build windows

package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
)

// platformLoad loads decrypted shared library bytes as a Go plugin
// using a secure temporary file.
//
// This implementation requires the Go plugin patch for Windows support.
// Without the patch, plugin.Open will fail at runtime.
//
// Flow:
//  1. Create a per-process temp directory with restrictive permissions
//  2. Write decrypted bytes to a temp file
//  3. plugin.Open(path)
//  4. os.Remove(path) — delete immediately after loading
//  5. Clean up the temp directory
func platformLoad(data []byte) (*plugin.Plugin, error) {
	// Create per-process secure temp directory
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("ironclad-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	// Write to temp file
	f, err := os.CreateTemp(dir, "plugin-*.dll")
	if err != nil {
		os.Remove(dir)
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()

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

	if err := os.Chmod(tmpPath, 0500); err != nil {
		cleanup()
		return nil, fmt.Errorf("chmod temp file: %w", err)
	}

	// Load the plugin
	p, err := plugin.Open(tmpPath)

	// Immediately delete — on Windows, this may fail if the DLL
	// is still locked by the process. In that case, the file
	// remains in the secure temp directory until process exit.
	os.Remove(tmpPath)
	os.Remove(dir)

	if err != nil {
		return nil, fmt.Errorf("plugin.Open: %w", err)
	}
	return p, nil
}
