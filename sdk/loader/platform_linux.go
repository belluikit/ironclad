//go:build linux

package loader

import (
	"fmt"
	"plugin"

	"golang.org/x/sys/unix"
)

// platformLoad loads decrypted shared library bytes as a Go plugin
// using memfd_create. The plaintext never touches a real filesystem.
//
// Flow:
//  1. Create an anonymous in-memory file via memfd_create
//  2. Write the decrypted bytes to the memfd
//  3. Seal the memfd against modification (F_SEAL_*)
//  4. Load via plugin.Open("/proc/self/fd/<fd>")
//  5. Close the fd (dlopen holds its own reference)
func platformLoad(data []byte) (*plugin.Plugin, error) {
	// Create anonymous in-memory file descriptor
	fd, err := unix.MemfdCreate("ironclad", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}

	// Write all bytes to the memfd
	written := 0
	for written < len(data) {
		n, err := unix.Write(fd, data[written:])
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("write to memfd: %w", err)
		}
		written += n
	}

	// Seal the memfd to prevent modification after loading.
	// Best-effort: sealing hardens security but is not required for loading.
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_ADD_SEALS), uintptr(seals))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("seal memfd: %w", errno)
	}

	// Load via /proc/self/fd path
	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	p, err := plugin.Open(path)

	// Close our fd — dlopen opened its own
	unix.Close(fd)

	if err != nil {
		return nil, fmt.Errorf("plugin.Open: %w", err)
	}
	return p, nil
}
