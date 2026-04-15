//go:build linux

package loader

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// platformPrepareExec writes decrypted executable bytes to a sealed memfd
// and returns the /proc/self/fd/<fd> path for use with exec.Command.
//
// The memfd is created once and reused across multiple Run()/Command() calls.
// The plaintext never touches a real filesystem.
//
// The cleanup function closes the fd. After a subprocess has been started
// via exec.Command, the kernel holds its own reference to the memfd inode,
// so closing the parent's fd is safe.
func platformPrepareExec(data []byte) (execPath string, cleanup func(), err error) {
	fd, err := unix.MemfdCreate("ironclad-exec", unix.MFD_CLOEXEC)
	if err != nil {
		return "", nil, fmt.Errorf("memfd_create: %w", err)
	}

	written := 0
	for written < len(data) {
		n, err := unix.Write(fd, data[written:])
		if err != nil {
			unix.Close(fd)
			return "", nil, fmt.Errorf("write to memfd: %w", err)
		}
		written += n
	}

	// Seal the memfd to prevent modification after writing.
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_ADD_SEALS), uintptr(seals))
	if errno != 0 {
		unix.Close(fd)
		return "", nil, fmt.Errorf("seal memfd: %w", errno)
	}

	execPath = fmt.Sprintf("/proc/self/fd/%d", fd)
	cleanup = func() { unix.Close(fd) }

	return execPath, cleanup, nil
}
