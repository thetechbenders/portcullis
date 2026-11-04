//go:build linux && !386

package ipc

import (
	"syscall"
	"unsafe"
)

// getsockopt is the raw getsockopt(2) the syscall package does not export
// for struct-valued options (TCP_INFO, SO_NETNS_COOKIE).
func getsockopt(fd, level, opt int, val unsafe.Pointer, vallen *uint32) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
