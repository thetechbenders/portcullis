package ipc

import (
	"syscall"
	"unsafe"
)

// getsockopt is unavailable as a direct syscall on linux/386 (socketcall
// multiplexing); guest descriptor validation fails closed there.
func getsockopt(fd, level, opt int, val unsafe.Pointer, vallen *uint32) error {
	return syscall.ENOSYS
}
