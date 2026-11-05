//go:build linux

package kernel

import "syscall"

// sysProcAttr puts each command in its own process group, so a timeout can
// kill anything it forked, and asks the kernel to SIGKILL the child if the
// thread that started it dies.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
