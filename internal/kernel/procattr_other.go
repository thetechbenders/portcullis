//go:build unix && !linux

package kernel

import "syscall"

// sysProcAttr puts each command in its own process group so a timeout can
// kill anything it forked.
func sysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }
