package ipc

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

const (
	tcpEstablished = 1  // TCP_ESTABLISHED in include/net/tcp_states.h
	soNetnsCookie  = 71 // SO_NETNS_COOKIE (Linux 5.14+), same value on every Go linux arch
)

// ValidateGuestFD verifies that fd is an established IPv4 TCP socket in
// this process's network namespace whose local address is exactly portal,
// and returns both kernel-reported endpoints. Every value comes from the
// kernel (getsockopt/getsockname/getpeername), never from the sender.
//
// The network-namespace check stops a compromised portal from fabricating
// a "guest" connection inside a private user+network namespace where it
// controls both addresses. Kernels without SO_NETNS_COOKIE fail closed.
func ValidateGuestFD(fd int, portal netip.AddrPort) (GuestConn, error) {
	own, err := ownNetnsCookie()
	if err != nil {
		return GuestConn{}, fmt.Errorf("%w: own network namespace: %v", ErrDescriptor, err)
	}
	return validateGuestFD(fd, portal, own)
}

func validateGuestFD(fd int, portal netip.AddrPort, wantNetns uint64) (GuestConn, error) {
	fail := func(format string, args ...any) (GuestConn, error) {
		return GuestConn{}, fmt.Errorf("%w: %s", ErrDescriptor, fmt.Sprintf(format, args...))
	}
	if fd < 0 {
		return fail("invalid descriptor")
	}
	if !portal.IsValid() || !portal.Addr().Is4() || portal.Port() == 0 {
		return fail("invalid portal address")
	}
	for _, check := range []struct {
		name      string
		opt, want int
	}{
		{"address family", syscall.SO_DOMAIN, syscall.AF_INET},
		{"socket type", syscall.SO_TYPE, syscall.SOCK_STREAM},
		{"protocol", syscall.SO_PROTOCOL, syscall.IPPROTO_TCP},
	} {
		v, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, check.opt)
		if err != nil {
			return fail("%s: %v", check.name, err)
		}
		if v != check.want {
			return fail("%s %d is not %d", check.name, v, check.want)
		}
	}
	cookie, err := netnsCookie(fd)
	if err != nil {
		return fail("network namespace: %v", err)
	}
	if cookie != wantNetns {
		return fail("socket belongs to a different network namespace")
	}
	lsa, err := syscall.Getsockname(fd)
	if err != nil {
		return fail("getsockname: %v", err)
	}
	local, ok := inet4(lsa)
	if !ok || local != portal {
		return fail("local address is not the portal listener")
	}
	rsa, err := syscall.Getpeername(fd)
	if err != nil {
		return fail("getpeername: %v", err)
	}
	remote, ok := inet4(rsa)
	if !ok {
		return fail("peer is not IPv4")
	}
	if err := checkPeerAddr(remote, portal); err != nil {
		return GuestConn{}, err
	}
	state, err := tcpState(fd)
	if err != nil {
		return fail("TCP_INFO: %v", err)
	}
	if state != tcpEstablished {
		return fail("TCP state %d is not ESTABLISHED", state)
	}
	return GuestConn{Local: local, Remote: remote}, nil
}

// checkPeerAddr rejects peers that cannot be a guest. Loopback peers are
// accepted only when the portal itself is loopback (unit tests); otherwise
// a loopback peer or the portal's own address is a local process.
func checkPeerAddr(remote, portal netip.AddrPort) error {
	a := remote.Addr()
	switch {
	case !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || remote.Port() == 0:
		return fmt.Errorf("%w: peer address is not a unicast IPv4 endpoint", ErrDescriptor)
	case a.IsLoopback() && !portal.Addr().IsLoopback():
		return fmt.Errorf("%w: loopback peer on a non-loopback portal", ErrDescriptor)
	case !portal.Addr().IsLoopback() && a == portal.Addr():
		return fmt.Errorf("%w: connection from the gateway's own address", ErrDescriptor)
	}
	return nil
}

func inet4(sa syscall.Sockaddr) (netip.AddrPort, bool) {
	in, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(netip.AddrFrom4(in.Addr), uint16(in.Port)), true
}

func tcpState(fd int) (uint8, error) {
	var info syscall.TCPInfo
	l := uint32(syscall.SizeofTCPInfo)
	if err := getsockopt(fd, syscall.IPPROTO_TCP, syscall.TCP_INFO, unsafe.Pointer(&info), &l); err != nil {
		return 0, err
	}
	if l < 1 {
		return 0, syscall.EINVAL
	}
	return info.State, nil
}

func netnsCookie(fd int) (uint64, error) {
	var cookie uint64
	l := uint32(unsafe.Sizeof(cookie))
	if err := getsockopt(fd, syscall.SOL_SOCKET, soNetnsCookie, unsafe.Pointer(&cookie), &l); err != nil {
		return 0, err
	}
	if l != uint32(unsafe.Sizeof(cookie)) {
		return 0, syscall.EINVAL
	}
	return cookie, nil
}

func ownNetnsCookie() (uint64, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	return netnsCookie(fd)
}
