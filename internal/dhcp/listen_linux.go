//go:build linux

package dhcp

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// ListenInterface opens the DHCP server socket on udp4 0.0.0.0:port bound to
// ifname with SO_BINDTODEVICE.
//
// This is the one wildcard-address listener in Portcullis: a DHCPDISCOVER is
// sent from 0.0.0.0 to 255.255.255.255, so no unicast bind address could
// receive it. SO_BINDTODEVICE confines the socket to the guest interface:
// the kernel delivers only datagrams that arrived on that device, and
// broadcast replies leave through it. SO_BROADCAST permits the replies.
//
// SO_REUSEADDR is deliberately NOT set. UDP has no TIME_WAIT, so a restart
// rebinds without it, and setting it would let another local process that
// also sets it share port 67 on the guest device (in the lab the netns-local
// unprivileged port floor is lowered for the portal) and receive copies of
// guest DHCP traffic. Without it a second bind fails closed with EADDRINUSE.
func ListenInterface(ifname string, port int) (net.PacketConn, error) {
	if !safeInterface.MatchString(ifname) {
		return nil, invalid("interface name must be 1-15 safe ASCII bytes")
	}
	if port < 1 || port > 65535 {
		return nil, invalid("port must be between 1 and 65535")
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); serr != nil {
				return
			}
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifname)
		}); err != nil {
			return err
		}
		return serr
	}}
	conn, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("dhcp: listen on %s: %w", ifname, err)
	}
	return conn, nil
}
