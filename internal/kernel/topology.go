package kernel

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrTopology reports a guest attachment the guard cannot see or police:
// an enslaved or bridging guest interface (frames would arrive with another
// iifname and fall through the guard's policy accept), XDP programs that act
// before netfilter, or IPv6 enabled on the guest interface.
var ErrTopology = errors.New("guest topology attestation failed")

// Topology reads interface sysctls from a /proc tree. The tree is the
// caller's network namespace, because /proc/sys/net is per-netns.
type Topology struct {
	ProcRoot string // default "/proc"
}

// IPv6Disabled reports whether IPv6 is disabled on ifname. A kernel or netns
// with no IPv6 stack at all (no <ProcRoot>/sys/net/ipv6) counts as disabled,
// but only after <ProcRoot>/sys/net/ipv4/conf/<ifname> proves that the /proc
// tree is live and the interface exists: an unmounted /proc must not look
// like "no IPv6".
func (t Topology) IPv6Disabled(ifname string) (bool, error) {
	if err := checkIfname(ifname); err != nil {
		return false, err
	}
	if ifname == "all" || ifname == "default" {
		return false, fmt.Errorf("%w: %q names a global sysctl, not an interface", ErrArgument, ifname)
	}
	root := t.ProcRoot
	if root == "" {
		root = "/proc"
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false, fmt.Errorf("%w: proc root must be a clean absolute path", ErrArgument)
	}
	net := filepath.Join(root, "sys", "net")
	if fi, err := os.Stat(filepath.Join(net, "ipv4", "conf", ifname)); err != nil || !fi.IsDir() {
		return false, fmt.Errorf("interface %q not present in %s/ipv4/conf: %v", ifname, net, err)
	}
	switch fi, err := os.Stat(filepath.Join(net, "ipv6")); {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, err
	case !fi.IsDir():
		return false, fmt.Errorf("%s/ipv6 is not a directory", net)
	}
	path := filepath.Join(net, "ipv6", "conf", ifname, "disable_ipv6")
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16))
	if err != nil {
		return false, err
	}
	switch strings.TrimSuffix(string(data), "\n") {
	case "1":
		return true, nil
	case "0":
		return false, nil
	}
	return false, fmt.Errorf("%s: unexpected value %q", path, data)
}

// CheckGuestLink fails unless the guest interface is a plain, unenslaved,
// non-bridging link without XDP, the uplink has no XDP and is a different
// interface, and guest IPv6 is disabled. All problems are reported together.
func CheckGuestLink(guest, uplink LinkInfo, ipv6Disabled bool) error {
	var p []string
	if guest.Name == "" || uplink.Name == "" {
		p = append(p, "interface name missing")
	}
	if guest.Name == uplink.Name {
		p = append(p, "guest and uplink are the same interface")
	}
	if guest.Master != "" {
		p = append(p, fmt.Sprintf("guest interface is enslaved to %q", guest.Master))
	}
	if guest.SlaveKind != "" {
		p = append(p, fmt.Sprintf("guest interface is a %q port", guest.SlaveKind))
	}
	switch strings.ToLower(guest.Kind) {
	case "bridge", "bond", "team":
		p = append(p, fmt.Sprintf("guest interface is a %q device", guest.Kind))
	}
	if guest.XDP {
		p = append(p, "guest interface has an XDP program")
	}
	if uplink.XDP {
		p = append(p, "uplink interface has an XDP program")
	}
	if !ipv6Disabled {
		p = append(p, "IPv6 is enabled on the guest interface")
	}
	if len(p) > 0 {
		return fmt.Errorf("%w: %s", ErrTopology, strings.Join(p, "; "))
	}
	return nil
}
