package kernel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

// Conntrack deletes connection-tracking state for a guest address.
type Conntrack struct{ x *Exec }

// NewConntrack wraps an Exec validated for the configured conntrack path.
func NewConntrack(x *Exec) *Conntrack { return &Conntrack{x: x} }

// conntrack-tools 1.4.8 exits 1 when a delete matched nothing. Only this
// exact single-line message counts as success; anything else is an error.
var nothingDeleted = regexp.MustCompile(`^conntrack v[0-9][0-9A-Za-z.+~-]* \(conntrack-tools\): 0 flow entries have been deleted\.$`)

// FlushAddr deletes IPv4 conntrack entries whose original source or
// original destination is ip. Both deletions are always attempted and their
// errors joined. The guard does not depend on this for enforcement (it has
// no blanket established accept), but flushing ends tracked state promptly.
func (c *Conntrack) FlushAddr(ctx context.Context, ip netip.Addr) error {
	if !ip.Is4() || ip.IsUnspecified() {
		return fmt.Errorf("%w: conntrack flush requires a specific IPv4 address", ErrArgument)
	}
	var x *Exec
	if c != nil {
		x = c.x
	}
	var errs []error
	for _, dir := range []string{"-s", "-d"} {
		if _, err := x.Run(ctx, nil, "-D", "-f", "ipv4", dir, ip.String()); err != nil && !emptyDelete(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func emptyDelete(err error) bool {
	code, stderr, ok := exitStderr(err)
	return ok && code == 1 && nothingDeleted.Match(bytes.TrimSpace(stderr))
}
