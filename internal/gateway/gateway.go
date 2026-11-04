// Package gateway connects the pure guard renderers and attestation in
// internal/enforce to the fixed-path command layer in internal/kernel. It
// implements the controller's Kernel, Flows and Failsafe collaborators and
// the offline bootstrap step. It never shells out and never replaces hooked
// base chains at runtime.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/thetechbenders/portcullis/internal/enforce"
	"github.com/thetechbenders/portcullis/internal/kernel"
	"github.com/thetechbenders/portcullis/internal/model"
)

var (
	// ErrGuestUp refuses a bootstrap while guests could be attached.
	ErrGuestUp = errors.New("refusing bootstrap: guest interface is administratively up")
	// ErrGuardExists refuses a bootstrap that would merge into or replace an
	// existing guard. Live replacement of hooked base chains is never done.
	ErrGuardExists = errors.New("refusing bootstrap: guard table already exists")
)

// Kernel implements controller.Kernel with nft batches rendered from typed,
// validated values.
type Kernel struct {
	Guard    enforce.GuardConfig
	NFT      *kernel.NFT
	Link     *kernel.Link
	Topology kernel.Topology
}

// Snapshot attests the guard table and returns its set elements and counters.
func (k *Kernel) Snapshot(ctx context.Context) (model.KernelState, error) {
	data, err := k.NFT.ListGuard(ctx)
	if err != nil {
		return model.KernelState{}, fmt.Errorf("%w: %v", enforce.ErrGuardAttestation, err)
	}
	return enforce.VerifyGuardJSON(data, k.Guard)
}

// Attest additionally rejects packet paths that bypass the inet forward
// hook and guest interface attachment the guard cannot see.
func (k *Kernel) Attest(ctx context.Context) (model.KernelState, error) {
	state, err := k.Snapshot(ctx)
	if err != nil {
		return model.KernelState{}, err
	}
	ruleset, err := k.NFT.ListRuleset(ctx)
	if err != nil {
		return model.KernelState{}, fmt.Errorf("%w: %v", enforce.ErrGuardAttestation, err)
	}
	if err := enforce.VerifyNoBypass(ruleset, k.Guard); err != nil {
		return model.KernelState{}, err
	}
	if err := k.checkTopology(ctx); err != nil {
		return model.KernelState{}, err
	}
	return state, nil
}

func (k *Kernel) checkTopology(ctx context.Context) error {
	guest, err := k.Link.Inspect(ctx, k.Guard.Guest)
	if err != nil {
		return fmt.Errorf("%w: guest interface: %v", kernel.ErrTopology, err)
	}
	uplink, err := k.Link.Inspect(ctx, k.Guard.Uplink)
	if err != nil {
		return fmt.Errorf("%w: uplink interface: %v", kernel.ErrTopology, err)
	}
	disabled, err := k.Topology.IPv6Disabled(k.Guard.Guest)
	if err != nil {
		return fmt.Errorf("%w: guest IPv6 state: %v", kernel.ErrTopology, err)
	}
	if err := kernel.CheckGuestLink(guest, uplink, disabled); err != nil {
		return err
	}
	return k.Link.CheckNoUpperLinks(ctx, k.Guard.Guest, k.Guard.Uplink)
}

func (k *Kernel) apply(ctx context.Context, batch string, err error) error {
	if err != nil {
		return err
	}
	return k.NFT.Apply(ctx, batch)
}

// Bind refreshes the anti-spoofing element that admits a DHCP-bound client
// to the portal and DNS only.
func (k *Kernel) Bind(ctx context.Context, ip netip.Addr, mac model.MAC, ttl time.Duration) error {
	batch, err := enforce.RenderBind(k.Guard, ip, mac, ttl)
	return k.apply(ctx, batch, err)
}

// Unbind idempotently removes a client's bound element.
func (k *Kernel) Unbind(ctx context.Context, ip netip.Addr, mac model.MAC) error {
	batch, err := enforce.RenderUnbind(k.Guard, ip, mac)
	return k.apply(ctx, batch, err)
}

// Grant atomically installs both timed forwarding elements.
func (k *Kernel) Grant(ctx context.Context, ip netip.Addr, mac model.MAC, ttl time.Duration) error {
	batch, err := enforce.RenderGrant(k.Guard, ip, mac, ttl)
	return k.apply(ctx, batch, err)
}

// Revoke idempotently removes both forwarding elements in one transaction.
func (k *Kernel) Revoke(ctx context.Context, ip netip.Addr, mac model.MAC) error {
	batch, err := enforce.RenderRevoke(k.Guard, ip, mac)
	return k.apply(ctx, batch, err)
}

// RevokeDst removes a stray reply-direction element.
func (k *Kernel) RevokeDst(ctx context.Context, ip netip.Addr) error {
	batch, err := enforce.RenderRevokeDst(k.Guard, ip)
	return k.apply(ctx, batch, err)
}

// FlushGrants removes every forwarding grant without touching chains.
func (k *Kernel) FlushGrants(ctx context.Context) error {
	return k.NFT.Apply(ctx, enforce.RenderFlushGrants())
}

// Bootstrap installs the guard offline: only while the guest interface is
// administratively down and no guard table exists. The rendered batch begins
// with "create table", so the kernel also rejects it if a table appears
// concurrently. The installed guard is attested before success is reported.
func (k *Kernel) Bootstrap(ctx context.Context) error {
	if err := k.Guard.Validate(); err != nil {
		return err
	}
	guest, err := k.Link.Inspect(ctx, k.Guard.Guest)
	if err != nil {
		return fmt.Errorf("%w: guest interface: %v", kernel.ErrTopology, err)
	}
	if guest.Up {
		return ErrGuestUp
	}
	switch _, err := k.NFT.ListGuard(ctx); {
	case err == nil:
		return ErrGuardExists
	case !errors.Is(err, kernel.ErrTableAbsent):
		return err
	}
	batch, err := enforce.RenderGuardBootstrap(k.Guard)
	if err != nil {
		return err
	}
	if err := k.NFT.Apply(ctx, batch); err != nil {
		return err
	}
	_, err = k.Attest(ctx)
	return err
}

// Flows deletes conntrack state for a guest address in both directions.
type Flows struct{ Conntrack *kernel.Conntrack }

// Flush implements controller.Flows.
func (f Flows) Flush(ctx context.Context, ip netip.Addr) error {
	return f.Conntrack.FlushAddr(ctx, ip)
}

// LinkFailsafe sets the guest interface administratively down when the guard
// can no longer be attested: without a verified guard, no guest frame may
// reach the gateway at all.
type LinkFailsafe struct {
	Link      *kernel.Link
	Interface string
}

// Engage implements controller.Failsafe.
func (l LinkFailsafe) Engage(ctx context.Context, reason string) error {
	return l.Link.SetDown(ctx, l.Interface)
}
