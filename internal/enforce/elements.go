package enforce

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

// ErrGuardElement rejects an element batch input (address, MAC or TTL).
var ErrGuardElement = errors.New("invalid portcullis guard set element")

// Element batches only ever add, delete or flush set elements of the guard
// table; they never mention tables, chains or rules, so they cannot clear a
// dormant flag or replace hooked base chains. Each batch is ONE nft -f
// transaction. Deleting an absent element fails the whole batch, so removal
// uses the idempotent "add timeout 1s; delete" idiom (verified on nft 1.0.9).
type elementBatch struct{ strings.Builder }

func (b *elementBatch) add(set, key string, secs int64) {
	fmt.Fprintf(b, "add element inet %s %s { %s timeout %ds }\n", GuardTable, set, key, secs)
}

func (b *elementBatch) remove(set, key string) {
	b.add(set, key, 1)
	fmt.Fprintf(b, "delete element inet %s %s { %s }\n", GuardTable, set, key)
}

func (b *elementBatch) refresh(set, key string, secs int64) {
	b.remove(set, key)
	b.add(set, key, secs)
}

func elementAddr(c GuardConfig, ip netip.Addr) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if !validGuestAddr(c, ip) {
		return "", fmt.Errorf("%w: address must be unicast IPv4 and not the gateway", ErrGuardElement)
	}
	return ip.String(), nil
}

func elementPair(c GuardConfig, ip netip.Addr, mac model.MAC) (string, error) {
	addr, err := elementAddr(c, ip)
	if err != nil {
		return "", err
	}
	if _, err := model.MACFromBytes(mac[:]); err != nil {
		return "", fmt.Errorf("%w: %w", ErrGuardElement, err)
	}
	return addr + " . " + mac.String(), nil
}

// timeoutSeconds floors ttl to whole seconds within [1s, limit].
func timeoutSeconds(ttl, limit time.Duration) (int64, error) {
	secs := int64(ttl / time.Second)
	if secs < 1 || secs > int64(limit/time.Second) {
		return 0, fmt.Errorf("%w: timeout must be 1s..%s", ErrGuardElement, limit)
	}
	return secs, nil
}

// RenderBind refreshes the bound_v4 element admitting ip . mac to the
// portal and DNS for ttl (at most MaxBindTimeout).
func RenderBind(c GuardConfig, ip netip.Addr, mac model.MAC, ttl time.Duration) (string, error) {
	key, err := elementPair(c, ip, mac)
	if err != nil {
		return "", err
	}
	secs, err := timeoutSeconds(ttl, MaxBindTimeout)
	if err != nil {
		return "", err
	}
	var b elementBatch
	b.refresh(SetBound, key, secs)
	return b.String(), nil
}

// RenderUnbind idempotently removes the bound_v4 element for ip . mac.
func RenderUnbind(c GuardConfig, ip netip.Addr, mac model.MAC) (string, error) {
	key, err := elementPair(c, ip, mac)
	if err != nil {
		return "", err
	}
	var b elementBatch
	b.remove(SetBound, key)
	return b.String(), nil
}

// RenderGrant sets granted_v4 {ip . mac} and granted_dst_v4 {ip} to the same
// timeout (at most MaxGrantTimeout) in one transaction.
func RenderGrant(c GuardConfig, ip netip.Addr, mac model.MAC, ttl time.Duration) (string, error) {
	key, err := elementPair(c, ip, mac)
	if err != nil {
		return "", err
	}
	secs, err := timeoutSeconds(ttl, MaxGrantTimeout)
	if err != nil {
		return "", err
	}
	var b elementBatch
	b.refresh(SetGranted, key, secs)
	b.refresh(SetGrantedDst, ip.String(), secs)
	return b.String(), nil
}

// RenderRevoke idempotently removes both grant elements in one transaction.
func RenderRevoke(c GuardConfig, ip netip.Addr, mac model.MAC) (string, error) {
	key, err := elementPair(c, ip, mac)
	if err != nil {
		return "", err
	}
	var b elementBatch
	b.remove(SetGranted, key)
	b.remove(SetGrantedDst, ip.String())
	return b.String(), nil
}

// RenderRevokeDst idempotently removes only granted_dst_v4 {ip}.
func RenderRevokeDst(c GuardConfig, ip netip.Addr) (string, error) {
	addr, err := elementAddr(c, ip)
	if err != nil {
		return "", err
	}
	var b elementBatch
	b.remove(SetGrantedDst, addr)
	return b.String(), nil
}

// RenderFlushGrants removes every forwarding grant without touching chains.
func RenderFlushGrants() string {
	return "flush set inet " + GuardTable + " " + SetGranted + "\n" +
		"flush set inet " + GuardTable + " " + SetGrantedDst + "\n"
}
