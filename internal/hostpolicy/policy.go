// Package hostpolicy renders inert candidate host configuration for independent
// review. It never writes to /etc, invokes systemd, or configures a NIC.
package hostpolicy

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var ErrUnsafePlan = errors.New("unsafe host ownership plan")

// Identity contains private physical identities. Do not include it in reports,
// fixtures built from hardware, logs or Git commits.
type Identity struct {
	GuestMAC      string
	UplinkMAC     string
	ManagementMAC string
}

// normalizedMAC accepts only six-octet, unicast, nonzero Ethernet addresses.
func normalizedMAC(input string) (string, error) {
	addr, err := net.ParseMAC(input)
	if err != nil || len(addr) != 6 || addr[0]&1 != 0 || strings.EqualFold(addr.String(), "00:00:00:00:00:00") {
		return "", ErrUnsafePlan
	}
	return strings.ToLower(addr.String()), nil
}

func validate(i Identity) (string, string, error) {
	g, err := normalizedMAC(i.GuestMAC)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid guest identity", ErrUnsafePlan)
	}
	u, err := normalizedMAC(i.UplinkMAC)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid uplink identity", ErrUnsafePlan)
	}
	m, err := normalizedMAC(i.ManagementMAC)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid management identity", ErrUnsafePlan)
	}
	if g == u || g == m || u == m {
		return "", "", fmt.Errorf("%w: role identities overlap", ErrUnsafePlan)
	}
	return g, u, nil
}

// RenderGuestExclusion proposes strict NetworkManager exclusion scoped to the
// permanent guest MAC. A generated type:ethernet managed=1 rule and an existing
// broad wired autoconnect profile must still be tested against this directive.
// An exclusion match failure must not enable physical link exposure.
func RenderGuestExclusion(i Identity) (string, error) {
	g, _, err := validate(i)
	if err != nil {
		return "", err
	}
	return "[keyfile]\nunmanaged-devices=mac:" + g + "\n", nil
}

// RenderUplinkNetplanDefinition is a narrow replacement for the *Ethernet*
// portion of the existing persistent Netplan source, NOT a complete YAML file.
// It must be merged by a separately authorized transaction which preserves the
// Wi-Fi stanza, renderer and any required policy passthrough.
func RenderUplinkNetplanDefinition(i Identity) (string, error) {
	_, u, err := validate(i)
	if err != nil {
		return "", err
	}
	return "ethernets:\n  eth0:\n    match:\n      macaddress: " + u + "\n    dhcp4: true\n    dhcp6: true\n", nil
}

// RenderNftablesServiceOverride neutralizes the stock nftables.service
// lifecycle, whose ExecStart and ExecStop flush the entire ruleset on this host.
// Only use when the full nftables ruleset has an independently reviewed owner.
// It must NEVER be applied before that owner, rollback and recovery exist.
// This is NOT a substitute for installing or attesting the Portcullis guard.
func RenderNftablesServiceOverride() string {
	return "[Service]\nExecStart=\nExecStart=/usr/bin/true\nExecReload=\nExecStop=\n"
}

// EvaluateProvisioning rejects attempts to construe generated configuration as
// admission authority. Both independent evidence gates are mandatory.
func EvaluateProvisioning(recoveryTested, earlyAdmissionTested, guestCableDisconnected bool) error {
	if !guestCableDisconnected || !recoveryTested || !earlyAdmissionTested {
		return fmt.Errorf("%w: physical recovery, independently tested early admission and disconnected guest cable required", ErrUnsafePlan)
	}
	return nil
}
