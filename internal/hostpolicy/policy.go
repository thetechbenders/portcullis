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

// RenderGuestExclusion uses a negative allowlist: strictly exclude ALL
// Ethernet devices from NetworkManager except the attested onboard uplink.
// This also excludes a re-enumerated guest with a new MAC/name rather than
// failing open when a narrow guest-specific selector misses. The management
// Wi-Fi device is not matched by type:ethernet. The except clause does NOT
// override other reasons an uplink might already be unmanaged.
//
// This prevents automatic NetworkManager adoption; it does NOT enforce
// IFF_DOWN, block another network manager, or establish pre-packet isolation.
func RenderGuestExclusion(i Identity) (string, error) {
	_, uplink, err := validate(i)
	if err != nil {
		return "", err
	}
	return "[keyfile]\nunmanaged-devices=type:ethernet;except:mac:" + uplink + "\n", nil
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

// USBBootEvidence describes independently verified host properties. USB
// authorization is global to the USB subsystem and therefore must not be
// proposed when the root filesystem, management, or independently tested
// recovery depends on USB. These booleans are evidence inputs, not attestations
// performed by this package.
type USBBootEvidence struct {
	RootFilesystemNonUSB     bool
	ManagementPathNonUSB     bool
	RecoveryPathNonUSB       bool
	KernelParameterSupported bool
}

// RenderUSBDefaultDenyKernelArg proposes kernel USB authorization lockdown.
// usbcore.authorized_default=0 is applied before USB drivers bind, so a newly
// enumerated USB Ethernet device cannot form a network interface until an
// explicit device authorization. This affects ALL external and internal USB
// devices other than root hubs, not just the Portcullis guest adapter.
//
// This is a boot-argument fragment, NOT a boot configuration file and NOT an
// installer. The trusted authorizer that later permits one USB device must
// still require separately attested firewall and admission state.
func RenderUSBDefaultDenyKernelArg(e USBBootEvidence) (string, error) {
	if !e.RootFilesystemNonUSB || !e.ManagementPathNonUSB || !e.RecoveryPathNonUSB || !e.KernelParameterSupported {
		return "", fmt.Errorf("%w: kernel USB default-deny requires non-USB storage, management, recovery and kernel support", ErrUnsafePlan)
	}
	return "usbcore.authorized_default=0", nil
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
