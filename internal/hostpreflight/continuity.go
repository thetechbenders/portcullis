package hostpreflight

import "fmt"

// ContinuityFindings compares two non-atomic passive observations.
// It reports changes rather than enforcing any interface state: a polling
// observer cannot prevent packets during a hotplug, boot or manager race.
func ContinuityFindings(first, current Snapshot) []Finding {
	findings := []Finding{}
	add := func(code, detail string) {
		findings = append(findings, Finding{Code: code, Severity: "hazard", Detail: detail})
	}
	if first.BootID == "" || current.BootID == "" || first.BootID != current.BootID {
		add("boot_identity_changed", "boot ID missing or changed between observations")
	}
	if first.OS != current.OS || first.Arch != current.Arch {
		add("host_identity_changed", "host OS or architecture changed between observations")
	}
	before := make(map[string]Interface, len(first.Interfaces))
	for _, nic := range first.Interfaces {
		if nic.Name == "" || nic.Index <= 0 {
			add("baseline_identity_incomplete", "interface has missing name or index in first observation")
		}
		if _, exists := before[nic.Name]; exists {
			add("baseline_identity_incomplete", "duplicate interface name in first observation")
		}
		before[nic.Name] = nic
	}
	seen := make(map[string]bool, len(current.Interfaces))
	for _, nic := range current.Interfaces {
		if nic.Name == "" || nic.Index <= 0 || seen[nic.Name] {
			add("interface_identity_incomplete", "current interface has invalid or duplicate identity")
		}
		seen[nic.Name] = true
		old, ok := before[nic.Name]
		if !ok {
			add("interface_added", fmt.Sprintf("interface %q appeared since first observation", nic.Name))
			continue
		}
		if old.Index != nic.Index {
			add("interface_index_changed", fmt.Sprintf("interface %q changed kernel ifindex", nic.Name))
		}
		if old.MAC != nic.MAC || old.SysfsPath != nic.SysfsPath {
			add("interface_physical_identity_changed", fmt.Sprintf("interface %q changed observed MAC or parent", nic.Name))
		}
	}
	for name := range before {
		if !seen[name] {
			add("interface_removed", fmt.Sprintf("interface %q disappeared since first observation", name))
		}
	}
	return findings
}
