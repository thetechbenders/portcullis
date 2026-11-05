package hostpreflight

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

var macInterfaceName = regexp.MustCompile(`(?i)^(?:en|wl|ww)x[0-9a-f]{12}$`)

// A report-local mapping preserves joins without making hardware identifiers reversible.
type interfaceRedactor struct {
	names map[string]string
}

func (r *interfaceRedactor) name(name string) string {
	if !macInterfaceName.MatchString(name) {
		return name
	}
	if r.names == nil {
		r.names = make(map[string]string)
	}
	key := strings.ToLower(name)
	if alias, ok := r.names[key]; ok {
		return alias
	}
	alias := fmt.Sprintf("mac-interface-%d", len(r.names)+1)
	r.names[key] = alias
	return alias
}

func (r *interfaceRedactor) diagnostic(detail string) string {
	// Diagnostic errors may include paths containing MAC-derived interface names.
	// Suppress the detail entirely: arbitrary paths can reveal more than MACs.
	if detail == "" {
		return ""
	}
	return "Inventory observation failed; inspect private local diagnostics"
}

// RedactSnapshot produces a copy for sharing. The unredacted observation is
// always used for evaluation, so redaction cannot cause missing hazards.
func RedactSnapshot(s Snapshot) Snapshot {
	redactor := &interfaceRedactor{}
	s.Hostname = ""
	s.BootID = ""
	s.Interfaces = append([]Interface(nil), s.Interfaces...)
	for i := range s.Interfaces {
		s.Interfaces[i].Uppers = append([]string(nil), s.Interfaces[i].Uppers...)
		s.Interfaces[i].Name = redactor.name(s.Interfaces[i].Name)
		s.Interfaces[i].Master = redactor.name(s.Interfaces[i].Master)
		for j := range s.Interfaces[i].Uppers {
			s.Interfaces[i].Uppers[j] = redactor.name(s.Interfaces[i].Uppers[j])
		}
		s.Interfaces[i].MAC = ""
		s.Interfaces[i].SysfsPath = ""
		s.Interfaces[i].Addresses = nil
	}
	s.InventoryError = append([]string(nil), s.InventoryError...)
	for i := range s.InventoryError {
		s.InventoryError[i] = redactor.diagnostic(s.InventoryError[i])
	}
	s.Routes = append([]Route(nil), s.Routes...)
	for i := range s.Routes {
		s.Routes[i].Destination = ""
		s.Routes[i].Interface = redactor.name(s.Routes[i].Interface)
	}
	s.DefaultRoutes = append([]Route(nil), s.DefaultRoutes...)
	for i := range s.DefaultRoutes {
		s.DefaultRoutes[i].Destination = ""
		s.DefaultRoutes[i].Interface = redactor.name(s.DefaultRoutes[i].Interface)
	}
	return s
}

func RedactReport(r Report) Report {
	redactor := &interfaceRedactor{}
	if r.BootID != "" {
		// Stable within a boot for comparing reports; deliberately pseudonymous.
		digest := sha256.Sum256([]byte(r.BootID))
		r.BootID = fmt.Sprintf("sha256:%x", digest[:12])
	}
	r.Selection.Guest = redactor.name(r.Selection.Guest)
	r.Selection.Uplink = redactor.name(r.Selection.Uplink)
	r.Selection.Management = redactor.name(r.Selection.Management)
	r.Selection.PinnedGuestMAC, r.Selection.PinnedGuestSysfs = "", ""
	r.Selection.PinnedUplinkMAC, r.Selection.PinnedUplinkSysfs = "", ""
	r.Selection.PinnedManagementMAC, r.Selection.PinnedManagementSysfs = "", ""
	r.Hazards = append([]Finding(nil), r.Hazards...)
	// Avoid copying sensitive paths, IPs or hardware-encoded interface names
	// from diagnostic strings into a report intended for sharing.
	for i := range r.Hazards {
		r.Hazards[i].Detail = "Observed condition requires private local inspection; see finding code"
	}
	return r
}
