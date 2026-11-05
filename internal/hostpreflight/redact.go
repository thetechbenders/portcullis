package hostpreflight

import (
 "crypto/sha256"
 "fmt"
 "regexp"
)

var macInterfaceName = regexp.MustCompile("(?i)^enx[0-9a-f]{12}$")

func redactInterfaceName(name string) string {
 if macInterfaceName.MatchString(name) {
  sum := sha256.Sum256([]byte(name))
  return fmt.Sprintf("enx-redacted-%x", sum[:4])
 }
 return name
}

// RedactSnapshot produces a copy for sharing. The unredacted observation is
// always used for evaluation, so redaction cannot cause missing hazards.
func RedactSnapshot(s Snapshot) Snapshot {
	s.Hostname = ""
	s.BootID = ""
	s.Interfaces = append([]Interface(nil), s.Interfaces...)
	for i := range s.Interfaces {
		s.Interfaces[i].Name = redactInterfaceName(s.Interfaces[i].Name)
		s.Interfaces[i].Master = redactInterfaceName(s.Interfaces[i].Master)
		for j := range s.Interfaces[i].Uppers { s.Interfaces[i].Uppers[j] = redactInterfaceName(s.Interfaces[i].Uppers[j]) }
		s.Interfaces[i].MAC = ""
		s.Interfaces[i].SysfsPath = ""
		s.Interfaces[i].Addresses = nil
	}
	s.Routes = append([]Route(nil), s.Routes...)
	for i := range s.Routes {
		s.Routes[i].Destination = ""
		s.Routes[i].Interface = redactInterfaceName(s.Routes[i].Interface)
	}
	s.DefaultRoutes = append([]Route(nil), s.DefaultRoutes...)
	for i := range s.DefaultRoutes {
		s.DefaultRoutes[i].Destination = ""
		s.DefaultRoutes[i].Interface = redactInterfaceName(s.DefaultRoutes[i].Interface)
	}
	return s
}

func RedactReport(r Report) Report {
 r.BootID = ""
 r.Selection.Guest = redactInterfaceName(r.Selection.Guest)
 r.Selection.Uplink = redactInterfaceName(r.Selection.Uplink)
 r.Selection.Management = redactInterfaceName(r.Selection.Management)
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
