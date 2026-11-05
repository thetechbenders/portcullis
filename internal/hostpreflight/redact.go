package hostpreflight

// RedactSnapshot produces a copy for sharing. The unredacted observation is
// always used for evaluation, so redaction cannot cause missing hazards.
func RedactSnapshot(s Snapshot) Snapshot {
	s.Hostname = ""
	s.BootID = ""
	s.Interfaces = append([]Interface(nil), s.Interfaces...)
	for i := range s.Interfaces {
		s.Interfaces[i].MAC = ""
		s.Interfaces[i].SysfsPath = ""
		s.Interfaces[i].Addresses = nil
	}
	s.Routes = append([]Route(nil), s.Routes...)
	for i := range s.Routes {
		s.Routes[i].Destination = ""
	}
	s.DefaultRoutes = append([]Route(nil), s.DefaultRoutes...)
	for i := range s.DefaultRoutes {
		s.DefaultRoutes[i].Destination = ""
	}
	return s
}
