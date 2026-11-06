// Package owneraudit interprets strictly scoped, read-only NetworkManager
// observations. It neither configures devices nor grants activation authority.
package owneraudit

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
)

var ErrObservation = errors.New("untrusted or incomplete NetworkManager device observation")

// NMDevice is the limited, non-secret subset of nmcli device show that the
// audit needs. A missing or unexpected value must never mean unmanaged.
type NMDevice struct {
	Managed     bool
	Autoconnect bool
	Connected   bool
}

// ParseNMDevice parses only these explicitly requested nmcli fields:
// GENERAL.NM-MANAGED, GENERAL.AUTOCONNECT, GENERAL.CONNECTION.
// Connection names are never returned or logged, even in diagnostic errors.
func ParseNMDevice(data []byte) (NMDevice, error) {
	if len(data) == 0 || len(data) > 4096 {
		return NMDevice{}, fmt.Errorf("%w: bounded output missing or too large", ErrObservation)
	}
	const managed, auto, connection = "GENERAL.NM-MANAGED", "GENERAL.AUTOCONNECT", "GENERAL.CONNECTION"
	values := make(map[string]string, 3)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != managed && key != auto && key != connection) {
			return NMDevice{}, fmt.Errorf("%w: unexpected device field", ErrObservation)
		}
		if _, exists := values[key]; exists {
			return NMDevice{}, fmt.Errorf("%w: duplicate device field", ErrObservation)
		}
		values[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return NMDevice{}, fmt.Errorf("%w: invalid device output", ErrObservation)
	}
	if len(values) != 3 {
		return NMDevice{}, fmt.Errorf("%w: missing device fields", ErrObservation)
	}
	if (values[managed] != "yes" && values[managed] != "no") ||
		(values[auto] != "yes" && values[auto] != "no") {
		return NMDevice{}, fmt.Errorf("%w: unknown managed or autoconnect state", ErrObservation)
	}
	if values[connection] == "" {
		return NMDevice{}, fmt.Errorf("%w: connection state missing", ErrObservation)
	}
	return NMDevice{
		Managed:     values[managed] == "yes",
		Autoconnect: values[auto] == "yes",
		Connected:   values[connection] != "--",
	}, nil
}

// Finding contains deliberately no raw interface names, paths, addresses,
// profile identifiers, MACs or connection names.
type Finding struct {
	Code string `json:"code"`
}

// Report is a diagnostic, not a deployment permission or safety certificate.
type Report struct {
	Hazards     []Finding `json:"hazards"`
	NotAssessed []string  `json:"not_assessed"`
}

func Evaluate(guest NMDevice, observed bool, preflightHazard bool) Report {
	r := Report{
		Hazards: []Finding{},
		NotAssessed: []string{
			"root-visible NetworkManager profile files and effective unmanaged-device rules",
			"other manager ownership (systemd-networkd, dhcpcd, ifupdown and similar)",
			"independent default-DOWN enforcement before any device UP or packet exposure",
			"udev and NetworkManager race conditions, including missed identity match",
			"permanent physical MAC and immutable device-parent identity",
			"local-console recovery and independently supervised physical acceptance",
		},
	}
	add := func(code string) { r.Hazards = append(r.Hazards, Finding{Code: code}) }
	if !observed {
		add("networkmanager_observation_unavailable")
	} else {
		if guest.Managed {
			add("guest_networkmanager_managed")
		}
		if guest.Autoconnect {
			add("guest_networkmanager_autoconnect")
		}
		if guest.Connected {
			add("guest_networkmanager_connection_active")
		}
	}
	if preflightHazard {
		add("host_preflight_hazard")
	}
	return r
}
