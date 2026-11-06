package owneraudit

import (
	"errors"
	"strings"
	"testing"
)

const normal = "GENERAL.NM-MANAGED:no\nGENERAL.AUTOCONNECT:no\nGENERAL.CONNECTION:--\n"

func TestParseNMDevice(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		wantErr   bool
		want      NMDevice
	}{
		{"unmanaged", normal, false, NMDevice{}},
		{"manager owns", "GENERAL.NM-MANAGED:yes\nGENERAL.AUTOCONNECT:yes\nGENERAL.CONNECTION:Wired connection 1\n", false, NMDevice{true, true, true}},
		{"colon in private profile", "GENERAL.NM-MANAGED:yes\nGENERAL.AUTOCONNECT:no\nGENERAL.CONNECTION:private:secret\n", false, NMDevice{Managed: true, Connected: true}},
		{"missing field", "GENERAL.NM-MANAGED:no\nGENERAL.AUTOCONNECT:no\n", true, NMDevice{}},
		{"unknown state", strings.Replace(normal, "NM-MANAGED:no", "NM-MANAGED:unknown", 1), true, NMDevice{}},
		{"autoconnect ambiguous", strings.Replace(normal, "AUTOCONNECT:no", "AUTOCONNECT:unknown", 1), true, NMDevice{}},
		{"duplicate", normal + "GENERAL.NM-MANAGED:no\n", true, NMDevice{}},
		{"unexpected field", normal + "IP4.ADDRESS:secret\n", true, NMDevice{}},
		{"trailing garbage", normal + "corrupt\n", true, NMDevice{}},
		{"empty", "", true, NMDevice{}},
		{"oversized", strings.Repeat("X", 4097), true, NMDevice{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseNMDevice([]byte(tc.raw))
			if tc.wantErr {
				if !errors.Is(err, ErrObservation) {
					t.Fatalf("expected redacted observation failure, got %+v %v", got, err)
				}
				if strings.Contains(err.Error(), "secret") {
					t.Fatalf("sensitive data leaked: %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %+v err=%v, want %+v", got, err, tc.want)
			}
		})
	}
}

func TestEvaluateIsAlwaysNonAuthorizing(t *testing.T) {
	for _, tc := range []struct {
		name                string
		observed, preflight bool
		nm                  NMDevice
		wantCode            string
	}{
		{"safe observation still incomplete", true, false, NMDevice{}, ""},
		{"missing nmcli", false, false, NMDevice{}, "networkmanager_observation_unavailable"},
		{"managed", true, false, NMDevice{Managed: true}, "guest_networkmanager_managed"},
		{"autoconnect", true, false, NMDevice{Autoconnect: true}, "guest_networkmanager_autoconnect"},
		{"active profile", true, false, NMDevice{Connected: true}, "guest_networkmanager_connection_active"},
		{"host exposure", true, true, NMDevice{}, "host_preflight_hazard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(tc.nm, tc.observed, tc.preflight)
			if len(got.NotAssessed) == 0 {
				t.Fatal("unassessed privileged conditions disappeared")
			}
			if tc.wantCode == "" {
				if len(got.Hazards) != 0 {
					t.Fatalf("unexpected hazards: %+v", got.Hazards)
				}
				return
			}
			for _, h := range got.Hazards {
				if h.Code == tc.wantCode {
					return
				}
			}
			t.Fatalf("missing %q in %+v", tc.wantCode, got.Hazards)
		})
	}
}
