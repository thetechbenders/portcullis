//go:build netnslab

package enforce

import (
	"errors"
	"strings"
	"testing"
)

func TestTimedFixturePolicyStartsClosed(t *testing.T) {
	rules, err := RenderTimedFixturePolicy("guest0", "uplink0")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{
		"table inet portcullis_lab",
		"flags timeout",
		"iifname \"guest0\" oifname \"uplink0\" ip saddr @test_allow_v4 counter accept",
		"iifname \"guest0\" counter drop",
		"oifname \"guest0\" ip daddr @test_allow_v4 ct state established,related counter accept",
		"oifname \"guest0\" counter drop",
	} {
		if !strings.Contains(rules, item) {
			t.Errorf("missing %q", item)
		}
	}
	if strings.Contains(rules, "elements =") || strings.Contains(rules, "ct state established accept") {
		t.Fatal("fixture must start with an empty allow set and per-packet checks")
	}
}

func TestTimedFixtureRejectsInterfaces(t *testing.T) {
	for _, tc := range [][2]string{
		{"", "uplink0"}, {"guest0", ""}, {"guest0", "guest0"},
		{"guest0", "wan0;flush"}, {"bad interface", "wan0"},
	} {
		rules, err := RenderTimedFixturePolicy(tc[0], tc[1])
		if !errors.Is(err, ErrGuestInterface) && err == nil || rules != "" {
			t.Fatalf("guest=%q uplink=%q rules=%q err=%v", tc[0], tc[1], rules, err)
		}
	}
}
