package enforce

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderDenyBaseline(t *testing.T) {
	rules, err := RenderDenyBaseline("opg.3030")
	if err != nil {
		t.Fatal(err)
	}
	checks := []string{
		"table inet portcullis_guard",
		"type filter hook input priority -50; policy accept;",
		"type filter hook forward priority -50; policy accept;",
		"iifname \"opg.3030\" counter drop",
	}
	for _, want := range checks {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %q from rules:\n%s", want, rules)
		}
	}
	if strings.Count(rules, "counter drop") != 2 {
		t.Fatalf("expected exactly 2 guest drops: %s", rules)
	}
	if strings.Contains(rules, "ct state established accept") || strings.Contains(rules, "flags owner") {
		t.Fatal("baseline must not accept established connections or be owner-scoped")
	}
}

func TestRenderRejectsUntrustedInterfaceNames(t *testing.T) {
	for _, name := range []string{
		"", "this-interface-is-too-long", "eth0; flush ruleset", "lo\naccept",
		"eth 0", "-eth", ".eth", "eth/0", "éthernet",
	} {
		rules, err := RenderDenyBaseline(name)
		if !errors.Is(err, ErrGuestInterface) || rules != "" {
			t.Errorf("name %q: rules=%q err=%v", name, rules, err)
		}
	}
}

func TestRenderAllowsConventionalNames(t *testing.T) {
	for _, name := range []string{"vlan3030", "enp1s0.3030", "veth_guest", "a", "abcdefghijklmn0"} {
		if _, err := RenderDenyBaseline(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}
