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
		"add table inet portcullis_guard",
		"delete table inet portcullis_guard",
		"table inet portcullis_guard",
		"type filter hook input priority -50; policy accept;",
		"type filter hook forward priority -50; policy accept;",
		"iifname \"opg.3030\" counter drop",
		"oifname \"opg.3030\" counter drop",
	}
	for _, want := range checks {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %q from rules:\n%s", want, rules)
		}
	}
	if strings.Count(rules, "counter drop") != 3 {
		t.Fatalf("expected exactly 3 deny counters: %s", rules)
	}
	if strings.Contains(rules, "ct state established accept") || strings.Contains(rules, "flags owner") {
		t.Fatal("baseline must not permit established connections or be owner-scoped")
	}
	if strings.Index(rules, "add table") > strings.Index(rules, "delete table") {
		t.Fatal("must establish table before delete for first-time installation")
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

func TestRenderReconcileDeny(t *testing.T) {
	rules, err := RenderReconcileDeny("guest0")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"flush chain inet portcullis_guard guest_input",
		"flush chain inet portcullis_guard guest_forward",
		"add rule inet portcullis_guard guest_input iifname \"guest0\" counter drop",
		"add rule inet portcullis_guard guest_forward iifname \"guest0\" counter drop",
		"add rule inet portcullis_guard guest_forward oifname \"guest0\" counter drop",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(rules, "delete table") || strings.Contains(rules, "add table") ||
		strings.Contains(rules, "type filter hook") {
		t.Fatal("reconciliation must never replace hooked base chains")
	}
	if _, err := RenderReconcileDeny("bad;command"); !errors.Is(err, ErrGuestInterface) {
		t.Fatalf("invalid interface: %v", err)
	}
}
