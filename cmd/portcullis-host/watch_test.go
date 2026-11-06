package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/thetechbenders/portcullis/internal/hostpreflight"
)

func watchSelection() hostpreflight.Selection {
	return hostpreflight.Selection{
		Guest: "usb0", Uplink: "eth0", Management: "wlan0",
		PinnedGuestMAC: "02:22:33:44:55:66", PinnedGuestSysfs: "/sys/devices/pci0000/usb0",
		PinnedUplinkMAC: "dc:a6:32:aa:bb:cc", PinnedUplinkSysfs: "/sys/devices/platform/soc/eth0",
		PinnedManagementMAC: "dc:a6:32:bb:cc:dd", PinnedManagementSysfs: "/sys/devices/platform/soc/wlan0",
	}
}

func TestWatchContinuityAndRedaction(t *testing.T) {
	original := testSnapshot()
	changed := testSnapshot()
	changed.Interfaces[0].Index = 77
	seq := []hostpreflight.Snapshot{original, changed}
	i, pauses := 0, 0
	collect := func() hostpreflight.Snapshot {
		s := seq[i]
		i++
		return s
	}
	var out, diag bytes.Buffer
	if got := watch(watchSelection(), false, 3,
		&out, &diag, collect, func() { pauses++ }); got != 1 {
		t.Fatalf("watch must stop on changed ifindex; status %d diag %q", got, diag.String())
	}
	if i != 2 || pauses != 1 {
		t.Fatalf("expected early stop after 2 samples and one pause: %d %d", i, pauses)
	}
	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte{10})
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON line records, got %d", len(lines))
	}
	var result struct {
		Sample int                  `json:"sample"`
		Report hostpreflight.Report `json:"report"`
	}
	if err := json.Unmarshal(lines[1], &result); err != nil {
		t.Fatal(err)
	}
	if result.Sample != 2 {
		t.Fatalf("wrong sample: %d", result.Sample)
	}
	found := false
	for _, h := range result.Report.Hazards {
		if h.Code == "interface_index_changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing ifindex change: %s", lines[1])
	}
	if strings.Contains(out.String(), "02:22:33:44:55:66") || strings.Contains(out.String(), "/sys/devices/pci0000") {
		t.Fatalf("private identity leaked: %s", out.String())
	}
}

func TestWatchStableAndOutputFailure(t *testing.T) {
	var out, diag bytes.Buffer
	var calls int
	status := watch(watchSelection(), false, 3,
		&out, &diag, func() hostpreflight.Snapshot { calls++; return testSnapshot() }, func() {})
	if status != 0 || calls != 3 {
		t.Fatalf("stable watch failed: %d calls=%d diag=%s", status, calls, diag.String())
	}
	if bytes.Count(out.Bytes(), []byte{10}) != 3 {
		t.Fatalf("expected 3 records, got %s", out.String())
	}
	if status := watch(watchSelection(), false, 2, io.Discard, &diag,
		func() hostpreflight.Snapshot {
			s := testSnapshot()
			s.Interfaces[0].Up = true
			return s
		}, func() {}); status != 1 {
		t.Fatalf("first-sample exposure must fail: %d", status)
	}
	if status := watch(watchSelection(), false, 2, failingWriter{}, &diag,
		testSnapshot, func() {}); status != 3 {
		t.Fatalf("watch output failure must be fatal: %d", status)
	}
}

func TestWatchArgumentRejectionBeforeCollection(t *testing.T) {
	for _, args := range [][]string{
		{"watch"}, {"watch", "-plan", "fake", "-samples", "0"},
		{"watch", "-plan", "fake", "-interval", "1ms"},
		{"watch", "-plan", "fake", "-samples", "121"},
		{"watch", "-plan", "fake", "extra"},
	} {
		var out, diag bytes.Buffer
		status := run(args, &out, &diag, func() hostpreflight.Snapshot {
			t.Fatal("invalid watch flags should not collect host data")
			return hostpreflight.Snapshot{}
		})
		if status != 2 {
			t.Fatalf("%v returned %d: %s", args, status, diag.String())
		}
	}
}
