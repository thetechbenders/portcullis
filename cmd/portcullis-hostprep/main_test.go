package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thetechbenders/portcullis/internal/hostpolicy"
)

func privateInput(t *testing.T, id hostpolicy.Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identities.json")
	b, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testIDs() hostpolicy.Identity {
	return hostpolicy.Identity{
		GuestMAC:      "02:00:00:00:00:11",
		UplinkMAC:     "02:00:00:00:00:22",
		ManagementMAC: "02:00:00:00:00:33",
	}
}

func TestPreparePrivateOfflineArtifacts(t *testing.T) {
	out := filepath.Join(t.TempDir(), "new-private-output")
	if err := prepare(privateInput(t, testIDs()), out); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("unsafe output directory: %+v %v", info, err)
	}
	for _, name := range []string{
		"20-portcullis-ethernet-ownership.conf",
		"uplink-netplan-fragment.yaml",
		"nftables-service-override.candidate",
	} {
		fi, err := os.Stat(filepath.Join(out, name))
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("unsafe artifact permissions %s: %+v %v", name, fi, err)
		}
	}
	nm, err := os.ReadFile(filepath.Join(out, "20-portcullis-ethernet-ownership.conf"))
	if err != nil || !strings.Contains(string(nm), "type:ethernet;except:mac:02:00:00:00:00:22") {
		t.Fatalf("incorrect NM exclusion: %v", err)
	}
	if err := prepare(privateInput(t, testIDs()), out); err == nil {
		t.Fatal("overwrote existing output directory")
	}
}

func TestPrepareRejectsUnsafeInputs(t *testing.T) {
	ids := testIDs()
	ids.GuestMAC = ids.UplinkMAC
	if err := prepare(privateInput(t, ids), filepath.Join(t.TempDir(), "bad")); err == nil {
		t.Fatal("accepted duplicate physical identity")
	}
	path := privateInput(t, testIDs())
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := prepare(path, filepath.Join(t.TempDir(), "bad-perms")); err == nil {
		t.Fatal("accepted world-readable private identifiers")
	}
	if err := prepare(privateInput(t, testIDs()), "relative"); err == nil {
		t.Fatal("accepted nonabsolute output")
	}
}
