package model

import (
	"errors"
	"testing"
)

func TestParseMAC(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"02:00:00:00:00:0A", "02:00:00:00:00:0a"},
		{"02-00-5e-10-00-01", "02:00:5e:10:00:01"},
		{"0200.5e10.0001", "02:00:5e:10:00:01"},
	} {
		m, err := ParseMAC(tc.in)
		if err != nil || m.String() != tc.want {
			t.Errorf("%q: got %v %v", tc.in, m, err)
		}
	}
}

func TestParseMACRejectsUnsafe(t *testing.T) {
	for _, in := range []string{
		"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01",
		"02:00:00:00:00", "02:00:00:00:00:00:00:01", "zz:00:00:00:00:01",
		"02:00:00:00:00:01;flush ruleset",
	} {
		if _, err := ParseMAC(in); !errors.Is(err, ErrMAC) {
			t.Errorf("%q accepted: %v", in, err)
		}
	}
	if _, err := MACFromBytes([]byte{2, 0, 0, 0, 1}); !errors.Is(err, ErrMAC) {
		t.Fatal("short MAC accepted")
	}
}

func TestMACHintHidesPrefix(t *testing.T) {
	m, err := ParseMAC("02:aa:bb:cc:00:0a")
	if err != nil {
		t.Fatal(err)
	}
	if m.Hint() != "…:00:0a" {
		t.Fatalf("hint %q", m.Hint())
	}
}
