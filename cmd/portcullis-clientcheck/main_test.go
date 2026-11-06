package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testOptions(port uint16) options {
	return options{gateway: netip.MustParseAddr("127.0.0.1"), host: "portal.portcullis.test", dnsPort: 53, httpPort: port, timeout: time.Second}
}

func TestClientCheck(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dns     string
		session string
		status  int
		wantErr string
	}{
		{name: "recognized denied client", dns: "127.0.0.1", session: `{"ok":true,"session":{"state":"denied"}}`},
		{name: "recognized granted client", dns: "127.0.0.1", session: `{"ok":true,"session":{"state":"granted"}}`},
		{name: "wrong dns", dns: "127.0.0.2", wantErr: "DNS A record"},
		{name: "unrecognized client", dns: "127.0.0.1", session: `{"ok":false}`, wantErr: "recognized guest"},
		{name: "bad session body", dns: "127.0.0.1", session: `not json`, wantErr: "session JSON invalid"},
		{name: "session error", dns: "127.0.0.1", status: 403, wantErr: "session GET unexpected HTTP status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "portal.portcullis.test" {
					t.Errorf("unexpected HTTP host %q", r.Host)
				}
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					fmt.Fprint(w, "<h1>Portal</h1>")
				case "/api/session":
					w.Header().Set("Content-Type", "application/json")
					if tc.status != 0 {
						w.WriteHeader(tc.status)
					}
					fmt.Fprint(w, tc.session)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			_, p, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			n, _ := strconv.Atoi(p)
			o := testOptions(uint16(n))
			var output bytes.Buffer
			err := check(context.Background(), o, func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP(tc.dns)}, nil }, server.Client(), &output)
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("got %v want %s", err, tc.wantErr)
			}
			if tc.wantErr == "" && !strings.Contains(output.String(), "PASS session API") {
				t.Fatalf("missing passing session evidence: %s", output.String())
			}
		})
	}
}

func TestValidation(t *testing.T) {
	o := testOptions(80)
	if err := validate(o); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*options)
	}{
		{"missing gateway", func(p *options) { p.gateway = netip.Addr{} }},
		{"ipv6 gateway", func(p *options) { p.gateway = netip.MustParseAddr("::1") }},
		{"empty host", func(p *options) { p.host = "" }},
		{"invalid host", func(p *options) { p.host = "x/a" }},
		{"host port", func(p *options) { p.host = "portal.test:80" }},
		{"bad dns port", func(p *options) { p.dnsPort = 0 }},
		{"bad http port", func(p *options) { p.httpPort = 0 }},
		{"bad timeout", func(p *options) { p.timeout = 31 * time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := o
			tc.change(&p)
			if validate(p) == nil {
				t.Fatalf("accepted %+v", p)
			}
		})
	}
}

func TestDNSFailureDoesNotFallThroughToHTTP(t *testing.T) {
	var output bytes.Buffer
	err := check(context.Background(), testOptions(80), func(context.Context, string) ([]net.IP, error) { return nil, errors.New("unreachable") }, http.DefaultClient, &output)
	if err == nil || !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(output.String(), "PASS") {
		t.Fatalf("false success: %s", output.String())
	}
}

func TestDirectGatewayDNSQuery(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	responseDone := make(chan error, 1)
	go func() {
		packet := make([]byte, 512)
		n, address, err := server.ReadFrom(packet)
		if err != nil {
			responseDone <- err
			return
		}
		if n < 18 {
			responseDone <- errors.New("short DNS question")
			return
		}
		// Answer the exact incoming question. No system DNS or hosts file is used.
		header := []byte{packet[0], packet[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
		answer := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1}
		reply := append(append(header, packet[12:n]...), answer...)
		_, err = server.WriteTo(reply, address)
		responseDone <- err
	}()
	port := server.LocalAddr().(*net.UDPAddr).Port
	o := testOptions(80)
	o.dnsPort = uint16(port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := resolver(o)(ctx, o.host)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatalf("wrong answers: %v", ips)
	}
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
}
