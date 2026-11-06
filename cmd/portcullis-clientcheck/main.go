// Command portcullis-clientcheck checks read-only client-visible DNS and portal
// behavior. It does not request a grant, configure networking or prove isolation.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type options struct {
	gateway  netip.Addr
	host     string
	dnsPort  uint16
	httpPort uint16
	timeout  time.Duration
}

type dnsLookup func(context.Context, string) ([]net.IP, error)

func validate(o options) error {
	if !o.gateway.Is4() || o.gateway.IsUnspecified() || o.gateway.IsMulticast() || o.gateway.String() == "255.255.255.255" {
		return errors.New("gateway must be a unicast IPv4 address")
	}
	if o.host == "" || len(o.host) > 253 || strings.ContainsAny(o.host, ":/\\ \t\r\n") || strings.HasSuffix(o.host, ".") {
		return errors.New("portal host must be an unqualified DNS authority name without port or path")
	}
	for _, part := range strings.Split(o.host, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return errors.New("invalid portal host label")
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("portal host must use ASCII DNS labels")
			}
		}
	}
	if o.dnsPort == 0 || o.httpPort == 0 || o.timeout <= 0 || o.timeout > 30*time.Second {
		return errors.New("invalid port or timeout (maximum 30 seconds)")
	}
	return nil
}

func resolver(o options) dnsLookup {
	server := net.JoinHostPort(o.gateway.String(), strconv.Itoa(int(o.dnsPort)))
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "udp" && network != "udp4" && network != "tcp" && network != "tcp4" {
			return nil, fmt.Errorf("unexpected DNS network %q", network)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server)
	}}
	return func(ctx context.Context, host string) ([]net.IP, error) { return r.LookupIP(ctx, "ip4", host) }
}

func check(ctx context.Context, o options, lookup dnsLookup, client *http.Client, report io.Writer) error {
	if err := validate(o); err != nil {
		return err
	}
	ips, err := lookup(ctx, o.host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("DNS lookup returned no A records")
	}
	for _, ip := range ips {
		if ip.To4() == nil || ip.String() != o.gateway.String() {
			return errors.New("DNS A record did not match expected guest gateway")
		}
	}
	fmt.Fprintln(report, "PASS guest DNS: portal host resolves only to expected gateway")

	base := "http://" + net.JoinHostPort(o.gateway.String(), strconv.Itoa(int(o.httpPort)))
	fetch := func(path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return nil, err
		}
		req.Host = o.host
		return client.Do(req)
	}
	resp, err := fetch("/")
	if err != nil {
		return fmt.Errorf("portal GET failed: %w", err)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("portal body read failed: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("portal body close failed: %w", closeErr)
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return fmt.Errorf("portal GET unexpected HTTP status/content type: %d", resp.StatusCode)
	}
	fmt.Fprintln(report, "PASS portal HTTP: guest page reachable")

	resp, err = fetch("/api/session")
	if err != nil {
		return fmt.Errorf("session GET failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("session GET unexpected HTTP status: %d", resp.StatusCode)
	}
	var session struct {
		OK      bool `json:"ok"`
		Session struct {
			State string `json:"state"`
		} `json:"session"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&session); err != nil {
		return fmt.Errorf("session JSON invalid: %w", err)
	}
	if !session.OK || session.Session.State == "" {
		return errors.New("session response did not confirm a recognized guest")
	}
	fmt.Fprintf(report, "PASS session API: recognized client, state=%s
", session.Session.State)
	fmt.Fprintln(report, "NOTE read-only application reachability only; not evidence of firewall denial or physical isolation")
	return nil
}

func main() {
	gateway := flag.String("gateway", "", "expected guest gateway IPv4 address (required)")
	host := flag.String("portal-host", "portal.portcullis.test", "portal HTTP Host and DNS name")
	dnsPort := flag.Uint("dns-port", 53, "guest DNS UDP/TCP port")
	httpPort := flag.Uint("http-port", 80, "guest portal HTTP port")
	timeout := flag.Duration("timeout", 5*time.Second, "total check deadline (max 30s)")
	flag.Parse()
	if flag.NArg() != 0 || *gateway == "" || *dnsPort == 0 || *dnsPort > 65535 || *httpPort == 0 || *httpPort > 65535 {
		fmt.Fprintln(os.Stderr, "usage: portcullis-clientcheck -gateway IPv4 [-portal-host NAME] [-dns-port N] [-http-port N] [-timeout 5s]")
		os.Exit(2)
	}
	addr, err := netip.ParseAddr(*gateway)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid gateway:", err)
		os.Exit(2)
	}
	o := options{gateway: addr, host: *host, dnsPort: uint16(*dnsPort), httpPort: uint16(*httpPort), timeout: *timeout}
	if err := validate(o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	client := &http.Client{Timeout: o.timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	if err := check(ctx, o, resolver(o), client, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
