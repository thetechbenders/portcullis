# First physical-client smoke probe (read-only, optional)

`go run ./cmd/portcullis-clientcheck -gateway GUEST_GATEWAY_IPV4` runs **from a guest client**, only after the operator has separately approved a fully isolated wired pilot. The Pi's current physical networking is **not** ready for that pilot. No network configuration, DHCP request, firewall rule, grant, interface, service or privileged state is changed by this tool.

The probe checks, in order:

1. Direct UDP DNS A query to the nominated gateway's DNS port (no local hosts-file or system-resolver fallback): portal hostname must return only the expected gateway IPv4 address. Truncated replies fail rather than silently switching to another resolver.
2. HTTP GET `/` to that gateway, using the configured portal `Host`. It requires HTTP 200 with HTML content type.
3. Read-only GET `/api/session`, requiring a successful JSON response from a recognized guest. Reports only the session state, not IP/MAC or tokens.

For a different portal hostname or ports, use `-portal-host`, `-dns-port`, or `-http-port`. A bounded total deadline defaults to five seconds. No system resolver, proxy or redirect is consulted for the portal HTTP check. No grant request or browser automation is performed.

**This is application reachability evidence, not a firewall or physical isolation verdict.** It neither checks DHCP lease ownership, destination reachability, kernel drop counters, forwarding, AP station identity, nor management-network leakage. Those require independent controlled packet probes with positive delivery controls and inspected firewall counters. A passing probe must never trigger guest-link activation. Never run `demo/portcullis-lab.sh` on physical interfaces.

Unit tests use a local HTTP test server and injected DNS answers, without privileged network commands. GitHub-hosted `netns` and `e2e` remain the only automated privileged test environment.
