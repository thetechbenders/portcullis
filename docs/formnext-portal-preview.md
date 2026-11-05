# Formnext portal preview

This is a **visual preview only**, not a captive portal. It cannot create leases, authorize clients, change nftables rules, or bind to non-loopback interfaces.

```sh
go run ./cmd/portcullis-demo
# Open http://127.0.0.1:8787/
```

The status endpoint `GET /api/status` deliberately reports `authorization: denied` and `mode: preview`. All mutation methods are disabled. The HTML contains a disabled access button, not a simulated grant.

Before turning this into a real guest-facing portal, implement authenticated, independently observed client binding, narrowly authorized privileged IPC, live guard validation, DHCP/DNS captive-portal discovery, and an isolated demo network. Never interpret this preview as network access.
