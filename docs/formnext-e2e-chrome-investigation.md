# PR #20: headless Chrome startup deadline

Investigated 2026-11-05. Scope: disposable CI browser acceptance only.

## Evidence

- [Failed run 42120366114](https://github.com/thetechbenders/portcullis/actions/runs/42120366114)
  passed DHCP, controller and unprivileged portal readiness, both guest session
  checks, and the host-loopback portal relay HTTP check before launching Chrome.
  It failed approximately 30 seconds later, at the browser's wall-clock deadline.
  The old error handler discarded Chrome/timeout's exit code and DOM output.
- Chrome executes in the host namespace with `--no-proxy-server` and an explicit
  `portal.localhost` to `127.0.0.1` mapping. The relay preserves HTTP authority
  and creates its upstream socket inside guest A's namespace. That socket still
  traverses the bound-guest guard; Chrome does not get a direct gateway shortcut.
- [Diagnostic run 42122091272](https://github.com/thetechbenders/portcullis/actions/runs/42122091272)
  used Chrome 156.0.8078.79 on the same Ubuntu runner image. A normal-environment
  `about:blank` invocation returned 0 in 7.05 seconds despite the same D-Bus error
  messages. A subsequent invocation with both D-Bus addresses pointing to
  `/dev/null` returned 0 in 0.71 seconds. Invocation order and cache warming
  confound that timing comparison; it does not establish a D-Bus root cause.
  The unchanged e2e suite and demo lifecycle then passed, as did Go/race checks
  and the separate namespace suite. The temporary diagnostic step was removed.

The evidence points to a browser startup/deadline flake, rather than a reproducible
networking regression. D-Bus error messages alone are not evidence of fatal browser
failure. The exact source of the original runner's startup latency is unconfirmed;
the original log did not record the process status. No speculative D-Bus or browser
security settings were changed.

## Fix

Allow 90 seconds of wall time, including cold Chrome startup, while retaining the
existing 5-second virtual page-execution budget. Add a 5-second forced-termination
backstop, and always print Chrome's exit status and elapsed wall time. Nonzero
status, missing denied-state rendering, or failure to execute JavaScript still
fails the suite. All guard, HTTP authority, identity, positive delivery, directional
drop-counter, expiry, revoke, and topology assertions remain in place.

## Validation and limits

Local Go 1.26.10: unit tests, build, both vet modes, tagged enforcement tests,
gofmt, Python relay tests, and shell/Python syntax checks passed. Initially, local
race testing lacked a C compiler and was performed in CI; the subsequent local
race run is recorded below. The local host is `hephaestus`;
the lab's protected-host refusal was preserved. Local browser-only `about:blank`
checks succeeded but did not reproduce the CI failure. Browser runtime libraries
were extracted under `/tmp` for these unprivileged checks; no system packages or
services were installed. No physical Pi or live network changes were performed.

[Fix validation run 42122649241](https://github.com/thetechbenders/portcullis/actions/runs/42122649241)
passed all three jobs at code commit `c473812fe18701624d472b0dac1321fd1415cf18`
(tested merge `0e20bf3`). With the warm-up probes removed, Chrome returned 0 in
1 second, then the real-browser rendering/JavaScript assertions, full kernel e2e
suite, and demo lifecycle passed. This confirms the final browser path works;
it does not deterministically reproduce or explain the earlier 30-second stall.

## Follow-up with the system toolchain

On the same date, `go test -race -count=1 ./...` passed locally at `36ac248`
using system Go 1.26.8, GCC 15.2.0, and `CGO_ENABLED=1`. There were no race reports.
The log is `/tmp/portcullis-pr20-local-validation/race-go1.26.8.log` on Hephaestus.

[Final documented-head CI run 42123106150](https://github.com/thetechbenders/portcullis/actions/runs/42123106150)
passed all jobs at `36ac248096c9a67f61375b6bb427e15792010ee4` (tested merge
`410a224`). Chrome returned 0 after **28 seconds**, followed by successful browser,
kernel e2e, and demo lifecycle checks. The 1-second versus 28-second successful
renders on fresh runners support retaining startup headroom, but do not identify
the cause of the latency variation.

Six further unprivileged, fresh-profile local `about:blank` controls alternated
normal D-Bus selection and explicit unavailable D-Bus addresses, with both orders
represented. All rendered successfully in 0.427-0.464 seconds and all emitted
D-Bus errors. These used existing Chrome for Testing 156.0.8078.4, rather than
CI's Chrome 156.0.8078.79, and exercised no guest networking. They reproduce the
nonfatal log messages, not the original startup stall, and give no local evidence
that changing D-Bus settings would fix the CI latency. Logs and timings are under
`/tmp/portcullis-pr20-local-validation/`. No network-lab restrictions, guard rules,
or browser settings in the harness were changed during this follow-up.
