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
gofmt, Python relay tests, and shell/Python syntax checks passed. Local race tests
require a C compiler and were run in CI instead. The local host is `hephaestus`;
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
