# Raspberry Pi 5 native ARM64 bring-up

2026-11-05: **native build and unprivileged unit testing work**. No application
porting changes were needed. Race testing is blocked by the installed Go race
runtime's address-space requirements. This is not gateway deployment acceptance.

## Revision and workspace

- Branch: `feat/pi5-arm64-bringup`.
- Tested application revision: `ebe1aa5ddb75c778b445b9bfd44384d2f0576b10`.
- SSH: `ssh -o BatchMode=yes -o ForwardAgent=no portcullis-pi`, user `heph`
  (UID 1001), hostname `portcullis`. The exact prefix works unattended following
  the operator's SSH repair. No authentication configuration was changed by this work.
- Remote workspace: `/home/heph/portcullis/pi5-ebe1aa5-u7TahHNZ` (called `$work`
  below). An exact `git archive HEAD` was transferred and checksum-verified;
  no Git credentials, private keys or agent forwarding were used on the Pi.
- Layout: `src/`, `tools/go/`, `bin/`, `cache/`, `tmp/`, `logs/`.
  Go build/module caches, GOPATH, Python bytecode and test scratch files stay here.
  `GOENV=off`, `GOTOOLCHAIN=local`, `GOPROXY=off` and `GOSUMDB=off` avoid implicit
  user configuration changes, toolchain switching and module downloads.
- The follow-up commit adds instructions, this report and the check runner;
  it does not change the tested application code. Source is an archive, not a
  remote Git checkout; later edits must be transferred explicitly.

## Verified platform

| Item | Pi observation |
| --- | --- |
| Hardware | Raspberry Pi 5 Model B Rev 1.1; 4 CPUs; about 16 GB RAM |
| OS | Debian GNU/Linux 13.7 (trixie), 64-bit userspace |
| Kernel | `6.18.50+rpt-rpi-2712`, `aarch64`; 16,384-byte pages |
| Storage | NVMe root filesystem; about 893 GiB available during checks |
| Go | Initially absent; workspace-local `go1.26.10 linux/arm64` installed |
| Compiler | GCC 14.2.0; `CGO_ENABLED=1`; native host and target both `linux/arm64` |
| Python / Git | Python 3.13.5; Git 2.47.3 |
| Network tools | nftables 1.1.3; iproute2 6.15.0; ping; busybox with `udhcpc`; setpriv; curl |
| Missing dependency | `conntrack` package and binary absent; no installation attempted |
| Interfaces | `eth0`, `wlan0`, `lo`; no guest/uplink assignment or interface changes |

The Go archive came from [official Go downloads](https://go.dev/dl/), using
the ARM64 checksum in the [release metadata](https://go.dev/dl/?mode=json).
Go 1.26.10 matches the toolchain recorded in the integration handoff.
No system packages, shell profiles or services were installed or changed.
`nft` is present at `/usr/sbin/nft` but is outside the initial SSH login PATH;
the privileged command layer uses configured absolute paths.

## Native checks

The final runner reproduced the initial bring-up results, with separate
per-invocation logs. The extracted source tree was also verified byte-for-byte
against the transferred archive, with no additional source files.
Counts include subtests and fuzz seed cases; tagged checks overlap ordinary checks.

| Check | Result |
| --- | --- |
| `go build -o "$work/bin/" ./cmd/...` | PASS: all six commands |
| Tagged `tests/netns/policy` build | PASS: seventh binary, compiled only |
| `go test -count=1 -timeout=5m -json ./...` | PASS: 295 checks, 13 tested packages; no test failures or skips |
| `go test -tags netnslab -count=1 -timeout=5m -json ./...` | PASS: 297 checks, 13 tested packages; no test failures or skips |
| `go test -race -count=1 -timeout=5m -json ./...` | BLOCKED: all 13 test binaries fail before tests run |
| `go vet ./...`; `go vet -tags netnslab ./...` | PASS |
| `gofmt -l .` | PASS: no output |
| Python relay unit tests | PASS: 3 tests; namespace entry mocked |
| Bash/sh and Python syntax checks | PASS: both namespace suites, demo, DHCP hook and Python fixtures |
| `file "$work"/bin/*` | All seven binaries are ARM aarch64 ELF64 executables |

Go JSON reports five ordinary/six tagged packages as `skip` because those
packages have **no test files**. No individual unit test was skipped. Builds use
CGO and produce dynamically linked binaries requiring the ARM64 system loader;
these are not portable static release artifacts.

Race stderr: `FATAL: ThreadSanitizer: unsupported VMA range` and
`FATAL: Found 47 - Supported 48`. The installed
[Go 1.26.10 source](https://github.com/golang/go/blob/go1.26.10/src/internal/platform/supported.go)
documents the ARM64 race detector's 48-bit VMA requirement. This is a race-runtime
startup limitation, not a reported application data race. No kernel/boot or
address-space workaround was attempted. Race acceptance remains outstanding.

## Privileged work deliberately not executed

`tests/netns/run.sh`, `tests/netns/e2e.sh` and `demo/portcullis-lab.sh` require
root and manipulate namespaces, links, routes, nftables and namespace sysctls.
The E2E suite additionally requires a disposable GitHub-hosted runner; its
environment checks were not bypassed. Only syntax checks and the inert tagged
policy build/unit tests ran. No real `portcullisd`, portal, DHCP server, operator
dashboard or firewall guard was started, and no generated policy was applied.

The repository's ordinary Go tests use fake nft/ip/conntrack executables,
fixture data, temporary files and local sockets. These tests exercise IPC socket
passing and credential validation on ARM64 without starting a gateway. They do
not verify packet filtering, real DHCP delivery or network isolation.

## Differences from the disposable VM demo

| Existing VM/CI assumptions | Physical Pi consequence |
| --- | --- |
| Runbook targets Ubuntu 24.04+, Go 1.26+, Python 3.12+ and root | Pi is Debian 13 ARM64 with Python 3.13; Go is local to the workspace and this work stays unprivileged |
| Namespace-created `guest0`/`uplink0`, veth, bridge and dummy links | Pi has real Ethernet/Wi-Fi; no physical topology, station binding or isolation has been accepted |
| Disposable kernel with required nft/conntrack/IPv6 behavior | Pi has nft 1.1.3, lacks conntrack, and privileged kernel compatibility remains untested; existing fixture captures include nft 1.0.9 |
| Race checks run in the disposable CI test job | This Pi's Go race runtime rejects the observed VMA layout before tests |
| Root-owned `/run` state, low HTTP/DNS/DHCP ports, namespace browser relay | No `/run` state or low-port services were created; shell approval does not authorize service activation |
| No NAT, HTTPS, reboot persistence or production access-layer guarantees | Those gaps remain on physical hardware; native compilation does not close them |

## Reproduction, evidence and next steps

Run the reviewed [check runner](../scripts/pi5-checks.sh) on the Pi after placing
source in `$work/src` and the verified toolchain in `$work/tools/go`:

```sh
bash "$work/run-checks-final.sh" "$work"
```

`run-checks-final.sh` is byte-identical to the committed runner. It creates a fresh
`logs/checks-TIMESTAMP-RANDOM/` directory, continues independent checks after a
failure, and returns nonzero if any check fails (currently the race check).
It rebuilds `bin/`; it does not install software or execute the namespace labs.

Original logs: `$work/logs/`. Final-run logs:
`$work/logs/checks-20261105T161142Z-ssyfcXEj/`; `verified-summary.json` records
the complete-log audit and source comparison. A preserved snapshot of all runs,
inventory, script versions and release metadata is in
`$work/evidence-final-20261105.tar.gz`. An earlier snapshot is in
`$work/evidence-20261105.tar.gz`, with a checksum-matched copy on Hephaestus at
`/tmp/portcullis-pi5-20261105-evidence.tar.gz` (temporary local storage).

SHA-256 provenance:

```text
source.tar                 f40f17a3cf3813ec0aaa77201b40be35947c77aacb5b8839dca40d7897d21a86
go1.26.10.linux-arm64.tar.gz 3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797
run-checks-final.sh         0a9f22304bafbe2a28a6b87f302c289a07c03fbb2a1314c18da9c51978a2090a
evidence-20261105.tar.gz    378da4d078c06dcc09cf8c0428ac93890609d559ea8dc3c1970331b57fcfed7b
evidence-final-20261105.tar.gz 6c855080d3e66ce096b00541d82af29f3855c48ab3d86f80315f41fe799a69f2
```

Next steps:

1. Retain race coverage on a supported CI runner; investigate future upstream
   Go race-runtime support for this Pi layout without changing this host's boot configuration.
2. Keep privileged packet/E2E validation on disposable runners under the existing
   runbooks. A separate approved hardware-validation plan is needed for Pi kernel
   behavior, conntrack installation and independent recovery/isolation evidence.
3. Before physical guest access, explicitly review NIC/AP roles, station binding,
   IPv6 behavior, guard compatibility and confirmed failsafe isolation. Do not
   activate the VM launcher against physical interfaces as a deployment shortcut.
