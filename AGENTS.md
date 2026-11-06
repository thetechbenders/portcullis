# Portcullis development and safety conventions

These project-specific conventions supplement the operator's existing Sara
instructions; they do not replace them.

- Inspect the current branch, worktree and relevant documentation before edits.
  Preserve existing work and back up existing configuration before changing it.
  Never reset, merge, publish, push or deploy beyond the authorized scope.
- Read `README.md`, `docs/formnext-integration.md`, `docs/formnext-demo.md` and
  `tests/netns/README.md` before gateway or lab work. Historical handoffs describe
  earlier states; verify claims against the current source and fresh results.
- Linux and Go 1.26+ are required. The module currently uses the standard library
  only. Build commands with `go build -o BINDIR/ ./cmd/...`; compilation does not
  authorize running the resulting daemon.
- Safe unprivileged checks: `go test -count=1 ./...`, `go test -race -count=1 ./...`
  (requires a C compiler), `go vet ./...`, `go vet -tags netnslab ./...`,
  `go test -tags netnslab -count=1 ./...`, formatting, script syntax, and
  `python3 -m unittest discover -s demo -p 'test_*.py' -v`.
  Go tests use fake privileged executables, temporary files and local sockets.
  Python relay unit tests mock namespace entry. Audit new tests before assuming
  they have the same properties.
- `tests/netns/run.sh`, `tests/netns/e2e.sh` and `demo/portcullis-lab.sh` perform
  privileged networking work. Do not run or source them on Hephaestus or the Pi
  during unprivileged bring-up. Syntax checks are safe. Never spoof CI variables
  or weaken host/root checks to bypass their disposable-runner restrictions.
- Pi bring-up uses the exact SSH prefix
  `ssh -o BatchMode=yes -o ForwardAgent=no portcullis-pi` so the persistent
  approval rule matches. It authenticates as unprivileged user `heph`. Do not
  add IdentityAgent, reorder arguments or substitute another hostname. Keep
  private keys and passphrases on Hephaestus; use its configured authentication.
- All remote writes, toolchains, caches, temporary files, source and logs must
  remain in a unique directory beneath `/home/heph/portcullis`. Do not change
  shell startup files or install system packages for this workflow.
  `scripts/pi5-checks.sh WORKSPACE` reproduces the safe native check batch with
  `WORKSPACE/src` and `WORKSPACE/tools/go` already populated.
- No sudo, capability grants or privilege escalation. No host networking,
  firewall, DNS, route, SSH, NetworkManager, boot or service changes. Never start
  the actual gateway, bootstrap guard or apply generated nft text during bring-up.
  Document elevated prerequisites and continue independent safe checks.
- Keep a concise record of source revision, archive/toolchain hashes, commands,
  dependency versions, results and gaps in `docs/pi5-arm64-bringup.md`. Distinguish
  native compilation/unit acceptance from packet enforcement, real DHCP,
  physical topology and browser acceptance. Never infer hardware safety from CI.
- Keep secrets out of logs and commits. Ask before consequential installations,
  system/security changes or enabling services; finish an approved batch without
  repeated permission requests. Report verified milestones precisely.
