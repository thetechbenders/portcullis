#!/usr/bin/env bash
# Native, unprivileged checks only. Never starts a gateway or namespace lab.
set -euo pipefail
work=$(realpath "${1:?usage: bash scripts/pi5-checks.sh WORKSPACE}")
[[ $work == /home/heph/portcullis/* && -d $work/src && -x $work/tools/go/bin/go ]] || {
  echo 'expected an isolated Pi workspace with src and tools/go' >&2; exit 1;
}
[[ $(id -u) != 0 && $(uname -m) == aarch64 ]] || {
  echo 'requires an unprivileged native ARM64 host' >&2; exit 1;
}
umask 077
mkdir -p "$work"/{bin,cache/go-build,cache/mod,cache/gopath,tmp,logs}
logs=$(mktemp -d "$work/logs/checks-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
printf 'logs: %s\n' "$logs"
export PATH="$work/tools/go/bin:$PATH"
export GOCACHE="$work/cache/go-build" GOMODCACHE="$work/cache/mod"
export GOPATH="$work/cache/gopath" GOENV=off GOTOOLCHAIN=local
export GOPROXY=off GOSUMDB=off TMPDIR="$work/tmp"
export PYTHONPYCACHEPREFIX="$work/cache/pycache"
unset GOOS GOARCH GOARM GOARM64 GOFLAGS GOROOT
cd "$work/src"
go version > "$logs/toolchain.txt"
go env GOHOSTOS GOHOSTARCH GOOS GOARCH CGO_ENABLED CC >> "$logs/toolchain.txt"
[[ $(go env GOHOSTARCH) == arm64 && $(go env GOARCH) == arm64 ]] || exit 1
# Each check has its own log; an unavailable race prerequisite must not hide
# independent unit, vet, Python or syntax results.
: > "$logs/results.tsv"
failed=0
check() {
  local name=$1 rc=0
  shift
  "$@" > "$logs/$name.log" 2>&1 || rc=$?
  printf '%s\t%s\n' "$name" "$rc" | tee -a "$logs/results.tsv"
  if (( rc != 0 )); then failed=1; fi
}
check build go build -o "$work/bin/" ./cmd/...
check build-lab go build -tags netnslab -o "$work/bin/portcullis-lab-policy" ./tests/netns/policy
check unit go test -count=1 -timeout=5m -json ./...
check race go test -race -count=1 -timeout=5m -json ./...
check unit-lab go test -tags netnslab -count=1 -timeout=5m -json ./...
check vet go vet ./...
check vet-lab go vet -tags netnslab ./...
check format bash -ec 'files=$(gofmt -l .); printf "%s" "$files"; test -z "$files"'
check python-unit python3 -m unittest discover -s demo -p 'test_*.py' -v
check bash-syntax bash -n tests/netns/run.sh
check e2e-syntax bash -n tests/netns/e2e.sh
check demo-syntax bash -n demo/portcullis-lab.sh
check dhcp-hook-syntax sh -n tests/netns/udhcpc.script
check python-syntax python3 -m py_compile tests/netns/*.py demo/nsproxy.py
check binaries file "$work"/bin/*
exit "$failed"
