#!/usr/bin/env bash
# Disposable GitHub-hosted runner ONLY. Every link, sysctl and nft mutation
# occurs inside namespaces owned by this invocation. Never run on a workstation.
set -Eeuo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'e2e: requires a disposable GitHub-hosted runner' >&2; exit 1;
}
source "$(dirname "${BASH_SOURCE[0]}")/../../demo/portcullis-lab.sh"
need_root
refuse_protected_host
bindir="$(realpath "${1:?usage: e2e.sh BINDIR}")"
for c in ip nft conntrack busybox setpriv python3 ping curl; do command -v "$c" >/dev/null || die "missing $c"; done
[[ -d /proc/sys/net/ipv6 ]] || die 'IPv6 required; refusing to skip'
state="$(mktemp -d /run/portcullis-e2e.XXXXXX)"
chmod 755 "$state"
prefix="pce$$"
ns_gw=$prefix-gw ns_ap=$prefix-ap ns_a=$prefix-a ns_b=$prefix-b ns_wan=$prefix-wan ns_lan=$prefix-lan
cleanup() {
  local rc=$? ns pid
  trap - EXIT
  if (( rc != 0 )); then
    echo 'E2E FAILURE: logs and namespace state follow' >&2
    for f in "$state"/*.log; do [[ ! -f $f ]] || { echo "--- $f"; cat "$f"; }; done
    ip netns exec "$ns_gw" nft list ruleset || true
    for ns in "$ns_a" "$ns_b" "$ns_gw" "$ns_wan"; do
      echo "--- namespace $ns"
      ip -n "$ns" -d link show || true
      ip -n "$ns" addr show || true
      ip -n "$ns" -6 route show || true
      ip -n "$ns" -6 neigh show || true
    done
  fi
  # The host-loopback relays are host-namespace Python processes. Kill
  # them explicitly before deleting guest namespaces.
  for name in proxy-portal proxy-demo dashboard; do
    [[ ! -f "$state/$name.pid" ]] || kill "$(cat "$state/$name.pid")" 2>/dev/null || true
  done
  for ns in "$ns_a" "$ns_b" "$ns_ap" "$ns_wan" "$ns_lan" "$ns_gw"; do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  done
  for ns in "$ns_a" "$ns_b" "$ns_ap" "$ns_wan" "$ns_lan" "$ns_gw"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf -- "$state"
  exit "$rc"
}
trap cleanup EXIT
trap 'echo "e2e: failed at line $LINENO: $BASH_COMMAND" >&2' ERR
gw() { ip netns exec "$ns_gw" "$@"; }
a() { ip netns exec "$ns_a" "$@"; }
b() { ip netns exec "$ns_b" "$@"; }
ctl() { gw "$state/bin/portcullisctl" -config "$state/portcullis.json" "$@"; }
attest() { gw "$state/bin/portcullisd" attest -config "$state/portcullis.json"; }
stop_controller() {
  kill -9 "$(cat "$state/portcullisd.pid")"
  wait "$(cat "$state/portcullisd.pid")" 2>/dev/null || true
  rm "$state/portcullisd.pid"
}
api() {
  local ns=$1 path=$2; shift 2
  ip netns exec "$ns" curl --noproxy '*' --fail-with-body --silent --show-error --max-time 8 \
    -H 'Host: portal.portcullis.test' "http://10.203.0.1$path" "$@"
}
session_state() {
  api "$1" /api/session | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["ok"],d; print(d["session"]["state"])'
}
grant() {
  api "$ns_a" /api/access -H 'Origin: http://portal.portcullis.test' -H 'Content-Type: application/json' \
    -H 'X-Portcullis-Request: 1' -d '{"duration_seconds":30}' > "$state/grant.json"
  python3 - "$state/grant.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); s=x['session']
assert x['ok'] and s['state']=='granted' and 0<s['remaining_seconds']<=s['granted_seconds']<=30,x
PY
}
count() {
  gw nft -j list table inet portcullis_guard | python3 -c '
import json,sys
name=sys.argv[1]
r=[o["rule"] for o in json.load(sys.stdin)["nftables"] if "rule" in o and o["rule"].get("comment")==name]
assert len(r)==1,r
print(next(e["counter"]["packets"] for e in r[0]["expr"] if "counter" in e))' "$1"
}
# Only a receiver timeout (exit 1), with a live sender and increased directional
# DROP counter, establishes non-delivery. Setup errors never count as a drop.
probe() {
  local receiver=$1 target=$2 sender=$3 expected=$4 rule=${5:-} before=0 after rc=0
  [[ -z $rule ]] || before=$(count "$rule")
  rm -f "$state/probe.ready"
  ip netns exec "$receiver" python3 "$root/tests/netns/udp_probe.py" listen "$target" --ready "$state/probe.ready" &
  local pid=$!
  wait_file "$state/probe.ready"
  ip netns exec "$sender" python3 "$root/tests/netns/udp_probe.py" send "$target"
  wait "$pid" || rc=$?
  if [[ $expected == allow ]]; then
    (( rc == 0 )) || die "positive packet not delivered: $sender -> $target (rc=$rc)"
  else
    (( rc == 1 )) || die "expected receiver timeout: $sender -> $target (rc=$rc)"
    after=$(count "$rule")
    (( after > before )) || die "no $rule drop observed"
  fi
}
install -d -m 755 "$state/bin" "$state/portal-ready"
chown 65534:65534 "$state/portal-ready"
install -m 755 "$bindir/portcullisd" "$bindir/portcullis-portal" "$bindir/portcullisctl" "$state/bin/"
write_config
build_topology
# SEC-001: the privileged gateway cannot bootstrap or run with isolation
# disabled. This checks real config loading, not only unit-level validation.
python3 - "$state/portcullis.json" "$state/unsafe-no-failsafe.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
cfg["failsafe_link_down"] = False
with open(sys.argv[2], "w") as f:
    json.dump(cfg, f)
PY
if gw "$state/bin/portcullisd" bootstrap -config "$state/unsafe-no-failsafe.json"; then
  die 'disabled failsafe accepted by bootstrap'
fi
if gw "$state/bin/portcullisd" run -config "$state/unsafe-no-failsafe.json"; then
  die 'disabled failsafe accepted by controller run'
fi
# Temporary static fixture addresses prove every negative packet path before
# installing the guard. DHCP replaces them below and is required to succeed.
ip -n "$ns_a" addr add 10.203.0.100/24 dev eth0
ip -n "$ns_b" addr add 10.203.0.101/24 dev eth0
for ns in "$ns_a" "$ns_b"; do ip -n "$ns" route add default via 10.203.0.1; done
ip -n "$ns_gw" link set guest0 up
probe "$ns_wan" 198.18.0.2 "$ns_a" allow
probe "$ns_wan" 198.18.0.2 "$ns_b" allow
probe "$ns_a" 10.203.0.100 "$ns_wan" allow
probe "$ns_lan" 10.204.0.2 "$ns_a" allow
probe "$ns_wan" 192.168.77.2 "$ns_a" allow
# IPv6 controls include working forwarding and permanent neighbours. Disabling
# IPv6 is part of production topology; enable it again only with controller
# stopped below, to prove the actual guard blocks it even without that layer.
for ns in "$ns_gw" "$ns_a"; do ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0; done
gw sysctl -qw net.ipv6.conf.guest0.disable_ipv6=0
a sysctl -qw net.ipv6.conf.eth0.disable_ipv6=0
gw sysctl -qw net.ipv6.conf.all.forwarding=1
ip -n "$ns_gw" -6 addr add 2001:db8:203::1/64 dev guest0 nodad
ip -n "$ns_a" -6 addr add 2001:db8:203::2/64 dev eth0 nodad
ip -n "$ns_gw" -6 addr add 2001:db8:204::1/64 dev uplink0 nodad
ip -n "$ns_wan" -6 addr add 2001:db8:204::2/64 dev eth0 nodad
ip -n "$ns_a" -6 route add default via 2001:db8:203::1
ip -n "$ns_wan" -6 route add 2001:db8:203::/64 via 2001:db8:204::1
gwmac=$(ip -n "$ns_gw" -j link show guest0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["address"])')
amac=$mac_a
ip -n "$ns_a" -6 neigh replace 2001:db8:203::1 lladdr "$gwmac" dev eth0 nud permanent
ip -n "$ns_gw" -6 neigh replace 2001:db8:203::2 lladdr "$amac" dev guest0 nud permanent
# Make the complete IPv6 control route deterministic: the first one-shot
# probe must test forwarding, not race asynchronous neighbour discovery.
wanmac=$(ip -n "$ns_wan" -j link show eth0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["address"])')
uplinkmac=$(ip -n "$ns_gw" -j link show uplink0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["address"])')
ip -n "$ns_gw" -6 neigh replace 2001:db8:204::2 lladdr "$wanmac" dev uplink0 nud permanent
ip -n "$ns_wan" -6 neigh replace 2001:db8:204::1 lladdr "$uplinkmac" dev eth0 nud permanent
a ping -6 -n -c 1 -W 2 2001:db8:204::2
ip netns exec "$ns_wan" ping -6 -n -c 1 -W 2 2001:db8:203::2
gw sysctl -qw net.ipv6.conf.guest0.disable_ipv6=1
a sysctl -qw net.ipv6.conf.eth0.disable_ipv6=1
ip -n "$ns_gw" link set guest0 down
gw "$state/bin/portcullisd" bootstrap -config "$state/portcullis.json"
ip -n "$ns_gw" link set guest0 up
start_controller
start_bg portal ip netns exec "$ns_gw" setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
  "$state/bin/portcullis-portal" -config "$state/portcullis.json" -ready-file "$state/portal-ready/ready"
wait_file "$state/portal-ready/ready"
dhcp_guest "$ns_a"
dhcp_guest "$ns_b"
ip_a=$(ip -n "$ns_a" -4 -j addr show eth0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["addr_info"][0]["local"])')
[[ $ip_a == 10.203.0.100 ]] || die "unexpected DHCP fixture address: $ip_a"
[[ $(session_state "$ns_a") == denied && $(session_state "$ns_b") == denied ]] || die 'initial state not denied'
api "$ns_a" / > /dev/null

# Disposable host-browser relay acceptance with the actual Host/Origin.
# Port 80 preserves the portal's authority checks, not a rewritten header.
# Unlike the packet-only scenarios, this browser relay needs an actual HTTP
# destination to prove positive delivery after a kernel grant.
install -d -m 755 "$state/www"
printf "%s\n" "<!doctype html><title>Portcullis destination</title><h1>You're through.</h1>" > "$state/www/index.html"
start_bg browser-www ip netns exec "$ns_wan" python3 -m http.server \
  --bind 198.18.0.2 --directory "$state/www" 8080
browser_www_ready=0
for _ in {1..100}; do
  if ip netns exec "$ns_wan" curl --noproxy '*' --silent --fail --max-time 1 \
    http://198.18.0.2:8080/ > /dev/null; then
    browser_www_ready=1
    break
  fi
  sleep .1
done
(( browser_www_ready == 1 )) || die 'browser destination server never became ready'
start_bg proxy-portal python3 "$root/demo/nsproxy.py" --netns "$ns_a" --listen-port 80 \
  --target-host 10.203.0.1 --target-port 80 --ready "$state/proxy-portal.ready"
start_bg proxy-demo python3 "$root/demo/nsproxy.py" --netns "$ns_a" --listen-port 9081 \
  --target-host 198.18.0.2 --target-port 8080 --ready "$state/proxy-demo.ready"
wait_file "$state/proxy-portal.ready"
wait_file "$state/proxy-demo.ready"
browser() {
  curl --noproxy '*' --silent --show-error --fail-with-body --max-time 8 \
    --resolve portal.localhost:80:127.0.0.1 "$@" 
}
browser "http://portal.localhost/" | grep -q 'Portcullis' || die 'portal browser relay failed'
browser "http://portal.localhost/api/session" > "$state/browser-session.json"
python3 - "$state/browser-session.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["ok"] and x["session"]["state"] == "denied", x
PY
before=$(count guest-egress)
curl --noproxy '*' --silent --show-error --max-time 8 \
  --output "$state/browser-blocked.html" --write-out '%{http_code}' \
  "http://127.0.0.1:9081/" > "$state/browser-blocked.status"
[[ $(cat "$state/browser-blocked.status") == 504 ]] || die 'unauthorized browser relay did not time out'
grep -q 'does not by itself prove a Portcullis firewall drop' "$state/browser-blocked.html" \
  || die 'relay falsely attributed connection failure to the firewall'
(( $(count guest-egress) > before )) || die 'missing real kernel drop for denied browser destination'
browser -H 'Origin: http://portal.localhost' -H 'Content-Type: application/json' \
  -H 'X-Portcullis-Request: 1' -d '{"duration_seconds":30}' \
  "http://portal.localhost/api/access" > "$state/browser-granted.json"
python3 - "$state/browser-granted.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["ok"] and x["session"]["state"] == "granted", x
PY
curl --noproxy '*' --silent --show-error --fail-with-body --max-time 8 \
  "http://127.0.0.1:9081/" | grep -q "You're through." \
  || die 'authorized browser destination failed despite kernel grant'

# Operator dashboard: loopback HTTP, token gate, actual kernel snapshot and
# browser-authorized revoke. This exercises the dashboard backend, not merely
# the operator CLI.
start_bg dashboard "$state/bin/portcullisctl" -config "$state/portcullis.json" serve \
  -listen 127.0.0.1:8788 -token-file "$state/operator.token"
wait_file "$state/operator.token"
dash_ready=0
for _ in {1..100}; do
  code=$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' \
    --max-time 1 "http://127.0.0.1:8788/api/snapshot" || true)
  if [[ $code == 401 ]]; then dash_ready=1; break; fi
  sleep .1
done
(( dash_ready == 1 )) || die 'operator dashboard not serving'
token=$(cat "$state/operator.token")
curl --noproxy '*' --silent --show-error --fail-with-body --max-time 8 \
  -H "Authorization: Bearer $token" "http://127.0.0.1:8788/api/snapshot" > "$state/dashboard-snapshot.json"
python3 - "$state/dashboard-snapshot.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["ok"] and x["snapshot"]["enforcement"]=="ok",x
assert len(x["snapshot"]["grants"])==1 and x["snapshot"]["grants"][0]["kernel_present"],x
PY
curl --noproxy '*' --silent --show-error --fail-with-body --max-time 8 \
  -H "Authorization: Bearer $token" \
  -H 'Origin: http://127.0.0.1:8788' \
  -H 'X-Portcullis-Request: 1' -H 'Content-Type: application/json' \
  -d "{\\"mac\\":\\"$mac_a\\"}" \
  "http://127.0.0.1:8788/api/revoke" > "$state/dashboard-revoke.json"
python3 - "$state/dashboard-revoke.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["ok"],x
PY
before=$(count guest-egress)
code=$(curl --noproxy '*' --silent --show-error --max-time 8 \
  --output "$state/dashboard-revoked.html" --write-out '%{http_code}' "http://127.0.0.1:9081/")
[[ $code == 504 ]] || die 'dashboard revoke left destination reachable'
(( $(count guest-egress) > before )) || die 'dashboard revoke missing kernel drop'
ctl reset > /dev/null
[[ $(session_state "$ns_a") == denied ]] || die 'browser grant not removed'
echo 'PASS: browser relay Host/Origin, real kernel grant, destination and error attribution'
probe "$ns_wan" 198.18.0.2 "$ns_a" deny guest-egress
# DNS isolation: real UDP replies, not an external resolver.
a python3 - <<'PY'
import socket,struct
for name,typ,rcode,answers in [('portal.portcullis.test',1,0,1),('example.org',1,5,0),('portal.portcullis.test',28,0,0)]:
 q=struct.pack('!6H',123,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',typ,1)
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(3); s.sendto(q,('10.203.0.1',53)); r,_=s.recvfrom(512)
  ident,flags,qd,an,ns,ar=struct.unpack('!6H',r[:12])
  assert ident==123 and flags&15==rcode and not flags&128 and an==answers,(name,r)
PY
grant
probe "$ns_wan" 198.18.0.2 "$ns_a" allow
probe "$ns_wan" 198.18.0.2 "$ns_b" deny guest-egress
probe "$ns_lan" 10.204.0.2 "$ns_a" deny guest-protected
probe "$ns_wan" 192.168.77.2 "$ns_a" deny guest-protected
# Spoof A's IPv4 address using B's own MAC: tuple check must stop it.
ip -n "$ns_b" addr add 10.203.0.100/32 dev eth0
before=$(count guest-egress)
b ping -n -c 1 -W 1 -I 10.203.0.100 198.18.0.2 && die 'spoofed IP authorized'
(( $(count guest-egress) > before )) || die 'no anti-spoof drop'
ip -n "$ns_b" addr del 10.203.0.100/32 dev eth0
# Restore A's ARP evidence after intentional spoofing.
ip -n "$ns_gw" neigh del 10.203.0.100 dev guest0
a ping -n -c 1 -W 2 198.18.0.2
flow_case() {
  local kind=$1 f="$state/flow-$1" server client before_in before_out
  ctl reset > /dev/null
  grant
  ip netns exec "$ns_wan" python3 "$root/tests/netns/e2e_flow.py" server "$f" "$ip_a" & server=$!
  wait_file "$f.bound"
  a python3 "$root/tests/netns/e2e_flow.py" client "$f" "$ip_a" & client=$!
  wait_file "$f.ready"
  case $kind in
    revoke) ctl revoke "$mac_a" > /dev/null ;;
    expiry) stop_controller; sleep 31 ;;
    restart) stop_controller; start_controller ;;
  esac
  # Raw nft read before any controller request: expiry must be kernel-only;
  # restart must already have removed inherited elements before readiness.
  for setname in granted_v4 granted_dst_v4; do
    gw nft -j list set inet portcullis_guard "$setname" | python3 -c 'import json,sys; sets=[o["set"] for o in json.load(sys.stdin)["nftables"] if "set" in o]; assert len(sets)==1 and not sets[0].get("elem"),sets'
  done
  before_in=$(count guest-ingress); before_out=$(count guest-egress)
  touch "$f.trigger"
  wait_file "$f.blocked"
  (( $(count guest-ingress) > before_in && $(count guest-egress) > before_out )) || die "$kind missing directional drops"
  [[ ! -e $f.leaked ]] || die "$kind outbound leaked"
  [[ $kind != expiry ]] || start_controller
  ctl reset > /dev/null
  grant
  touch "$f.resume"
  wait_file "$f.recovered"
  wait "$client"; wait "$server"
  echo "PASS: $kind stops both directions; same sockets recover after new authorization"
}
flow_case revoke
flow_case expiry
flow_case restart
# Crash with no grants: default deny persists and no second guest gets access.
ctl reset > /dev/null
stop_controller
probe "$ns_wan" 198.18.0.2 "$ns_a" deny guest-egress
probe "$ns_wan" 198.18.0.2 "$ns_b" deny guest-egress
# Prove IPv6 guard drops independently of disable_ipv6, using the pretested route.
gw sysctl -qw net.ipv6.conf.guest0.disable_ipv6=0
a sysctl -qw net.ipv6.conf.eth0.disable_ipv6=0
ip -n "$ns_gw" -6 addr add 2001:db8:203::1/64 dev guest0 nodad
ip -n "$ns_a" -6 addr add 2001:db8:203::2/64 dev eth0 nodad
ip -n "$ns_a" -6 route add default via 2001:db8:203::1
ip -n "$ns_a" -6 neigh replace 2001:db8:203::1 lladdr "$gwmac" dev eth0 nud permanent
ip -n "$ns_gw" -6 neigh replace 2001:db8:203::2 lladdr "$amac" dev guest0 nud permanent
before=$(count guest-egress)
a ping -6 -n -c 1 -W 1 2001:db8:204::2 && die 'IPv6 escaped'
(( $(count guest-egress) > before )) || die 'missing IPv6 egress drop'
before=$(count guest-ingress)
ip netns exec "$ns_wan" ping -6 -n -c 1 -W 1 2001:db8:203::2 && die 'IPv6 ingress escaped'
(( $(count guest-ingress) > before )) || die 'missing IPv6 ingress drop'
gw sysctl -qw net.ipv6.conf.guest0.disable_ipv6=1
a sysctl -qw net.ipv6.conf.eth0.disable_ipv6=1
# Each mutation must fail explicit attestation AND drive a live controller
# into degraded mode, flushing grants and taking the guest link down.
mutation() {
 local kind=$1
 start_controller
 ctl reset >/dev/null
 grant
 case $kind in
  hook) gw nft 'flush chain inet portcullis_guard guest_forward'
        gw nft 'delete chain inet portcullis_guard guest_forward'
        gw nft 'add chain inet portcullis_guard guest_forward { type filter hook output priority -50; policy accept; }' ;;
  dormant) gw nft 'add table inet portcullis_guard { flags dormant; }' ;;
  missing) gw nft 'flush chain inet portcullis_guard guest_forward'; gw nft 'delete chain inet portcullis_guard guest_forward' ;;
  vlan) ip -n "$ns_gw" link add link guest0 name upper0 type vlan id 17 ;;
  macvlan) ip -n "$ns_gw" link add link guest0 name upper0 type macvlan mode bridge ;;
  ipvlan) ip -n "$ns_gw" link add link guest0 name upper0 type ipvlan mode l2 ;;
 esac
 if attest; then die "$kind attested unexpectedly"; fi
 for _ in {1..100}; do
  ctl snapshot > "$state/snapshot.json"
  if python3 - "$state/snapshot.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); sys.exit(0 if x['snapshot']['enforcement']=='degraded' else 1)
PY
  then break; fi
  sleep .1
 done
 python3 - "$state/snapshot.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); assert x['snapshot']['enforcement']=='degraded',x
PY
 ip -n "$ns_gw" -j link show guest0 | python3 -c 'import json,sys; assert "UP" not in json.load(sys.stdin)[0]["flags"]'
 # SEC-A: after the first successful isolation, an out-of-band privileged
 # actor may bring guest0 UP. The degraded controller must reassert DOWN on
 # its next reconcile tick, not rely on the one-shot result.
 if [[ $kind == hook ]]; then
   ip -n "$ns_gw" link set guest0 up
   # The controller can win the race to re-isolate before an immediate
   # inspection; successful ip link set UP is the actual activation stimulus.
   down=0
   for _ in {1..100}; do
     if ip -n "$ns_gw" -j link show guest0 | python3 -c 'import json,sys; assert "UP" not in json.load(sys.stdin)[0]["flags"]' 2>/dev/null; then
       down=1
       break
     fi
     sleep .1
   done
   (( down == 1 )) || die 'degraded controller did not reassert guest link isolation after re-UP'
 fi
 # A failed startup stays alive to retry verified link isolation. Do not
 # wait for a prompt exit: this terminal safety loop ends only on shutdown.
 stop_controller
 rm -f "$state/failed-start.ready"
 start_bg failed-start ip netns exec "$ns_gw" "$state/bin/portcullisd" run \
   -config "$state/portcullis.json" -ready-file "$state/failed-start.ready"
 local failed_pid seen_failure=0
 failed_pid="$(cat "$state/failed-start.pid")"
 for _ in {1..100}; do
   if grep -q 'controller startup failed; guest authorization unavailable' "$state/failed-start.log"; then
     seen_failure=1
     break
   fi
   kill -0 "$failed_pid" 2>/dev/null || die "$kind failed startup exited without safety supervision"
   sleep .1
 done
 (( seen_failure == 1 )) || die "$kind failed startup was not observed"
 kill -0 "$failed_pid" 2>/dev/null || die "$kind failed-start supervisor exited"
 [[ ! -e "$state/failed-start.ready" ]] || die "$kind failed startup published readiness"
 python3 - "$state/guest.sock" "$state/operator.sock" <<'PY'
import errno, socket, sys
for path in sys.argv[1:]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        try:
            client.connect(path)
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                raise
        else:
            raise AssertionError(f"failed startup still serving socket: {path}")
PY
 ip -n "$ns_gw" -j link show guest0 | python3 -c \
   'import json,sys; assert "UP" not in json.load(sys.stdin)[0]["flags"]'
 if [[ $kind == hook ]]; then
   # Test re-isolation during *failed startup*, separately from the normal
   # degraded controller reactivation test earlier in this mutation.
   ip -n "$ns_gw" link set guest0 up
   local isolated_again=0
   for _ in {1..100}; do
     kill -0 "$failed_pid" 2>/dev/null || die 'failed-start supervisor exited during re-isolation'
     if ip -n "$ns_gw" -j link show guest0 | python3 -c \
       'import json,sys; assert "UP" not in json.load(sys.stdin)[0]["flags"]' 2>/dev/null; then
       isolated_again=1
       break
     fi
     sleep .1
   done
   (( isolated_again == 1 )) || die 'failed-start supervisor did not re-isolate reactivated guest link'
 fi
 kill -TERM "$failed_pid"
 if wait "$failed_pid"; then die "$kind failed startup returned successful process status"; fi
 grep -q 'portcullisd: refusing to serve: enforcement degraded' "$state/failed-start.log" \
   || die "$kind failed startup lost original attestation failure"
 rm -f "$state/failed-start.pid"
 ip -n "$ns_gw" link del upper0 2>/dev/null || true
 # Table replacement is solely an offline test reset with guest link DOWN.
 gw nft delete table inet portcullis_guard
 gw "$state/bin/portcullisd" bootstrap -config "$state/portcullis.json"
 ip -n "$ns_gw" link set guest0 up
 start_controller
 dhcp_guest "$ns_a"; dhcp_guest "$ns_b"
 stop_controller
 echo "PASS: $kind rejected at runtime and startup"
}
for kind in hook dormant missing vlan macvlan ipvlan; do mutation "$kind"; done
echo 'PASS: Formnext DHCP, portal, timed kernel grants, revoke, crash, restart, anti-spoof, LAN, IPv6, DNS and adversarial topology'
