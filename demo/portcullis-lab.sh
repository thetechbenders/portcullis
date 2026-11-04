#!/usr/bin/env bash
# Interactive Formnext demonstration lab. DISPOSABLE DEMO MACHINE ONLY.
#
# Builds a self-contained network-namespace topology (gateway, isolated AP
# bridge, two guests, demo destination, protected LAN), installs the
# Portcullis guard while the guest link is down, starts portcullisd, the
# unprivileged portal and the loopback operator dashboard, and exposes the
# guest's view to a host browser through relays that originate inside the
# guest namespace. Only veth/bridge/dummy links created INSIDE the lab
# namespaces are used; no physical interface or host firewall is touched.
#
#   sudo demo/portcullis-lab.sh up BINDIR    start (BINDIR holds the three binaries)
#   sudo demo/portcullis-lab.sh status       operator snapshot and kernel evidence
#   sudo demo/portcullis-lab.sh revoke       operator-revoke guest A
#   sudo demo/portcullis-lab.sh reset        revoke all grants, clear cooldowns
#   sudo demo/portcullis-lab.sh crash        kill -9 the controller (grants stay kernel-bounded)
#   sudo demo/portcullis-lab.sh restart      start the controller again (revokes inherited grants)
#   sudo demo/portcullis-lab.sh down         stop everything and delete the lab
set -Eeuo pipefail

state=/run/portcullis-demo
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ns_gw=pcdemo-gw ns_ap=pcdemo-ap ns_a=pcdemo-guestA ns_b=pcdemo-guestB ns_wan=pcdemo-wan ns_lan=pcdemo-lan
mac_a=02:00:00:00:0a:01 mac_b=02:00:00:00:0b:01
guest_port=9080 demo_port=9081 dash_port=8788

die() { echo "portcullis-lab: $*" >&2; exit 1; }
need_root() { (( EUID == 0 )) || die "must run as root on a disposable demo machine"; }
refuse_protected_host() {
  # Project rule: never run the lab on the production workstation.
  if [[ "$(hostname)" == hephaestus && -z "${PORTCULLIS_LAB_ALLOW_THIS_HOST:-}" ]]; then
    die "refusing to run on hephaestus; use a disposable demo machine or VM"
  fi
}
have_ipv6() { [[ -d /proc/sys/net/ipv6 ]]; }
wait_file() {
  local f="$1" i
  for i in {1..100}; do [[ -e "$f" ]] && return 0; sleep 0.1; done
  die "timed out waiting for $f"
}
start_bg() { # name, command...
  local name="$1"; shift
  "$@" >"$state/$name.log" 2>&1 &
  echo "$!" >"$state/$name.pid"
}
stop_pid() {
  local f="$state/$1.pid"
  [[ -f "$f" ]] || return 0
  kill "$(cat "$f")" 2>/dev/null || :
  rm -f "$f"
}

write_config() {
  local nft ip ct
  nft="$(command -v nft)" ip="$(command -v ip)" ct="$(command -v conntrack)"
  cat >"$state/portcullis.json" <<EOF
{
  "guest_interface": "guest0",
  "uplink_interface": "uplink0",
  "gateway_v4": "10.203.0.1",
  "guest_subnet_v4": "10.203.0.0/24",
  "dhcp_pool_start": "10.203.0.100",
  "dhcp_pool_end": "10.203.0.199",
  "dhcp_lease_seconds": 600,
  "portal_port": 80,
  "dns_port": 53,
  "portal_hostnames": ["portal.portcullis.test", "portal.localhost"],
  "dns_records": {"demo.portcullis.test": "198.18.0.2"},
  "grant_default_seconds": 120,
  "grant_max_seconds": 300,
  "revoke_cooldown_seconds": 60,
  "guest_socket": "$state/guest.sock",
  "operator_socket": "$state/operator.sock",
  "portal_uid": 65534,
  "nft_path": "$nft",
  "conntrack_path": "$ct",
  "ip_path": "$ip",
  "failsafe_link_down": true
}
EOF
}

build_topology() {
  local ns
  for ns in $ns_gw $ns_ap $ns_a $ns_b $ns_wan $ns_lan; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
  # Gateway guest side: guest0 <-> apup, kept DOWN until the guard is installed.
  ip -n $ns_gw link add guest0 type veth peer name apup
  ip -n $ns_gw link set apup netns $ns_ap
  ip -n $ns_gw link add uplink0 type veth peer name eth0 netns $ns_wan
  ip -n $ns_gw link add lan0 type veth peer name eth0 netns $ns_lan
  if have_ipv6; then
    ip netns exec $ns_gw sysctl -qw net.ipv6.conf.guest0.disable_ipv6=1
  fi
  ip -n $ns_gw addr add 10.203.0.1/24 dev guest0
  ip -n $ns_gw addr add 198.18.0.1/24 dev uplink0
  ip -n $ns_gw addr add 10.204.0.1/24 dev lan0
  ip -n $ns_gw link set uplink0 up
  ip -n $ns_gw link set lan0 up
  ip -n $ns_gw route add 192.168.77.0/24 via 198.18.0.2
  ip netns exec $ns_gw sysctl -qw net.ipv4.ip_forward=1
  ip netns exec $ns_gw sysctl -qw net.ipv4.ip_unprivileged_port_start=53
  # Access point model: bridge with isolated client ports (client isolation).
  ip -n $ns_ap link add br0 type bridge
  ip -n $ns_ap link set apup master br0
  for g in a b; do
    local gns mac
    if [[ $g == a ]]; then gns=$ns_a mac=$mac_a; else gns=$ns_b mac=$mac_b; fi
    ip -n $ns_ap link add "p$g" type veth peer name eth0 netns "$gns"
    ip -n $ns_ap link set "p$g" master br0
    ip -n $ns_ap link set "p$g" up
    ip -n $ns_ap link set dev "p$g" type bridge_slave isolated on
    ip -n "$gns" link set eth0 address "$mac"
    if have_ipv6; then ip netns exec "$gns" sysctl -qw net.ipv6.conf.eth0.disable_ipv6=1; fi
    ip -n "$gns" link set eth0 up
  done
  ip -n $ns_ap link set apup up
  ip -n $ns_ap link set br0 up
  # Demo destination and a "home network" host behind the uplink.
  ip -n $ns_wan addr add 198.18.0.2/24 dev eth0
  ip -n $ns_wan link set eth0 up
  ip -n $ns_wan link add home0 type dummy
  ip -n $ns_wan addr add 192.168.77.2/24 dev home0
  ip -n $ns_wan link set home0 up
  ip -n $ns_wan route add 10.203.0.0/24 via 198.18.0.1
  ip -n $ns_lan addr add 10.204.0.2/24 dev eth0
  ip -n $ns_lan link set eth0 up
  ip -n $ns_lan route add 10.203.0.0/24 via 10.204.0.1
}

start_controller() {
  rm -f "$state/portcullisd.ready"
  start_bg portcullisd ip netns exec $ns_gw "$state/bin/portcullisd" run -config "$state/portcullis.json" -ready-file "$state/portcullisd.ready"
  wait_file "$state/portcullisd.ready"
}

dhcp_guest() { # ns
  ip netns exec "$1" busybox udhcpc -i eth0 -q -n -t 5 -T 2 -s "$root/tests/netns/udhcpc.script" >"$state/$1-dhcp.log" 2>&1 \
    || die "DHCP failed in $1 (see $state/$1-dhcp.log)"
}

cmd_up() {
  local bindir="${1:-}"
  [[ -n "$bindir" && -x "$bindir/portcullisd" && -x "$bindir/portcullis-portal" && -x "$bindir/portcullisctl" ]] \
    || die "usage: portcullis-lab.sh up BINDIR (containing portcullisd, portcullis-portal, portcullisctl)"
  [[ ! -e "$state" ]] || die "lab already exists; run 'down' first"
  for c in ip nft conntrack busybox setpriv python3; do command -v "$c" >/dev/null || die "missing $c"; done
  install -d -m 0755 "$state" "$state/bin"
  install -m 0755 "$bindir/portcullisd" "$bindir/portcullis-portal" "$bindir/portcullisctl" "$state/bin/"
  write_config
  build_topology
  ip netns exec $ns_gw "$state/bin/portcullisd" bootstrap -config "$state/portcullis.json"
  ip -n $ns_gw link set guest0 up
  start_controller
  start_bg portal ip netns exec $ns_gw setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
    "$state/bin/portcullis-portal" -config "$state/portcullis.json" -ready-file "$state/portal.ready"
  wait_file "$state/portal.ready"
  # Demo destination web page, reachable only through a grant.
  install -d -m 0755 "$state/www"
  cat >"$state/www/index.html" <<'EOF'
<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>Demo destination</title>
<body style="font:20px system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem">
<h1>You're through.</h1><p>This page lives on the demo destination behind the gateway uplink.
It loads only while this guest holds a kernel-enforced Portcullis grant.</p>
EOF
  start_bg demo-www ip netns exec $ns_wan python3 -m http.server --bind 198.18.0.2 --directory "$state/www" 8080
  dhcp_guest $ns_a
  dhcp_guest $ns_b
  start_bg proxy-portal python3 "$root/demo/nsproxy.py" --netns $ns_a --listen-port $guest_port \
    --target-host 10.203.0.1 --target-port 80 --ready "$state/proxy-portal.ready"
  start_bg proxy-demo python3 "$root/demo/nsproxy.py" --netns $ns_a --listen-port $demo_port \
    --target-host 198.18.0.2 --target-port 8080 --ready "$state/proxy-demo.ready"
  start_bg dashboard "$state/bin/portcullisctl" -config "$state/portcullis.json" serve \
    -listen 127.0.0.1:$dash_port -token-file "$state/operator.token"
  wait_file "$state/proxy-portal.ready"
  wait_file "$state/proxy-demo.ready"
  wait_file "$state/operator.token"
  cat <<EOF

Portcullis demo lab is up.
  Guest A portal (as seen from guest A):  http://portal.localhost:$guest_port/
  Demo destination via guest A:           http://127.0.0.1:$demo_port/
  Operator dashboard (loopback only):     http://127.0.0.1:$dash_port/
  Operator token:                         $state/operator.token
Use 'status', 'revoke', 'reset', 'crash', 'restart' and 'down'.
EOF
}

cmd_status() {
  ip netns exec $ns_gw "$state/bin/portcullisctl" -config "$state/portcullis.json" snapshot || :
  echo "--- kernel grant sets (authoritative) ---"
  ip netns exec $ns_gw nft list set inet portcullis_guard granted_v4
  ip netns exec $ns_gw nft list set inet portcullis_guard bound_v4
  echo "--- labelled rule counters ---"
  ip netns exec $ns_gw nft list table inet portcullis_guard | grep -E 'counter packets' || :
}

cmd_down() {
  local name ns
  for name in proxy-portal proxy-demo dashboard demo-www portal portcullisd; do stop_pid "$name"; done
  for ns in $ns_a $ns_b $ns_ap $ns_wan $ns_lan $ns_gw; do ip netns del "$ns" 2>/dev/null || :; done
  rm -rf -- "$state"
  echo "lab removed"
}

need_root
refuse_protected_host
case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  status) cmd_status ;;
  revoke) ip netns exec $ns_gw "$state/bin/portcullisctl" -config "$state/portcullis.json" revoke $mac_a ;;
  reset) ip netns exec $ns_gw "$state/bin/portcullisctl" -config "$state/portcullis.json" reset ;;
  crash) kill -9 "$(cat "$state/portcullisd.pid")" && rm -f "$state/portcullisd.pid" && echo "controller killed (SIGKILL)" ;;
  restart) start_controller && echo "controller restarted; inherited grants revoked" ;;
  down) cmd_down ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
