#!/usr/bin/env bash
# netns.sh: build or remove the V60 S0-NAT-SPIKE topology on ONE Linux host (root).
#
# Everything lives in network namespaces named v60-*; no interface, route or firewall rule is added
# to the host's own namespace, so the host's networking is untouched. `down` deletes the namespaces
# and with them every veth, bridge and NAT rule.
#
#   v60-inet   a bridge standing in for the internet, 10.99.0.0/24
#   v60-relay  the relay, 10.99.0.1
#   v60-nata   home router A: WAN 10.99.0.2, LAN 192.168.10.1/24, NAT (MASQUERADE) out of WAN
#   v60-natb   home router B: WAN 10.99.0.3, LAN 192.168.20.1/24, NAT out of WAN
#   v60-a      member machine A, 192.168.10.2 (default route via router A)
#   v60-b      member machine B, 192.168.20.2 (default route via router B)
#
# Each router drops unsolicited inbound traffic from the WAN (only established/related is forwarded
# to its LAN), as a home router does. A and B have no route to each other's LAN.
#
# Usage: netns.sh up <cone|symmetric> [delay_ms]   |   netns.sh down   |   netns.sh status
#   cone       MASQUERADE keeps the source port when it is free (Linux default): the mapping for a
#              given local port is the same whatever the destination (endpoint-independent).
#   symmetric  MASQUERADE --random-fully: every new connection gets a random public port, so the
#              port the relay observes is not the port a hole punch would use.
#   delay_ms   one-way delay added on each router's WAN link (netem), default 20.
set -euo pipefail

NS=(v60-inet v60-relay v60-nata v60-natb v60-a v60-b)
die() { echo "netns.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
x() { ip netns exec "$1" "${@:2}"; }

down() {
  for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
}

link() { # link <ns-a> <if-a> <ns-b> <if-b>: a veth pair with one end in each namespace
  ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
}

router() { # router <ns> <wan-ip> <lan-cidr-gw> <mode> <delay>
  local ns=$1 wan=$2 lan=$3 mode=$4 delay=$5
  x "$ns" ip addr add "$wan/24" dev wan
  x "$ns" ip addr add "$lan" dev lan
  x "$ns" ip link set wan up; x "$ns" ip link set lan up; x "$ns" ip link set lo up
  x "$ns" sysctl -qw net.ipv4.ip_forward=1
  local rnd=""; [ "$mode" = symmetric ] && rnd="--random-fully"
  x "$ns" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE $rnd
  x "$ns" iptables -P FORWARD DROP
  x "$ns" iptables -A FORWARD -i lan -o wan -j ACCEPT
  x "$ns" iptables -A FORWARD -i wan -o lan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  # The router itself serves nothing on its WAN address.
  x "$ns" iptables -A INPUT -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  x "$ns" iptables -A INPUT -i wan -j DROP
  if [ "$delay" -gt 0 ] && x "$ns" tc qdisc add dev wan root netem delay "${delay}ms" 2>/dev/null; then
    :
  elif [ "$delay" -gt 0 ]; then
    echo "netns.sh: netem unavailable, no delay on $ns" >&2
  fi
}

up() {
  local mode=$1 delay=${2:-20}
  [ "$mode" = cone ] || [ "$mode" = symmetric ] || die "mode must be cone or symmetric"
  down
  for n in "${NS[@]}"; do ip netns add "$n"; done
  x v60-inet ip link add br0 type bridge
  x v60-inet ip link set br0 up
  x v60-inet ip link set lo up
  link v60-inet r0 v60-relay wan
  link v60-inet a0 v60-nata wan
  link v60-inet b0 v60-natb wan
  for i in r0 a0 b0; do x v60-inet ip link set "$i" master br0; x v60-inet ip link set "$i" up; done
  x v60-relay ip addr add 10.99.0.1/24 dev wan
  x v60-relay ip link set wan up; x v60-relay ip link set lo up

  link v60-nata lan v60-a eth0
  link v60-natb lan v60-b eth0
  router v60-nata 10.99.0.2 192.168.10.1/24 "$mode" "$delay"
  router v60-natb 10.99.0.3 192.168.20.1/24 "$mode" "$delay"
  x v60-a ip addr add 192.168.10.2/24 dev eth0; x v60-a ip link set eth0 up; x v60-a ip link set lo up
  x v60-a ip route add default via 192.168.10.1
  x v60-b ip addr add 192.168.20.2/24 dev eth0; x v60-b ip link set eth0 up; x v60-b ip link set lo up
  x v60-b ip route add default via 192.168.20.1

  # Sanity: both members reach the relay; neither reaches the other's private address.
  x v60-a ping -c1 -W2 10.99.0.1 >/dev/null || die "A cannot reach the relay"
  x v60-b ping -c1 -W2 10.99.0.1 >/dev/null || die "B cannot reach the relay"
  if x v60-a ping -c1 -W1 192.168.20.2 >/dev/null 2>&1; then die "A reaches B's LAN directly"; fi
  if x v60-a ping -c1 -W1 10.99.0.3 >/dev/null 2>&1; then die "B's router answers unsolicited traffic"; fi
  echo "netns.sh: up ($mode NAT, ${delay} ms per WAN hop)"
}

case "${1:-}" in
  up) up "${2:?mode}" "${3:-20}" ;;
  down) down; echo "netns.sh: down" ;;
  status) ip netns list | grep '^v60-' || echo "netns.sh: no v60 namespaces" ;;
  *) die "usage: netns.sh up <cone|symmetric> [delay_ms] | down | status" ;;
esac
