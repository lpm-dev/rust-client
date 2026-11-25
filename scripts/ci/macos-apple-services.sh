#!/usr/bin/env bash
# Cuts a hosted macOS runner off from Apple's services, as a firewall that
# silently drops their traffic does, so the checks after it show that
# installing and updating LPM needs none of them and doesn't stall without
# them.
#
#   macos-apple-services.sh block <state-dir>    block them and confirm it
#   macos-apple-services.sh restore <state-dir>  undo block
set -euo pipefail

# The hosts macOS asks about notarization tickets and certificate revocation.
# Some of them are served from outside Apple's networks, so the addresses each
# resolves to are blocked too, and the hosts file pins each name to them so a
# later lookup can't land somewhere else.
APPLE_HOSTS=(api.apple-cloudkit.com ocsp.apple.com ocsp2.apple.com crl.apple.com valid.apple.com)
APPLE_NETWORKS_V4="17.0.0.0/8"
APPLE_NETWORKS_V6="2620:149::/32 2a01:b740::/32 2403:300::/32"

HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
DEFAULT_PF_CONF="${DEFAULT_PF_CONF:-/etc/pf.conf}"
PFCTL_BIN="${PFCTL_BIN:-/sbin/pfctl}"
DIG_BIN="${DIG_BIN:-/usr/bin/dig}"
CURL_BIN="${CURL_BIN:-/usr/bin/curl}"
DSCACHEUTIL_BIN="${DSCACHEUTIL_BIN:-/usr/bin/dscacheutil}"
KILLALL_BIN="${KILLALL_BIN:-/usr/bin/killall}"
SUDO="${SUDO-sudo}"

die() {
	echo "::error::$*" >&2
	exit 1
}

flush_name_cache() {
	$SUDO "$DSCACHEUTIL_BIN" -flushcache
	$SUDO "$KILLALL_BIN" -HUP mDNSResponder 2>/dev/null || true
}

# Succeeds when a connection to $1 on port 443 opens, at the address $2 when
# given rather than the one its name resolves to. Only curl's exit codes for
# a name it couldn't resolve (6), a refused or unroutable connection (7) and
# a timeout (28) mean no connection: a TLS or HTTP error came after one.
connects() {
	local resolve=() status=0
	[ -n "${2:-}" ] && resolve=(--resolve "$1:443:$2")
	"$CURL_BIN" -sS -o /dev/null --connect-timeout 5 --max-time 15 \
		${resolve[@]+"${resolve[@]}"} "https://$1/" 2>/dev/null || status=$?
	case "$status" in
	6 | 7 | 28) return 1 ;;
	*) return 0 ;;
	esac
}

# Prints "host address" for each address DNS gives host $1. dig asks the DNS
# server directly, past the hosts file.
dns_addresses() {
	"$DIG_BIN" +short "$1" A | grep -E '^[0-9]+(\.[0-9]+){3}$' | sed "s/^/$1 /" || true
	"$DIG_BIN" +short "$1" AAAA | grep -E '^[0-9A-Fa-f]*:[0-9A-Fa-f:]+$' | sed "s/^/$1 /" || true
}

# Records the addresses to block in $1/addresses, and in $1/targets what
# answers now and must not once blocked: each host by name, and for each host
# its first address in Apple's IPv4 network and its first in Apple's IPv6
# networks that the runner reaches.
record_baseline() {
	local addresses="$1/addresses" targets="$1/targets" host address
	: >"$addresses"
	: >"$targets"
	connects api.github.com || die "GitHub is unreachable before blocking anything"
	for host in "${APPLE_HOSTS[@]}"; do
		connects "$host" || die "$host is unreachable before blocking, so blocking it would show nothing"
		printf '%s\n' "$host" >>"$targets"
		dns_addresses "$host" >>"$addresses"
		grep -q "^$host " "$addresses" || die "DNS gave no address for $host to block"
		address=$(awk -v host="$host" '$1 == host && $2 ~ /^17\./ { print $2; exit }' "$addresses")
		if [ -n "$address" ] && connects "$host" "$address"; then
			printf '%s %s\n' "$host" "$address" >>"$targets"
		fi
		while read -r address; do
			if connects "$host" "[$address]"; then
				printf '%s [%s]\n' "$host" "$address" >>"$targets"
				break
			fi
		done < <(awk -v host="$host" '$1 == host && tolower($2) ~ /^(2620:149|2a01:b740|2403:300):/ { print $2 }' "$addresses")
	done
	grep -q ' 17\.' "$targets" ||
		die "no address in Apple's IPv4 network answered before blocking, so the firewall can't be shown to work"
}

confirm_blocked() {
	local host address
	while read -r host address; do
		if connects "$host" "$address"; then
			die "$host is still reachable${address:+ at $address}"
		fi
	done <"$1/targets"
	connects api.github.com || die "blocking Apple's services also blocked GitHub"
	echo "Apple's services are unreachable:"
	sed 's/^/  /' "$1/targets"
}

block() {
	local state=$1 v4 v6
	mkdir -p "$state"
	record_baseline "$state"
	cp "$HOSTS_FILE" "$state/hosts"
	{
		printf '\n# Apple services blocked by scripts/ci/macos-apple-services.sh\n'
		awk '{ print $2, $1 }' "$state/addresses"
	} | $SUDO tee -a "$HOSTS_FILE" >/dev/null
	v4="$APPLE_NETWORKS_V4 $(awk '$2 !~ /:/ { print $2 }' "$state/addresses" | sort -u | tr '\n' ' ')"
	v6="$APPLE_NETWORKS_V6 $(awk '$2 ~ /:/ { print $2 }' "$state/addresses" | sort -u | tr '\n' ' ')"
	printf 'block drop out quick inet from any to { %s }\nblock drop out quick inet6 from any to { %s }\n' \
		"$v4" "$v6" >"$state/pf.conf"
	if ! $SUDO "$PFCTL_BIN" -E -f "$state/pf.conf" 2>"$state/pfctl.log"; then
		cat "$state/pfctl.log" >&2
		die "pfctl refused the rules"
	fi
	sed -n 's/^Token : //p' "$state/pfctl.log" >"$state/pf-token"
	if [ ! -s "$state/pf-token" ]; then
		cat "$state/pfctl.log" >&2
		die "pfctl did not enable the firewall"
	fi
	flush_name_cache
	confirm_blocked "$state"
}

restore() {
	local state=$1
	if [ -f "$state/hosts" ]; then
		$SUDO cp "$state/hosts" "$HOSTS_FILE"
	fi
	if [ -s "$state/pf-token" ]; then
		$SUDO "$PFCTL_BIN" -f "$DEFAULT_PF_CONF" 2>/dev/null || true
		$SUDO "$PFCTL_BIN" -X "$(cat "$state/pf-token")" 2>/dev/null || true
	fi
	flush_name_cache
}

case "${1:-}" in
block)
	[ "$#" -eq 2 ] || die "usage: $0 block <state-dir>"
	block "$2"
	;;
restore)
	[ "$#" -eq 2 ] || die "usage: $0 restore <state-dir>"
	restore "$2"
	;;
*) die "usage: $0 block|restore <state-dir>" ;;
esac
