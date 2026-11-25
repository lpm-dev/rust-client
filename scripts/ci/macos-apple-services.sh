#!/usr/bin/env bash
# Cuts a hosted macOS runner off from Apple's services, as a firewall that
# silently drops their traffic does, so the checks after it show that
# installing and updating LPM needs none of them and doesn't stall without
# them.
#
#   macos-apple-services.sh block <state-dir>    block them and confirm it
#   macos-apple-services.sh restore <state-dir>  undo block
set -euo pipefail

# The hosts macOS asks about notarization tickets, certificate revocation and
# Apple's intermediate certificates. Some are served from outside Apple's
# networks, so the addresses each resolves to are blocked too, and the hosts
# file pins each name to them, or to a dropped placeholder for an address
# family DNS gave none in, so a later lookup can't land somewhere else.
APPLE_HOSTS=(api.apple-cloudkit.com ocsp.apple.com ocsp2.apple.com crl.apple.com valid.apple.com certs.apple.com www.apple.com)
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

# Succeeds when a TCP connection to $1 on port 443 opens, at the address $2
# when given rather than the one its name resolves to. curl counts the
# connections it opened, whatever failed afterwards: a TLS error, or a service
# that accepts and then stalls, still opened one. No proxy or ~/.curlrc may
# stand in for the destination.
connects() {
	local resolve=() opened
	[ -n "${2:-}" ] && resolve=(--resolve "$1:443:$2")
	opened=$("$CURL_BIN" -q -sS -o /dev/null --noproxy '*' --connect-timeout 5 --max-time 15 \
		-w '%{num_connects}' ${resolve[@]+"${resolve[@]}"} "https://$1/" 2>/dev/null) || true
	[ "${opened:-0}" -gt 0 ] 2>/dev/null
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
		awk -v host="$host" '$1 == host && $2 !~ /:/ { found = 1 } END { exit !found }' "$addresses" ||
			printf '%s 192.0.2.1\n' "$host" >>"$addresses"
		awk -v host="$host" '$1 == host && $2 ~ /:/ { found = 1 } END { exit !found }' "$addresses" ||
			printf '%s 100::1\n' "$host" >>"$addresses"
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
	local state=$1 outside
	mkdir -p "$state"
	record_baseline "$state"
	cp "$HOSTS_FILE" "$state/hosts"
	{
		printf '\n# Apple services blocked by scripts/ci/macos-apple-services.sh\n'
		awk '{ print $2, $1 }' "$state/addresses"
	} | $SUDO tee -a "$HOSTS_FILE" >/dev/null
	# Addresses inside Apple's networks are left to the network entries, so
	# the probes of those addresses show the network entries work.
	outside=$(awk '$2 !~ /^17\./ && tolower($2) !~ /^(2620:149|2a01:b740|2403:300):/ { print $2 }' "$state/addresses" |
		sort -u | tr '\n' ' ')
	printf 'table <apple_services> const { %s %s %s}\nblock drop out quick from any to <apple_services>\n' \
		"$APPLE_NETWORKS_V4" "$APPLE_NETWORKS_V6" "$outside" >"$state/pf.conf"
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
