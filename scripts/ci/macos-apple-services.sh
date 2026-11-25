#!/usr/bin/env bash
# Cuts a hosted macOS runner off from Apple's services, as a Mac that is
# offline or behind a firewall that blocks Apple is, so the checks after it
# show that installing and updating LPM needs none of them.
#
#   macos-apple-services.sh block <state-dir>    block them and confirm it
#   macos-apple-services.sh restore <state-dir>  undo block
set -euo pipefail

# The hosts macOS asks about notarization tickets and certificate revocation.
# Some of them are served from outside Apple's networks, so each is also
# blocked by name.
APPLE_HOSTS=(api.apple-cloudkit.com ocsp.apple.com ocsp2.apple.com crl.apple.com valid.apple.com)
APPLE_NETWORKS_V4="17.0.0.0/8"
APPLE_NETWORKS_V6="2620:149::/32, 2a01:b740::/32, 2403:300::/32"

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

# Succeeds when an HTTPS connection to $1 opens within ten seconds, at the
# address $2 when given rather than the one its name resolves to.
reachable() {
	local resolve=()
	[ -n "${2:-}" ] && resolve=(--resolve "$1:443:$2")
	"$CURL_BIN" -sS -o /dev/null --max-time 10 ${resolve[@]+"${resolve[@]}"} "https://$1/" 2>/dev/null
}

confirm_blocked() {
	local host address
	for host in "${APPLE_HOSTS[@]}"; do
		if reachable "$host"; then
			die "$host is still reachable by name"
		fi
		# dig asks the DNS server, past the hosts file, for the addresses in
		# Apple's network that the firewall must block on its own.
		for address in $("$DIG_BIN" +short "$host" A | grep -E '^17\.[0-9.]+$' || true); do
			if reachable "$host" "$address"; then
				die "$host is still reachable at $address"
			fi
		done
	done
	reachable api.github.com || die "blocking Apple's services also blocked GitHub"
	echo "Apple's services are unreachable: ${APPLE_HOSTS[*]}, $APPLE_NETWORKS_V4, $APPLE_NETWORKS_V6"
}

block() {
	local state=$1 host
	mkdir -p "$state"
	cp "$HOSTS_FILE" "$state/hosts"
	{
		printf '\n# Apple services blocked by scripts/ci/macos-apple-services.sh\n'
		for host in "${APPLE_HOSTS[@]}"; do
			printf '0.0.0.0 %s\n:: %s\n' "$host" "$host"
		done
	} | $SUDO tee -a "$HOSTS_FILE" >/dev/null
	printf 'block drop out quick inet from any to { %s }\nblock drop out quick inet6 from any to { %s }\n' \
		"$APPLE_NETWORKS_V4" "$APPLE_NETWORKS_V6" >"$state/pf.conf"
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
	confirm_blocked
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
