#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper="$script_dir/macos-apple-services.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# A fake runner.
#
# dig answers a host's A records from dns-a.<host> when that exists and from
# dns-a otherwise, and its AAAA records likewise from dns-aaaa. By default
# every host has one address in Apple's IPv4 network and one in its IPv6
# network, and ocsp.apple.com is served only from outside Apple's networks.
#
# curl reaches a host by name when any address the hosts file pins it to is
# reachable, as curl tries each, or at an address of its own when the hosts
# file doesn't name it; at a --resolve address it uses that one. An address is unreachable when the
# firewall's active rules name it or a network holding it. Without IPv6
# (no-ipv6) no IPv6 address is reached. A host in never-answers times out
# whatever happens. A "host status" line in answers-anyway connects whatever
# is blocked and then exits with that status, such as 35 for a TLS error or
# 28 for a service that accepts and then stalls. Like curl -w
# '%{time_connect}', it prints 0.000000 when no connection opened.
#
# pfctl applies the rules it is given: none of them when inert-firewall
# exists, none of the IPv6 entries when inert-ipv6 exists, none of the network
# entries when inert-networks exists, and it refuses them when pfctl-fails
# exists.
make_runner() {
	rm -rf "$work/runner" "$work/state"
	mkdir -p "$work/runner/bin"
	printf '127.0.0.1 localhost\n' >"$work/runner/hosts"
	printf 'default rules\n' >"$work/runner/pf.conf"
	printf '17.253.0.1\n' >"$work/runner/dns-a"
	printf '2a01:b740::1\n' >"$work/runner/dns-aaaa"
	printf '2.22.144.17\n' >"$work/runner/dns-a.ocsp.apple.com"
	printf '2a02:26f0::1\n' >"$work/runner/dns-aaaa.ocsp.apple.com"
	: >"$work/runner/active-rules"
	: >"$work/runner/never-answers"
	: >"$work/runner/answers-anyway"
	: >"$work/runner/calls"
	cat >"$work/runner/bin/pfctl" <<EOF
#!/bin/bash
echo "pfctl \$*" >>"$work/runner/calls"
case "\$1" in
-E)
	[ -e "$work/runner/pfctl-fails" ] && { echo "pfctl: syntax error" >&2; exit 1; }
	if [ -e "$work/runner/inert-ipv6" ]; then
		awk '{ out = ""; for (i = 1; i <= NF; i++) if (\$i !~ /:/) out = out \$i " "; print out }' "\$3" >"$work/runner/active-rules"
	elif [ -e "$work/runner/inert-networks" ]; then
		awk '{ out = ""; for (i = 1; i <= NF; i++) if (\$i !~ /\//) out = out \$i " "; print out }' "\$3" >"$work/runner/active-rules"
	elif [ ! -e "$work/runner/inert-firewall" ]; then
		cp "\$3" "$work/runner/active-rules"
	fi
	echo "pf enabled" >&2
	echo "Token : 4242" >&2
	;;
-f) cp "\$2" "$work/runner/active-rules" ;;
-X) [ "\$2" = 4242 ] || exit 1 ;;
esac
EOF
	cat >"$work/runner/bin/dig" <<EOF
#!/bin/bash
case "\$3" in
A) records="$work/runner/dns-a" ;;
AAAA) records="$work/runner/dns-aaaa" ;;
esac
if [ -e "\$records.\$2" ]; then cat "\$records.\$2"; else cat "\$records"; fi
EOF
	cat >"$work/runner/bin/curl" <<EOF
#!/bin/bash
address=""
while [ "\$#" -gt 0 ]; do
	case "\$1" in
	--resolve) address="\${2#*:443:}"; shift ;;
	https://*) url="\$1" ;;
	esac
	shift
done
host="\${url#https://}"
host="\${host%/}"
unconnected() { printf '0.000000'; exit "\$1"; }
connected() { printf '0.050000'; exit "\$1"; }
grep -Fxq "\$host" "$work/runner/never-answers" && unconnected 28
status=\$(awk -v host="\$host" '\$1 == host { print \$2 }' "$work/runner/answers-anyway")
[ -n "\$status" ] && connected "\$status"
rules="$work/runner/active-rules"
reachable() {
	case "\$1" in
	*:*) [ -e "$work/runner/no-ipv6" ] && return 1 ;;
	esac
	grep -Eq "[ {]\$1[ }]" "\$rules" && return 1
	case "\$1" in
	17.*) grep -Fq '17.0.0.0/8' "\$rules" && return 1 ;;
	2a01:b740:*) grep -Fq '2a01:b740::/32' "\$rules" && return 1 ;;
	esac
	return 0
}
if [ -n "\$address" ]; then
	address="\${address#[}"
	address="\${address%]}"
	if reachable "\$address"; then connected 0; fi
	unconnected 28
fi
pinned=\$(awk -v host="\$host" '\$2 == host { print \$1 }' "$work/runner/hosts")
[ -n "\$pinned" ] || connected 0
for address in \$pinned; do
	if reachable "\$address"; then connected 0; fi
done
unconnected 28
EOF
	printf '#!/bin/bash\necho "dscacheutil $*" >>"%s"\n' "$work/runner/calls" >"$work/runner/bin/dscacheutil"
	printf '#!/bin/bash\necho "killall $*" >>"%s"\n' "$work/runner/calls" >"$work/runner/bin/killall"
	chmod +x "$work/runner/bin/"*
}

run_helper() {
	HOSTS_FILE="$work/runner/hosts" \
		DEFAULT_PF_CONF="$work/runner/pf.conf" \
		PFCTL_BIN="$work/runner/bin/pfctl" \
		DIG_BIN="$work/runner/bin/dig" \
		CURL_BIN="$work/runner/bin/curl" \
		DSCACHEUTIL_BIN="$work/runner/bin/dscacheutil" \
		KILLALL_BIN="$work/runner/bin/killall" \
		SUDO="" \
		bash "$helper" "$@"
}

# Runs block, which must fail with an error containing $2, or else fail the
# test with $3. When $1 is "before-blocking", block must also have left the
# hosts file alone.
expect_block_failure() {
	local output
	if output=$(run_helper block "$work/state" 2>&1); then
		fail "$3"
	fi
	case "$output" in
	*"$2"*) ;;
	*) fail "$3: $output" ;;
	esac
	if [ "$1" = before-blocking ] && [ "$(cat "$work/runner/hosts")" != "127.0.0.1 localhost" ]; then
		fail "block changed the hosts file before it knew it could show the block works"
	fi
}

make_runner
: >"$work/runner/dns-aaaa.www.apple.com"
run_helper block "$work/state" >/dev/null || fail "block did not confirm Apple's services unreachable"
for host in api.apple-cloudkit.com ocsp2.apple.com crl.apple.com valid.apple.com certs.apple.com www.apple.com; do
	grep -Fxq "17.253.0.1 $host" "$work/runner/hosts" || fail "$host is not pinned to its address"
	grep -Fxq "$host 17.253.0.1" "$work/state/targets" || fail "$host's address in Apple's network was not checked"
done
grep -Fxq "100::1 www.apple.com" "$work/runner/hosts" \
	|| fail "a host DNS gave no IPv6 address is not pinned to a dropped one, so an IPv6 lookup could reach it"
grep -Fq ' 100::1 ' "$work/runner/active-rules" || fail "the IPv6 placeholder a host is pinned to is not dropped"
grep -Fxq "192.0.2.1 ocsp.apple.com" "$work/runner/hosts" && fail "a host with an IPv4 address was pinned to the placeholder too"
if grep -Fq ' 17.253.0.1 ' "$work/runner/active-rules"; then
	fail "an address inside Apple's network is listed on its own, so the network entry is never shown to work"
fi
grep -Fxq "2a02:26f0::1 ocsp.apple.com" "$work/runner/hosts" || fail "ocsp.apple.com is not pinned to its IPv6 address outside Apple's networks"
grep -Fxq "ocsp.apple.com" "$work/state/targets" || fail "ocsp.apple.com was not checked by name"
grep -Fq ' 2a02:26f0::1 ' "$work/runner/active-rules" \
	|| fail "the firewall does not drop an IPv6 address outside Apple's networks that an Apple host resolves to"
for host in api.apple-cloudkit.com ocsp2.apple.com crl.apple.com valid.apple.com certs.apple.com; do
	grep -Fxq "2a01:b740::1 $host" "$work/runner/hosts" || fail "$host is not pinned to its IPv6 address"
	grep -Fxq "$host [2a01:b740::1]" "$work/state/targets" || fail "$host's IPv6 address was not checked"
	grep -Fxq "$host" "$work/state/targets" || fail "$host was not checked by name"
done
grep -Fxq "2.22.144.17 ocsp.apple.com" "$work/runner/hosts" || fail "ocsp.apple.com is not pinned to its address outside Apple's network"
grep -Fq '2.22.144.17' "$work/runner/active-rules" \
	|| fail "the firewall does not block an address outside Apple's networks that an Apple host resolves to"
grep -Fq '17.0.0.0/8' "$work/runner/active-rules" \
	|| fail "the firewall does not block Apple's IPv4 network: $(cat "$work/runner/active-rules")"
grep -Fq '2a01:b740::/32' "$work/runner/active-rules" \
	|| fail "the firewall does not block Apple's IPv6 networks: $(cat "$work/runner/active-rules")"
grep -q 'dscacheutil -flushcache' "$work/runner/calls" || fail "block did not flush the name cache"
run_helper restore "$work/state"
[ "$(cat "$work/runner/hosts")" = "127.0.0.1 localhost" ] || fail "restore left this hosts file: $(cat "$work/runner/hosts")"
[ "$(cat "$work/runner/active-rules")" = "default rules" ] || fail "restore did not reload the default firewall rules"
grep -Fxq 'pfctl -X 4242' "$work/runner/calls" || fail "restore did not release the firewall token"
echo "PASS: Apple's hosts are pinned to their addresses, which the firewall drops, and restore undoes it"

make_runner
printf 'ocsp.apple.com 0\n' >"$work/runner/answers-anyway"
expect_block_failure after-blocking "ocsp.apple.com is still reachable" "block reported Apple's services unreachable while one still answered"
echo "PASS: block fails when an Apple service still answers"

make_runner
printf 'ocsp.apple.com 35\n' >"$work/runner/answers-anyway"
expect_block_failure after-blocking "ocsp.apple.com is still reachable" "a TLS error after connecting was taken for a blocked service"
echo "PASS: a service that connects and then fails TLS still counts as reachable"

make_runner
printf 'ocsp.apple.com 28\n' >"$work/runner/answers-anyway"
expect_block_failure after-blocking "ocsp.apple.com is still reachable" "a service that accepts and then stalls was taken for a blocked one"
echo "PASS: a service that accepts a connection and then stalls still counts as reachable"

make_runner
: >"$work/runner/inert-firewall"
expect_block_failure after-blocking "still reachable" "block reported Apple's services unreachable while the firewall let them through"
echo "PASS: block fails when the firewall doesn't stop the traffic"

make_runner
: >"$work/runner/inert-networks"
expect_block_failure after-blocking "api.apple-cloudkit.com is still reachable" "block reported Apple's network unreachable while only single addresses were dropped"
echo "PASS: block fails when the firewall drops single addresses but not Apple's networks"

make_runner
: >"$work/runner/inert-ipv6"
expect_block_failure after-blocking "api.apple-cloudkit.com is still reachable" "block reported Apple's IPv6 network unreachable while the firewall let it through"
echo "PASS: block fails when the firewall doesn't stop traffic to Apple's IPv6 network"

make_runner
: >"$work/runner/no-ipv6"
: >"$work/runner/inert-ipv6"
run_helper block "$work/state" >/dev/null || fail "a runner without IPv6 can't show the IPv6 rules work, and needn't"
if grep -q '\[' "$work/state/targets"; then
	fail "an IPv6 address the runner never reached was taken as checked"
fi
echo "PASS: IPv6 is checked only where the runner reaches it"

make_runner
printf 'crl.apple.com\n' >"$work/runner/never-answers"
expect_block_failure before-blocking "crl.apple.com is unreachable before blocking" "a service that never answered was taken for a blocked one"
echo "PASS: block fails before blocking when a service doesn't answer to begin with"

make_runner
printf '2.22.144.17\n' >"$work/runner/dns-a"
expect_block_failure before-blocking "no address in Apple's IPv4 network answered" "block proceeded with no address in Apple's network to check the firewall against"
echo "PASS: block fails before blocking when no address in Apple's network answers"

make_runner
: >"$work/runner/dns-a.crl.apple.com"
: >"$work/runner/dns-aaaa.crl.apple.com"
expect_block_failure before-blocking "DNS gave no address for crl.apple.com" "block proceeded with a host it had no address to block for"
echo "PASS: block fails before blocking when DNS gives a host no address"

make_runner
: >"$work/runner/pfctl-fails"
expect_block_failure after-blocking "pfctl refused the rules" "block succeeded although the firewall refused its rules"
run_helper restore "$work/state"
[ "$(cat "$work/runner/hosts")" = "127.0.0.1 localhost" ] || fail "restore after a refused block left this hosts file: $(cat "$work/runner/hosts")"
echo "PASS: a refused firewall rule set fails block, and restore still undoes it"

make_runner
run_helper restore "$work/state"
[ "$(cat "$work/runner/hosts")" = "127.0.0.1 localhost" ] || fail "restore without a block changed the hosts file"
if grep -q '^pfctl' "$work/runner/calls"; then
	fail "restore without a block changed the firewall"
fi
echo "PASS: restore without a block changes nothing"
