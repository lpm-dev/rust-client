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

# A fake runner. curl reaches a host unless the hosts file maps it to 0.0.0.0,
# or, at a --resolve address, unless the firewall holds rules that block
# 17.0.0.0/8; a host listed in reachable-anyway is reached either way. dig
# answers 17.253.0.1 for every name, as Apple's DNS does for its own hosts.
# pfctl accepts rules without applying them when inert-firewall exists.
make_runner() {
	rm -rf "$work/runner" "$work/state"
	mkdir -p "$work/runner/bin"
	printf '127.0.0.1 localhost\n' >"$work/runner/hosts"
	printf 'default rules\n' >"$work/runner/pf.conf"
	: >"$work/runner/active-rules"
	: >"$work/runner/reachable-anyway"
	: >"$work/runner/calls"
	cat >"$work/runner/bin/pfctl" <<EOF
#!/bin/bash
echo "pfctl \$*" >>"$work/runner/calls"
case "\$1" in
-E)
	[ -e "$work/runner/pfctl-fails" ] && { echo "pfctl: syntax error" >&2; exit 1; }
	[ -e "$work/runner/inert-firewall" ] || cp "\$3" "$work/runner/active-rules"
	echo "pf enabled" >&2
	echo "Token : 4242" >&2
	;;
-f) cp "\$2" "$work/runner/active-rules" ;;
-X) [ "\$2" = 4242 ] || exit 1 ;;
esac
EOF
	cat >"$work/runner/bin/dig" <<'EOF'
#!/bin/bash
echo 17.253.0.1
EOF
	cat >"$work/runner/bin/curl" <<EOF
#!/bin/bash
address=""
while [ "\$#" -gt 0 ]; do
	case "\$1" in
	--resolve) address="\${2##*:}"; shift ;;
	https://*) url="\$1" ;;
	esac
	shift
done
host="\${url#https://}"
host="\${host%/}"
grep -Fxq "\$host" "$work/runner/reachable-anyway" && exit 0
if [ -n "\$address" ]; then
	case "\$address" in
	17.*) grep -Fq '17.0.0.0/8' "$work/runner/active-rules" && exit 28 ;;
	esac
	exit 0
fi
grep -Eq "^0\\.0\\.0\\.0 \$host\$" "$work/runner/hosts" && exit 7
exit 0
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

make_runner
run_helper block "$work/state" >/dev/null || fail "block did not confirm Apple's services unreachable"
for host in api.apple-cloudkit.com ocsp.apple.com ocsp2.apple.com crl.apple.com valid.apple.com; do
	grep -Fxq "0.0.0.0 $host" "$work/runner/hosts" || fail "$host is not blocked by name"
	grep -Fxq ":: $host" "$work/runner/hosts" || fail "$host is not blocked by name over IPv6"
done
grep -Fq 'block drop out quick inet from any to { 17.0.0.0/8 }' "$work/runner/active-rules" \
	|| fail "the firewall does not block Apple's IPv4 network: $(cat "$work/runner/active-rules")"
grep -Fq '2a01:b740::/32' "$work/runner/active-rules" \
	|| fail "the firewall does not block Apple's IPv6 networks: $(cat "$work/runner/active-rules")"
grep -q 'dscacheutil -flushcache' "$work/runner/calls" || fail "block did not flush the name cache"
run_helper restore "$work/state"
[ "$(cat "$work/runner/hosts")" = "127.0.0.1 localhost" ] || fail "restore left this hosts file: $(cat "$work/runner/hosts")"
[ "$(cat "$work/runner/active-rules")" = "default rules" ] || fail "restore did not reload the default firewall rules"
grep -Fxq 'pfctl -X 4242' "$work/runner/calls" || fail "restore did not release the firewall token"
echo "PASS: Apple's services are blocked by name and network, then restored"

make_runner
printf 'ocsp.apple.com\n' >"$work/runner/reachable-anyway"
if run_helper block "$work/state" >/dev/null 2>&1; then
	fail "block reported Apple's services unreachable while one still answered"
fi
echo "PASS: block fails when an Apple service still answers"

make_runner
: >"$work/runner/inert-firewall"
if run_helper block "$work/state" >/dev/null 2>&1; then
	fail "block reported Apple's network unreachable while the firewall let it through"
fi
echo "PASS: block fails when the firewall doesn't stop traffic to Apple's network"

make_runner
: >"$work/runner/pfctl-fails"
if run_helper block "$work/state" >/dev/null 2>&1; then
	fail "block succeeded although the firewall refused its rules"
fi
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
