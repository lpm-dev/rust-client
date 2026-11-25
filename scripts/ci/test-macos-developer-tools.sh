#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper="$script_dir/macos-developer-tools.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# A fake runner: two Xcode installations, a symlink to one of them, an
# unrelated app, the Command Line Tools, and developer-tool commands whose
# answers follow the selected developer directory the way Apple's do.
make_runner() {
	rm -rf "$work/runner" "$work/state"
	mkdir -p "$work/runner/Applications/Xcode_16.4.app/Contents/Developer/usr/bin" \
		"$work/runner/Applications/Xcode_26.0.app/Contents/Developer/usr/bin" \
		"$work/runner/Applications/Safari.app" \
		"$work/runner/CommandLineTools/usr/bin" "$work/runner/bin"
	ln -s "$work/runner/Applications/Xcode_16.4.app" "$work/runner/Applications/Xcode.app"
	printf '%s\n' "$work/runner/Applications/Xcode.app/Contents/Developer" >"$work/runner/selected"
	cat >"$work/runner/bin/xcode-select" <<EOF
#!/bin/bash
case "\$1" in
--reset)
	if [ -d "$work/runner/Applications/Xcode.app" ]; then
		echo "$work/runner/Applications/Xcode.app/Contents/Developer" >"$work/runner/selected"
	elif [ -d "$work/runner/CommandLineTools" ]; then
		echo "$work/runner/CommandLineTools" >"$work/runner/selected"
	else
		: >"$work/runner/selected"
	fi
	;;
--switch) echo "\$2" >"$work/runner/selected" ;;
-p) selected=\$(cat "$work/runner/selected"); [ -n "\$selected" ] && [ -d "\$selected" ] || exit 2; echo "\$selected" ;;
esac
EOF
	cat >"$work/runner/bin/xcrun" <<EOF
#!/bin/bash
selected=\$(cat "$work/runner/selected")
[ -n "\$selected" ] && [ -d "\$selected" ] || exit 1
echo "\$selected/usr/bin/\$2"
EOF
	# Like /usr/bin/stapler: it refuses to run without Xcode selected, unless
	# working-stapler exists, when it runs and rejects an unstapled bundle.
	cat >"$work/runner/bin/stapler" <<EOF
#!/bin/bash
[ "\$1" = validate ] && [ "\$#" -eq 2 ] || exit 99
if [ -e "$work/runner/working-stapler" ]; then
	echo "\$2 does not have a ticket stapled to it."
	exit 65
fi
case "\$(cat "$work/runner/selected")" in
*.app/Contents/Developer) exit 0 ;;
*) echo "xcode-select: error: tool 'stapler' requires Xcode, but active developer directory '\$(cat "$work/runner/selected")' is a command line tools instance" >&2; exit 1 ;;
esac
EOF
	chmod +x "$work/runner/bin/"*
}

run_helper() {
	MACOS_APPLICATIONS_DIR="$work/runner/Applications" \
		MACOS_COMMAND_LINE_TOOLS_DIR="$work/runner/CommandLineTools" \
		XCODE_SELECT_BIN="$work/runner/bin/xcode-select" \
		XCRUN_BIN="$work/runner/bin/xcrun" \
		STAPLER_BIN="$work/runner/bin/stapler" \
		XCRUN_CACHE_DIR="$work/cache dir" \
		SUDO="" \
		TMPDIR="$work" \
		bash "$helper" "$@"
}

apps() {
	(cd "$work/runner/Applications" && ls -d -- *.app | sort | tr '\n' ' ')
}

make_runner
if run_helper verify none >/dev/null 2>&1; then
	fail "verify accepted a runner that still has Xcode"
fi

run_helper hide none "$work/state" >/dev/null
[ "$(apps)" = "Safari.app " ] || fail "hiding developer tools left these apps: $(apps)"
[ ! -e "$work/runner/CommandLineTools" ] || fail "the Command Line Tools were not hidden"
if run_helper hide none "$work/state" >/dev/null 2>&1; then
	fail "hiding twice would lose track of the first hidden tools"
fi
run_helper restore "$work/state"
[ "$(apps)" = "Safari.app Xcode.app Xcode_16.4.app Xcode_26.0.app " ] || fail "restore left these apps: $(apps)"
[ -L "$work/runner/Applications/Xcode.app" ] || fail "restore did not keep Xcode.app a symlink"
[ -d "$work/runner/CommandLineTools/usr/bin" ] || fail "restore did not bring the Command Line Tools back"
[ "$(cat "$work/runner/selected")" = "$work/runner/Applications/Xcode.app/Contents/Developer" ] \
	|| fail "restore did not select Xcode again"
echo "PASS: a runner without developer tools is verified and restored"

run_helper hide command-line-tools "$work/state" >/dev/null
[ "$(apps)" = "Safari.app " ] || fail "hiding Xcode left these apps: $(apps)"
[ -d "$work/runner/CommandLineTools" ] || fail "the Command Line Tools must stay"
[ "$(cat "$work/runner/selected")" = "$work/runner/CommandLineTools" ] || fail "the Command Line Tools were not selected"
run_helper restore "$work/state"
[ "$(apps)" = "Safari.app Xcode.app Xcode_16.4.app Xcode_26.0.app " ] || fail "restore left these apps: $(apps)"
echo "PASS: a runner with only the Command Line Tools is verified and restored"

make_runner
: >"$work/runner/working-stapler"
if run_helper hide command-line-tools "$work/state" >/dev/null 2>&1; then
	fail "a stapler that runs and merely rejects its input was taken for Apple's Xcode-only shim"
fi
run_helper restore "$work/state"
echo "PASS: a working stapler is not mistaken for a Mac with only the Command Line Tools"

make_runner
rm -rf "$work/runner/CommandLineTools"
if run_helper hide command-line-tools "$work/state" >/dev/null 2>&1; then
	fail "a runner without the Command Line Tools cannot stand for one that has only them"
fi
run_helper restore "$work/state"
echo "PASS: a missing Command Line Tools installation is reported"

make_runner
run_helper restore "$work/state"
[ "$(apps)" = "Safari.app Xcode.app Xcode_16.4.app Xcode_26.0.app " ] || fail "restore without hidden tools changed apps"
echo "PASS: restore without hidden tools changes nothing"

make_runner
printf '%s\n' "$work/runner/Applications/Xcode_26.0.app/Contents/Developer" >"$work/runner/selected"
mkdir -p "$work/cache dir"
: >"$work/cache dir/xcrun_db"
run_helper hide none "$work/state" >/dev/null
[ ! -e "$work/cache dir/xcrun_db" ] || fail "hiding developer tools left xcrun's cache of their paths"
run_helper restore "$work/state"
[ "$(cat "$work/runner/selected")" = "$work/runner/Applications/Xcode_26.0.app/Contents/Developer" ] \
	|| fail "restore selected $(cat "$work/runner/selected") instead of the Xcode selected before"
echo "PASS: restore selects the developer directory selected before"
