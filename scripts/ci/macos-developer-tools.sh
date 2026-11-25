#!/bin/bash
# Turns a disposable macOS runner into a Mac without Xcode, and optionally
# without the Command Line Tools, so later steps exercise what LPM's users
# have. GitHub-hosted runners come with both. `restore` puts them back so the
# job's post steps, which need git, still work.
set -euo pipefail

APPLICATIONS_DIR="${MACOS_APPLICATIONS_DIR:-/Applications}"
COMMAND_LINE_TOOLS_DIR="${MACOS_COMMAND_LINE_TOOLS_DIR:-/Library/Developer/CommandLineTools}"
XCODE_SELECT_BIN="${XCODE_SELECT_BIN:-/usr/bin/xcode-select}"
XCRUN_BIN="${XCRUN_BIN:-/usr/bin/xcrun}"
STAPLER_BIN="${STAPLER_BIN:-/usr/bin/stapler}"
GETCONF_BIN="${GETCONF_BIN:-getconf}"
# xcrun caches where tools are in TMPDIR and in the per-user temporary
# directory, which differ when TMPDIR is overridden.
XCRUN_CACHE_DIRS=("${TMPDIR:-/tmp}" "$("$GETCONF_BIN" DARWIN_USER_TEMP_DIR 2>/dev/null || true)")
SUDO="${SUDO-sudo}"

usage() {
	echo "usage: $0 hide <none|command-line-tools> <state-dir> | verify <none|command-line-tools> | restore <state-dir>" >&2
	exit 64
}

fail() {
	echo "error: $*" >&2
	exit 1
}

require_mode() {
	case "${1:-}" in
	none | command-line-tools) ;;
	*) usage ;;
	esac
}

xcode_apps() {
	find "$APPLICATIONS_DIR" -maxdepth 1 -name 'Xcode*.app' \( -type d -o -type l \) -print
}

# Moves a developer-tools path into the state directory under a name without
# the .app suffix, so Launch Services no longer finds it as Xcode.
hide_path() {
	local path="$1" state_dir="$2"
	local hidden
	hidden="$state_dir/hidden/$(basename "$path").hidden"
	$SUDO mv "$path" "$hidden"
	printf '%s\t%s\n' "$path" "$hidden" >>"$state_dir/moved"
}

clear_xcrun_cache() {
	local directory
	for directory in "${XCRUN_CACHE_DIRS[@]}"; do
		if [ -n "$directory" ]; then
			rm -f "$directory"/xcrun_db*
		fi
	done
}

hide() {
	local mode="$1" state_dir="$2"
	[ ! -e "$state_dir/moved" ] || fail "$state_dir already records hidden developer tools"
	mkdir -p "$state_dir/hidden"
	env -u DEVELOPER_DIR "$XCODE_SELECT_BIN" -p >"$state_dir/selected" 2>/dev/null || : >"$state_dir/selected"
	: >"$state_dir/moved"
	local app
	while IFS= read -r app; do
		hide_path "$app" "$state_dir"
	done < <(xcode_apps)
	if [ "$mode" = none ]; then
		if [ -e "$COMMAND_LINE_TOOLS_DIR" ]; then
			hide_path "$COMMAND_LINE_TOOLS_DIR" "$state_dir"
		fi
		$SUDO "$XCODE_SELECT_BIN" --reset || true
	else
		[ -d "$COMMAND_LINE_TOOLS_DIR" ] || fail "this runner has no Command Line Tools at $COMMAND_LINE_TOOLS_DIR"
		$SUDO "$XCODE_SELECT_BIN" --switch "$COMMAND_LINE_TOOLS_DIR"
	fi
	clear_xcrun_cache
	verify "$mode"
}

verify() {
	local mode="$1"
	[ -z "$(xcode_apps)" ] || fail "Xcode is still installed: $(xcode_apps | tr '\n' ' ')"
	if [ "$mode" = none ]; then
		[ ! -e "$COMMAND_LINE_TOOLS_DIR" ] || fail "the Command Line Tools are still installed"
		if selected=$(env -u DEVELOPER_DIR "$XCODE_SELECT_BIN" -p 2>/dev/null); then
			fail "a developer directory is still selected: $selected"
		fi
		if found=$(env -u DEVELOPER_DIR "$XCRUN_BIN" --find stapler 2>/dev/null); then
			fail "xcrun still finds stapler at $found"
		fi
	else
		selected=$(env -u DEVELOPER_DIR "$XCODE_SELECT_BIN" -p)
		[ "$selected" = "$COMMAND_LINE_TOOLS_DIR" ] || fail "the selected developer directory is $selected"
		# A stapler that runs rejects this directory too, so only the shim's
		# own refusal shows that stapler needs Xcode here.
		local refusal
		refusal=$(env -u DEVELOPER_DIR "$STAPLER_BIN" validate "$COMMAND_LINE_TOOLS_DIR" 2>&1 || true)
		case "$refusal" in
		*"requires Xcode"*) ;;
		*) fail "$STAPLER_BIN did not refuse to run without Xcode: $refusal" ;;
		esac
	fi
	echo "developer tools: $mode"
}

restore() {
	local state_dir="$1"
	[ -f "$state_dir/moved" ] || return 0
	local original hidden status=0
	while IFS=$'\t' read -r original hidden; do
		$SUDO mv "$hidden" "$original" || status=1
	done < <(tail -r "$state_dir/moved" 2>/dev/null || tac "$state_dir/moved")
	local selected
	selected=$(cat "$state_dir/selected" 2>/dev/null || true)
	if [ -n "$selected" ]; then
		$SUDO "$XCODE_SELECT_BIN" --switch "$selected" || status=1
	else
		$SUDO "$XCODE_SELECT_BIN" --reset || status=1
	fi
	clear_xcrun_cache
	[ "$status" -eq 0 ] || fail "some developer tools could not be restored"
	rm -f "$state_dir/moved"
}

case "${1:-}" in
hide)
	[ "$#" -eq 3 ] || usage
	require_mode "$2"
	hide "$2" "$3"
	;;
verify)
	[ "$#" -eq 2 ] || usage
	require_mode "$2"
	verify "$2"
	;;
restore)
	[ "$#" -eq 2 ] || usage
	restore "$2"
	;;
*)
	usage
	;;
esac
