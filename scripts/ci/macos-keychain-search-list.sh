#!/bin/bash
set -euo pipefail

SECURITY_BIN="${SECURITY_BIN:-/usr/bin/security}"

usage() {
	echo "usage: $0 add <signing-keychain> <state-file> | restore <state-file>" >&2
	exit 64
}

trim_outer_whitespace() {
	local value="$1"
	value="${value#"${value%%[![:space:]]*}"}"
	value="${value%"${value##*[![:space:]]}"}"
	printf '%s' "$value"
}

decode_security_path() {
	local encoded="$1"
	local decoded=""
	local current next
	local index

	for ((index = 0; index < ${#encoded}; index++)); do
		current="${encoded:index:1}"
		if [ "$current" = "\\" ] && [ $((index + 1)) -lt ${#encoded} ]; then
			next="${encoded:index+1:1}"
			case "$next" in
			\\|\")
				decoded+="$next"
				index=$((index + 1))
				continue
				;;
			esac
		fi
		decoded+="$current"
	done

	printf '%s' "$decoded"
}

read_current_list() {
	local line encoded
	KEYCHAIN_LIST=()
	KEYCHAIN_LIST_COUNT=0

	while IFS= read -r line; do
		line="$(trim_outer_whitespace "$line")"
		if [ "${#line}" -lt 2 ] || [ "${line:0:1}" != '"' ] || [ "${line: -1}" != '"' ]; then
			echo "error: unexpected security list-keychains output: $line" >&2
			exit 1
		fi
		encoded="${line:1:${#line}-2}"
		KEYCHAIN_LIST+=("$(decode_security_path "$encoded")")
		KEYCHAIN_LIST_COUNT=$((KEYCHAIN_LIST_COUNT + 1))
	done < <("$SECURITY_BIN" list-keychains -d user)
}

write_state() {
	local destination="$1"
	local temporary
	local index

	if [ -e "$destination" ]; then
		echo "error: Keychain search-list state already exists: $destination" >&2
		exit 1
	fi

	umask 077
	temporary="$(mktemp "${destination}.tmp.XXXXXX")"
	trap 'rm -f -- "$temporary"' RETURN
	: >"$temporary"
	for ((index = 0; index < KEYCHAIN_LIST_COUNT; index++)); do
		printf '%s\0' "${KEYCHAIN_LIST[$index]}" >>"$temporary"
	done
	mv "$temporary" "$destination"
	trap - RETURN
}

read_state() {
	local source="$1"
	local keychain
	KEYCHAIN_LIST=()
	KEYCHAIN_LIST_COUNT=0

	while IFS= read -r -d '' keychain; do
		KEYCHAIN_LIST+=("$keychain")
		KEYCHAIN_LIST_COUNT=$((KEYCHAIN_LIST_COUNT + 1))
	done <"$source"
}

add_keychain() {
	local signing_keychain="$1"
	local state_file="$2"
	local keychain
	local already_present=0
	local index

	read_current_list
	write_state "$state_file"
	for ((index = 0; index < KEYCHAIN_LIST_COUNT; index++)); do
		keychain="${KEYCHAIN_LIST[$index]}"
		if [ "$keychain" = "$signing_keychain" ]; then
			already_present=1
			break
		fi
	done
	if [ "$KEYCHAIN_LIST_COUNT" -eq 0 ]; then
		"$SECURITY_BIN" list-keychains -d user -s "$signing_keychain"
	elif [ "$already_present" -eq 0 ]; then
		"$SECURITY_BIN" list-keychains -d user -s "${KEYCHAIN_LIST[@]}" "$signing_keychain"
	else
		"$SECURITY_BIN" list-keychains -d user -s "${KEYCHAIN_LIST[@]}"
	fi
}

restore_keychains() {
	local state_file="$1"

	if [ ! -f "$state_file" ]; then
		return 0
	fi

	read_state "$state_file"
	if [ "$KEYCHAIN_LIST_COUNT" -eq 0 ]; then
		"$SECURITY_BIN" list-keychains -d user -s
	else
		"$SECURITY_BIN" list-keychains -d user -s "${KEYCHAIN_LIST[@]}"
	fi
	rm -f -- "$state_file"
}

if [ ! -x "$SECURITY_BIN" ]; then
	echo "error: security executable is unavailable: $SECURITY_BIN" >&2
	exit 1
fi

case "${1:-}" in
add)
	[ "$#" -eq 3 ] || usage
	add_keychain "$2" "$3"
	;;
restore)
	[ "$#" -eq 2 ] || usage
	restore_keychains "$2"
	;;
*)
	usage
	;;
esac
