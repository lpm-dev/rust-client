#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/audit-install-args.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
TEST_POLICY_PATH=""

lpm_audit_security_policy_path() {
    printf '%s\n' "$TEST_POLICY_PATH"
}

assert_empty_default_args() {
    local out="$TMP_DIR/default.out"

    unset LPM_AUDIT_ALLOW_NEW
    unset LPM_SECURITY_POLICY_PATH

    lpm_audit_prepare_install_args > "$out"
    [[ "${#LPM_AUDIT_INSTALL_ARGS[@]}" -eq 0 ]]
    grep -q "running without --allow-new" "$out"
}

assert_allow_new_requires_policy() {
    local err="$TMP_DIR/missing-policy.err"
    TEST_POLICY_PATH="$TMP_DIR/missing.toml"

    if (
        export LPM_AUDIT_ALLOW_NEW=1
        lpm_audit_prepare_install_args >/dev/null
    ) 2>"$err"; then
        echo "expected missing managed policy to fail" >&2
        exit 1
    fi

    grep -q "no managed security policy" "$err"
}

assert_allow_new_adds_arg_with_policy() {
    local policy="$TMP_DIR/security-policy.toml"
    local out="$TMP_DIR/policy.out"
    printf 'minimum-release-age-secs = 0\n' > "$policy"
    TEST_POLICY_PATH="$policy"

    export LPM_AUDIT_ALLOW_NEW=1

    lpm_audit_prepare_install_args > "$out"
    [[ "${#LPM_AUDIT_INSTALL_ARGS[@]}" -eq 1 ]]
    [[ "${LPM_AUDIT_INSTALL_ARGS[0]}" == "--allow-new" ]]
    grep -q "using --allow-new" "$out"
}

assert_run_install_omits_allow_new_by_default() {
    local bin="$TMP_DIR/fake-lpm"
    local args="$TMP_DIR/default-args.txt"

    printf '%s\n' \
        '#!/bin/bash' \
        'printf "%s\n" "$*" >> "$LPM_TEST_ARGS_FILE"' \
        > "$bin"
    chmod +x "$bin"

    unset LPM_AUDIT_ALLOW_NEW
    unset LPM_SECURITY_POLICY_PATH
    export LPM_TEST_ARGS_FILE="$args"

    lpm_audit_prepare_install_args > /dev/null
    lpm_audit_run_install "$bin" --linker isolated --json > /dev/null

    grep -q '^install --linker isolated --json$' "$args"
    if grep -q -- '--allow-new' "$args"; then
        echo "default audit install unexpectedly used --allow-new" >&2
        exit 1
    fi
}

assert_run_install_includes_allow_new_when_opted_in() {
    local bin="$TMP_DIR/fake-lpm-allow-new"
    local args="$TMP_DIR/allow-new-args.txt"
    local policy="$TMP_DIR/run-security-policy.toml"

    printf '%s\n' \
        '#!/bin/bash' \
        'printf "%s\n" "$*" >> "$LPM_TEST_ARGS_FILE"' \
        > "$bin"
    chmod +x "$bin"
    printf 'minimum-release-age-secs = 0\n' > "$policy"
    TEST_POLICY_PATH="$policy"

    export LPM_AUDIT_ALLOW_NEW=1
    export LPM_TEST_ARGS_FILE="$args"

    lpm_audit_prepare_install_args > /dev/null
    lpm_audit_run_install "$bin" --linker hoisted --json > /dev/null

    grep -q '^install --allow-new --linker hoisted --json$' "$args"
}

assert_retryable_registry_failure_is_retried() {
    local bin="$TMP_DIR/fake-lpm-retry"
    local attempts="$TMP_DIR/retry-attempts.txt"
    local out="$TMP_DIR/retry-install.json"
    local err="$TMP_DIR/retry-install.log"

    printf '%s\n' \
        '#!/bin/bash' \
        'count=0' \
        'if [[ -f "$LPM_TEST_ATTEMPTS_FILE" ]]; then count="$(cat "$LPM_TEST_ATTEMPTS_FILE")"; fi' \
        'count=$((count + 1))' \
        'printf "%s\n" "$count" > "$LPM_TEST_ATTEMPTS_FILE"' \
        'if [[ "$count" -eq 1 ]]; then' \
        '  printf "%s\n" "{\"success\":false,\"error\":\"registry error: HTTP 406: \"}"' \
        '  exit 1' \
        'fi' \
        'printf "%s\n" "{\"success\":true}"' \
        > "$bin"
    chmod +x "$bin"

    unset LPM_AUDIT_ALLOW_NEW
    export LPM_AUDIT_INSTALL_RETRIES=2
    export LPM_TEST_ATTEMPTS_FILE="$attempts"

    lpm_audit_prepare_install_args > /dev/null
    lpm_audit_run_install_with_retries "$bin" "$out" "$err" --linker hoisted --json 2>/dev/null

    [[ "$(cat "$attempts")" == "2" ]]
    grep -q '"success":true' "$out"
}

assert_non_retryable_failure_is_not_retried() {
    local bin="$TMP_DIR/fake-lpm-no-retry"
    local attempts="$TMP_DIR/no-retry-attempts.txt"
    local out="$TMP_DIR/no-retry-install.json"
    local err="$TMP_DIR/no-retry-install.log"

    printf '%s\n' \
        '#!/bin/bash' \
        'count=0' \
        'if [[ -f "$LPM_TEST_ATTEMPTS_FILE" ]]; then count="$(cat "$LPM_TEST_ATTEMPTS_FILE")"; fi' \
        'count=$((count + 1))' \
        'printf "%s\n" "$count" > "$LPM_TEST_ATTEMPTS_FILE"' \
        'printf "%s\n" "{\"success\":false,\"error\":\"manifest validation failed\"}"' \
        'exit 1' \
        > "$bin"
    chmod +x "$bin"

    unset LPM_AUDIT_ALLOW_NEW
    export LPM_AUDIT_INSTALL_RETRIES=2
    export LPM_TEST_ATTEMPTS_FILE="$attempts"

    lpm_audit_prepare_install_args > /dev/null
    if lpm_audit_run_install_with_retries "$bin" "$out" "$err" --linker isolated --json 2>/dev/null; then
        echo "expected non-retryable install failure" >&2
        exit 1
    fi

    [[ "$(cat "$attempts")" == "1" ]]
    grep -q 'manifest validation failed' "$out"
}

assert_empty_default_args
assert_allow_new_requires_policy
assert_allow_new_adds_arg_with_policy
assert_run_install_omits_allow_new_by_default
assert_run_install_includes_allow_new_when_opted_in
assert_retryable_registry_failure_is_retried
assert_non_retryable_failure_is_not_retried

echo "audit install arg helper tests passed"
