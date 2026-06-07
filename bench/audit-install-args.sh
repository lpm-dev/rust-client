#!/bin/bash

LPM_AUDIT_INSTALL_ARGS=()

lpm_audit_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

lpm_audit_is_windows() {
    case "${OSTYPE:-}" in
        msys*|cygwin*|win32*) return 0 ;;
    esac
    [[ "${OS:-}" == "Windows_NT" ]]
}

lpm_audit_shell_path() {
    local path="$1"
    if lpm_audit_is_windows && command -v cygpath &>/dev/null; then
        cygpath -u "$path" 2>/dev/null || printf '%s\n' "$path"
    else
        printf '%s\n' "$path"
    fi
}

lpm_audit_security_policy_path() {
    if lpm_audit_is_windows; then
        if [[ -n "${ProgramData:-}" ]]; then
            lpm_audit_shell_path "${ProgramData}\\lpm\\security-policy.toml"
        else
            lpm_audit_shell_path "C:\\ProgramData\\lpm\\security-policy.toml"
        fi
    else
        printf '%s\n' "/etc/lpm/security-policy.toml"
    fi
}

lpm_audit_prepare_install_args() {
    LPM_AUDIT_INSTALL_ARGS=()

    if ! lpm_audit_truthy "${LPM_AUDIT_ALLOW_NEW:-}"; then
        echo "[audit] running without --allow-new; set LPM_AUDIT_ALLOW_NEW=1 for policy-backed cooldown bypasses"
        return 0
    fi

    local policy_path
    policy_path="$(lpm_audit_security_policy_path)"
    if [[ ! -f "$policy_path" ]]; then
        cat >&2 <<EOF
ERROR: LPM_AUDIT_ALLOW_NEW is set, but no managed security policy was found at:
  $policy_path

Install the CI audit policy first:
  sudo ./bench/install-audit-security-policy.sh

Or unset LPM_AUDIT_ALLOW_NEW to run the harness without --allow-new.
EOF
        exit 2
    fi

    LPM_AUDIT_INSTALL_ARGS=(--allow-new)
    echo "[audit] using --allow-new with managed security policy: $policy_path"
}

lpm_audit_run_install() {
    local bin="${1:?lpm binary path required}"
    shift

    if [[ "${#LPM_AUDIT_INSTALL_ARGS[@]}" -gt 0 ]]; then
        "$bin" install "${LPM_AUDIT_INSTALL_ARGS[@]}" "$@"
    else
        "$bin" install "$@"
    fi
}

lpm_audit_retry_count() {
    case "${LPM_AUDIT_INSTALL_RETRIES:-2}" in
        ''|*[!0-9]*) printf '%s\n' 2 ;;
        *) printf '%s\n' "${LPM_AUDIT_INSTALL_RETRIES:-2}" ;;
    esac
}

lpm_audit_install_failure_is_retryable() {
    local stdout_path="$1"
    local stderr_path="$2"

    grep -Eqi \
        'HTTP (406|408|409|425|429|500|502|503|504|520|521|522|523|524)|timed? ?out|timeout|connection (reset|refused)|temporarily unavailable|TLS|SSL|EAI_AGAIN|ECONNRESET|ETIMEDOUT' \
        "$stdout_path" "$stderr_path" 2>/dev/null
}

lpm_audit_run_install_with_retries() {
    local bin="${1:?lpm binary path required}"
    local stdout_path="${2:?install stdout path required}"
    local stderr_path="${3:?install stderr path required}"
    shift 3

    local retries
    retries="$(lpm_audit_retry_count)"
    local max_attempts=$((retries + 1))
    local attempt=1
    local rc=0
    local tmp_out="${stdout_path}.attempt"
    local tmp_err="${stderr_path}.attempt"
    local had_errexit=0
    case "$-" in
        *e*) had_errexit=1 ;;
    esac

    while (( attempt <= max_attempts )); do
        set +e
        lpm_audit_run_install "$bin" "$@" > "$tmp_out" 2> "$tmp_err"
        rc=$?
        if [[ $had_errexit -eq 1 ]]; then
            set -e
        else
            set +e
        fi

        cp "$tmp_out" "$stdout_path"
        cp "$tmp_err" "$stderr_path"

        if [[ $rc -eq 0 ]]; then
            rm -f "$tmp_out" "$tmp_err"
            return 0
        fi

        if (( attempt >= max_attempts )) || ! lpm_audit_install_failure_is_retryable "$tmp_out" "$tmp_err"; then
            rm -f "$tmp_out" "$tmp_err"
            return "$rc"
        fi

        printf '[audit] retrying install after retryable registry/network failure (attempt %d/%d)\n' \
            "$attempt" "$max_attempts" >&2
        sleep "$attempt"
        attempt=$((attempt + 1))
    done

    rm -f "$tmp_out" "$tmp_err"
    return "$rc"
}
