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
