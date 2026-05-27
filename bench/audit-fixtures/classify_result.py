#!/usr/bin/env python3

import json
import re
import sys


RUNTIME_MISMATCH_PATTERNS = [
    (
        re.compile(r"engine_mismatch", re.IGNORECASE),
        "install reported an engine mismatch",
    ),
    (
        re.compile(r"node version .* does not satisfy required", re.IGNORECASE),
        "current Node runtime does not satisfy the package engine requirement",
    ),
    (
        re.compile(r"minimum Node\.js version", re.IGNORECASE),
        "current Node runtime is below the package minimum",
    ),
    (
        re.compile(r"supports a minimum Node\.js version", re.IGNORECASE),
        "current Node runtime is below the package minimum",
    ),
    (
        re.compile(r"does not provide an export named 'styleText'", re.IGNORECASE),
        "current Node runtime lacks node:util.styleText",
    ),
    (
        re.compile(r"Unexpected token 'with'", re.IGNORECASE),
        "current Node runtime lacks import-attributes support",
    ),
    (
        re.compile(r"ReferenceError: File is not defined", re.IGNORECASE),
        "current Node runtime lacks the global File API expected by the package",
    ),
    (
        re.compile(r"Node\.js v[0-9.]+ is not supported", re.IGNORECASE),
        "current Node runtime is below the package supported range",
    ),
]

ENTRYPOINT_MISMATCH_PATTERNS = [
    (
        re.compile(
            r"cannot be imported in a CommonJS module using require\(\)",
            re.IGNORECASE,
        ),
        "package root entry does not support the audit loader contract",
    ),
    (
        re.compile(r'valid "main" entry', re.IGNORECASE),
        "package metadata points at a missing or unusable root entry file",
    ),
]

UPSTREAM_INTEROP_PATTERNS = [
    (
        re.compile(r"ERR_REQUIRE_ESM", re.IGNORECASE),
        "dependency graph hit a CJS/ESM interop failure",
    ),
    (
        re.compile(r"require\(\) of ES Module", re.IGNORECASE),
        "dependency graph hit a CJS/ESM interop failure",
    ),
]


def collect_signal_text(payload):
    parts = [
        payload.get("fail_reason", ""),
        payload.get("install_json_tail", ""),
        payload.get("install_log_tail", ""),
        payload.get("smoke_log_tail", ""),
    ]

    for failure in payload.get("require_failures", []):
        parts.append(failure.get("error", ""))

    return "\n".join(part for part in parts if part)


def find_first_match(text, patterns):
    for pattern, detail in patterns:
        if pattern.search(text):
            return detail
    return None


def find_missing_peer(payload, signal_text):
    missing_modules = []
    for pattern in (
        re.compile(r"Cannot find module ['\"]([^'\"]+)['\"]", re.IGNORECASE),
        re.compile(r"Can't resolve ['\"]([^'\"]+)['\"]", re.IGNORECASE),
        re.compile(r"Cannot find package ['\"]([^'\"]+)['\"] imported from", re.IGNORECASE),
    ):
        missing_modules.extend(pattern.findall(signal_text))

    if not missing_modules:
        return None

    missing_set = set(missing_modules)
    for surface in payload.get("package_surfaces", []):
        peer_dependencies = set(surface.get("peer_dependencies", []))
        intersection = sorted(missing_set & peer_dependencies)
        if intersection:
            missing_name = intersection[0]
            return (
                "fixture-limitation",
                f"fixture omits peer dependency {missing_name} required by {surface.get('dep', 'the package')}",
            )

    return None


def find_non_runtime_surface(payload):
    for surface in payload.get("package_surfaces", []):
        surface_kind = surface.get("surface_kind")
        if surface_kind == "types-only":
            dep = surface.get("dep", "package")
            return (
                "non-runtime-package",
                f"{dep} is a types-only package with no programmatic runtime entry point",
            )
        if surface_kind == "bin-only":
            dep = surface.get("dep", "package")
            return (
                "non-runtime-package",
                f"{dep} is a bin-only package with no programmatic runtime entry point",
            )
        if surface_kind == "non-runtime":
            dep = surface.get("dep", "package")
            return (
                "non-runtime-package",
                f"{dep} has no programmatic runtime entry point at its package root",
            )

    return None


def classify(payload):
    verdict = payload.get("verdict")
    if verdict == "PASS":
        return {
            "classification": "pass",
            "classification_detail": "all audit checks passed",
        }

    if verdict == "SKIP":
        return {
            "classification": "skip-requirements",
            "classification_detail": payload.get("skip_reason") or "fixture requirements were not met",
        }

    signal_text = collect_signal_text(payload)

    if payload.get("install_exit", 0) != 0:
        runtime_detail = find_first_match(signal_text, RUNTIME_MISMATCH_PATTERNS)
        if runtime_detail:
            return {
                "classification": "runtime-mismatch",
                "classification_detail": runtime_detail,
            }
        return {
            "classification": "install-failure",
            "classification_detail": "install failed outside the known runtime-mismatch cases",
        }

    non_runtime_surface = find_non_runtime_surface(payload)
    if non_runtime_surface:
        classification, detail = non_runtime_surface
        return {
            "classification": classification,
            "classification_detail": detail,
        }

    missing_peer = find_missing_peer(payload, signal_text)
    if missing_peer:
        classification, detail = missing_peer
        return {
            "classification": classification,
            "classification_detail": detail,
        }

    entrypoint_detail = find_first_match(signal_text, ENTRYPOINT_MISMATCH_PATTERNS)
    if entrypoint_detail:
        return {
            "classification": "entrypoint-mismatch",
            "classification_detail": entrypoint_detail,
        }

    interop_detail = find_first_match(signal_text, UPSTREAM_INTEROP_PATTERNS)
    if interop_detail:
        return {
            "classification": "upstream-interop",
            "classification_detail": interop_detail,
        }

    runtime_detail = find_first_match(signal_text, RUNTIME_MISMATCH_PATTERNS)
    if runtime_detail:
        return {
            "classification": "runtime-mismatch",
            "classification_detail": runtime_detail,
        }

    if payload.get("smoke_exit") == 124:
        return {
            "classification": "smoke-failure",
            "classification_detail": "smoke command timed out",
        }

    if payload.get("smoke_exit", 0) not in (0, 99):
        return {
            "classification": "smoke-failure",
            "classification_detail": "smoke command failed after install",
        }

    return {
        "classification": "unclassified-failure",
        "classification_detail": "failure did not match a known audit category",
    }


def main():
    payload = json.load(sys.stdin)
    json.dump(classify(payload), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()