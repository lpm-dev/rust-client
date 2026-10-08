"""Build a short-lived relay key list from operator-reviewed keys."""

import argparse
import json
import re
import time
from pathlib import Path


def build_manifest(approved, issued_at):
    if set(approved) != {"host", "spki_sha256"}:
        raise ValueError("The approved key file has unsupported fields.")
    pins = approved["spki_sha256"]
    if approved["host"] != "relay.lpm.fyi":
        raise ValueError("The approved key file must name relay.lpm.fyi.")
    if (
        not isinstance(pins, list)
        or not 1 <= len(pins) <= 16
        or any(not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins)
        or len(set(pins)) != len(pins)
    ):
        raise ValueError("The approved key file must contain 1 to 16 distinct SPKI SHA-256 hashes.")
    return {
        "schema_version": 1,
        "host": "relay.lpm.fyi",
        "issued_at": issued_at,
        "expires_at": issued_at + 7 * 24 * 60 * 60,
        "spki_sha256": pins,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("approved", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = build_manifest(json.loads(args.approved.read_text()), int(time.time()))
    args.output.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
