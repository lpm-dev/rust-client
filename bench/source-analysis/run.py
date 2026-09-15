#!/usr/bin/env python3
"""Run an immutable scanner binary over a selected frozen corpus split."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def validate_rows(packages, rows, exit_code):
    expected = [(package["name"], package["version"]) for package in packages]
    actual = [(row.get("name"), row.get("version")) for row in rows]
    if exit_code or actual != expected or any(not isinstance(row.get("analysis"), dict) for row in rows):
        raise ValueError("scanner failed or output identities do not match the selected corpus")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquired", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--split", choices=("tuning", "validation", "all"), required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    if args.threads < 1 or (args.limit is not None and args.limit < 1):
        parser.error("threads and limit must be positive")
    acquisition = json.loads(args.acquired.read_text())
    if acquisition["failures"]:
        parser.error("acquisition has failures; resolve them before scanning")
    packages = [p for p in acquisition["packages"] if args.split == "all" or p["split"] == args.split]
    if args.limit:
        packages = packages[:args.limit]
    if not packages or args.threads < 1:
        parser.error("empty selection or invalid thread count")
    if args.output.exists():
        parser.error("output already exists; preserve previous runs")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    requests = "".join(json.dumps({key: p[key] for key in ("name", "version", "path")}) + "\n" for p in packages)
    environment = dict(os.environ, RAYON_NUM_THREADS=str(args.threads))
    command = [str(args.binary.resolve())]
    if os.uname().sysname == "Darwin":
        command = ["/usr/bin/time", "-l", *command]
    started = time.monotonic()
    with args.output.open("x") as output, args.output.with_suffix(".stderr").open("x") as errors:
        result = subprocess.run(command, input=requests, text=True, stdout=output, stderr=errors,
                                env=environment, timeout=1800, check=False)
    metadata = {
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "manifest_sha256": acquisition["manifest_sha256"],
        "split": args.split, "count": len(packages), "threads": args.threads,
        "wall_seconds": time.monotonic() - started, "exit_code": result.returncode,
    }
    args.output.with_suffix(".meta.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = [json.loads(line) for line in args.output.read_text().splitlines()]
    validate_rows(packages, rows, result.returncode)
    print(json.dumps(metadata), flush=True)


if __name__ == "__main__":
    main()
