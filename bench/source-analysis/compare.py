#!/usr/bin/env python3
"""Compare package tags and coverage from two immutable source-corpus runs."""

import argparse
from collections import Counter
import json
from pathlib import Path


def load_rows(paths):
    rows = {}
    for path in paths:
        for line in path.read_text().splitlines():
            row = json.loads(line)
            identity = (row["name"], row["version"])
            if identity in rows:
                raise ValueError(f"duplicate package result: {identity}")
            rows[identity] = row
    return rows


def tags(analysis):
    return sorted(f"{group}.{tag}" for group in ("source", "supplyChain", "manifest")
                  for tag, present in analysis[group].items() if present is True)


def coverage(analysis):
    meta = analysis["meta"]
    reasons = []
    for key in ("inputIncomplete", "limitReached", "unparsedFiles"):
        if meta.get(key):
            reasons.append(key)
    return {"complete": not reasons, "reasons": reasons,
            "files_scanned": meta["filesScanned"], "bytes_scanned": meta["bytesScanned"]}


def compare(baseline, candidate):
    if baseline.keys() != candidate.keys():
        raise ValueError("baseline and candidate package identities differ")
    rows = []
    counts = {"baseline": Counter(), "candidate": Counter()}
    complete = Counter()
    for identity in sorted(baseline):
        row = {"name": identity[0], "version": identity[1]}
        for label, inputs in (("baseline", baseline), ("candidate", candidate)):
            analysis = inputs[identity]["analysis"]
            found = tags(analysis)
            status = coverage(analysis)
            counts[label].update(found)
            complete[label] += status["complete"]
            row[label] = {"tags": found, "coverage": status}
        row["removed"] = sorted(set(row["baseline"]["tags"]) - set(row["candidate"]["tags"]))
        row["added"] = sorted(set(row["candidate"]["tags"]) - set(row["baseline"]["tags"]))
        rows.append(row)
    return {"packages": len(rows), "complete": dict(complete),
            "tag_counts": {label: dict(sorted(values.items())) for label, values in counts.items()},
            "changed_packages": sum(bool(row["removed"] or row["added"]) for row in rows)}, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, nargs="+", required=True)
    parser.add_argument("--candidate", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary, rows = compare(load_rows(args.baseline), load_rows(args.candidate))
    with args.output.open("x") as output:
        for row in rows:
            output.write(json.dumps(row) + "\n")
    with args.output.with_suffix(".summary.json").open("x") as output:
        output.write(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
