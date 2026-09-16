#!/usr/bin/env python3
"""Publish aggregate archive observations without payload excerpts or private locations."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import statistics

import archive_inventory
import archive_pilot
import corpus


def critical(analysis):
    return [key for key in ("obfuscated", "protestware", "credentialExfiltration")
            if analysis["supplyChain"].get(key)]


def code_groups(packages, inspections):
    groups = archive_inventory.Groups(p["sha256"] for p in packages)
    seen = {}
    for package in packages:
        key = package["sha256"]
        hashes = {f["normalized_sha256"] for f in inspections[key].get("coverage", {}).get("files", [])
                  if f.get("normalized_sha256") and f["path"] != "package.json"}
        for value in ["metadata:" + package["group"], *sorted(hashes)]:
            if value in seen:
                groups.join(key, seen[value])
            else:
                seen[value] = key
    return {p["sha256"]: groups.root(p["sha256"]) for p in packages}


def summarize(packages, scans, inspections):
    groups = code_groups(packages, inspections)
    result_rows, coverage, strata = [], [], defaultdict(Counter)
    for package in packages:
        key = package["sha256"]
        scan, inspection = scans[key], inspections[key]
        row = {"sha256": key, "name": package["name"], "version": package["version"],
               "selection_stratum": package["selection_stratum"], "code_group": groups[key],
               "status": scan["status"], "label_status": "not_independently_adjudicated"}
        group = strata[package["selection_stratum"]]
        group["selected"] += 1
        if scan["status"] == "ok":
            result = archive_pilot.sanitize(scan["result"])
            row["result"] = result
            row["critical_source_findings"] = critical(result["analysis"])
            row["scanner_peak_rss_bytes"] = scan.get("scanner_peak_rss_bytes")
            group["scanned"] += 1
            group["with_critical"] += bool(row["critical_source_findings"])
            group["with_credential_exfiltration"] += "credentialExfiltration" in row["critical_source_findings"]
            group["with_obfuscated"] += "obfuscated" in row["critical_source_findings"]
            group["zero_selected_source"] += result["analysis"]["meta"]["filesScanned"] == 0
        else:
            row["error_type"] = scan["error_type"]
            group["acquisition_or_scan_failures"] += 1
        inv = inspection.get("coverage", {})
        meta = row.get("result", {}).get("analysis", {}).get("meta", {})
        coverage.append({"sha256": key, "name": package["name"], "status": inspection["status"],
                         "file_counts": inv.get("file_counts"), "byte_counts": inv.get("byte_counts"),
                         "lifecycle_hooks": sorted(inv.get("lifecycle", {})),
                         "scanner": {k: v for k, v in meta.items() if k != "evidence"},
                         "unsupported_scripts": [f for f in inv.get("files", [])
                             if Path(f["path"]).suffix in {".sh", ".bat", ".ps1", ".cmd", ".py"}]})
        result_rows.append(row)
    ok = [r for r in result_rows if r["status"] == "ok"]
    flagged = [r for r in ok if r["critical_source_findings"]]
    metas = [r["result"]["analysis"]["meta"] for r in ok]
    timings = sorted(r["result"]["elapsed_ns"] / 1e6 for r in ok)
    summary = {
        "selected": len(packages), "scanned": len(ok), "failed": len(packages) - len(ok),
        "with_critical_source_warning": len(flagged),
        "critical_rules": dict(Counter(k for r in flagged for k in r["critical_source_findings"])),
        "code_linked_components": len(set(groups.values())),
        "components_with_critical_warning": len({r["code_group"] for r in flagged}),
        "components_with_credential_exfiltration": len({r["code_group"] for r in flagged
                                                       if "credentialExfiltration" in r["critical_source_findings"]}),
        "strata": {k: dict(v) for k, v in strata.items()},
        "coverage": {"files_scanned": sum(m["filesScanned"] for m in metas),
                     "bytes_scanned": sum(m["bytesScanned"] for m in metas),
                     "unparsed_files": sum(m["unparsedFiles"] for m in metas),
                     "packages_with_unparsed_files": sum(m["unparsedFiles"] > 0 for m in metas),
                     "packages_with_limits": sum(bool(m.get("limitReached")) for m in metas),
                     "packages_with_input_incomplete": sum(bool(m.get("inputIncomplete")) for m in metas),
                     "packages_without_selected_source": sum(m["filesScanned"] == 0 for m in metas)},
        "performance": {"scan_sum_seconds": sum(timings) / 1000,
                        "scan_median_ms": statistics.median(timings),
                        "scan_p95_ms": timings[(95 * len(timings) + 99) // 100 - 1],
                        "scan_max_ms": max(timings),
                        "max_process_rss_bytes": max(r["scanner_peak_rss_bytes"] or 0 for r in ok),
                        "acquire_and_scan_seconds": sum(r["wall_seconds"] for r in scans.values()),
                        "inspect_seconds": sum(r["wall_seconds"] for r in inspections.values())},
        "interpretation": "Archive screening counts only. Unreviewed labels, code overlap, missing stages and selection bias prevent a malware-recall estimate.",
        "grouping": "Conservative connected components of metadata groups and matching normalized source files. "
                    "Normalization ignores comments and literal values; common libraries can overmerge groups. "
                    "These are not independently attributed campaigns. Reserved archive code was not inspected.",
    }
    return result_rows, coverage, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packages = json.loads((args.private_root / "snapshot/selected.json").read_text())["packages"]
    def read_directory(name):
        return {p["sha256"]: json.loads((args.private_root / name / (p["sha256"] + ".json")).read_text()) for p in packages}
    rows, coverage, summary = summarize(packages, read_directory("scans"), read_directory("inspection"))
    reviews_path = args.output / "source-reviews.json"
    if reviews_path.exists():
        reviews = {r["archive_sha256"]: r for r in json.loads(reviews_path.read_text())["cases"]}
        for row in rows:
            if row["sha256"] in reviews:
                review = reviews[row["sha256"]]
                row["label_status"] = review["label_status"]
                row["reviewed_family"] = review["family"]
        summary["source_reviews"] = dict(Counter(r["label_status"] for r in reviews.values()))
    controls = [archive_pilot.sanitize(json.loads(line)) for line in
                (args.private_root / "control-results.jsonl").read_text().splitlines()]
    for row in controls:
        row["critical_source_findings"] = critical(row["analysis"])
    summary["controls"] = {"scanned": len(controls), "with_critical": sum(bool(r["critical_source_findings"]) for r in controls)}
    for name, value in (("results.jsonl", rows), ("control-results.jsonl", controls)):
        (args.output / name).write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in value))
    corpus.write_json(args.output / "coverage.json", coverage)
    corpus.write_json(args.output / "summary.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
