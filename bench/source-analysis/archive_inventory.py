#!/usr/bin/env python3
"""Freeze archive provenance and reserve related packages before detector evaluation."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

import corpus


SEED = "lpm-archive-pilot-v1"
FOCUS = {
    "credential_files": r"\.npmrc|\.aws|\.ssh|id_rsa|credential.file|\.env\b|wallet.*file",
    "install_download": r"(?:download|fetch|curl|wget).*(?:execut|payload|binary|shell)",
    "encrypted_activation": r"decrypt|encrypted|aes[- ]|\bxor\b",
    "destructive_files": r"delet|destruct|wipe|ransom|overwrit",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def order(value):
    return digest((SEED + ":" + value).encode())


class Groups:
    def __init__(self, keys):
        self.parents = dict.fromkeys(keys)

    def root(self, key):
        trail = []
        while self.parents[key] is not None:
            trail.append(key)
            key = self.parents[key]
        for child in trail:
            self.parents[child] = key
        return key

    def join(self, left, right):
        a, b = sorted((self.root(left), self.root(right)))
        if a != b:
            self.parents[b] = a


def grouped(records):
    groups = Groups(record["sha256"] for record in records)
    seen = {}
    for record in records:
        keys = [("name", corpus.family(record["name"]))]
        for source in record["provenance"]:
            if source.get("advisory_id"):
                keys.append(("advisory", source["advisory_id"]))
        keys += [("evidence-source", value) for value in record.get("evidence_hashes", [])]
        for key in keys:
            if key in seen:
                groups.join(record["sha256"], seen[key])
            else:
                seen[key] = record["sha256"]
    return {record["sha256"]: groups.root(record["sha256"]) for record in records}


def consolidate(records):
    by_hash = {}
    for record in records:
        key = record["sha256"]
        if not re.fullmatch(r"[a-f0-9]{64}", key):
            raise ValueError("invalid archive hash")
        if key in by_hash:
            prior = by_hash[key]
            if any(prior[field] != record[field] for field in ("name", "version", "size_bytes")):
                raise ValueError("same bytes have conflicting package identity or size")
            for field in ("provenance", "locations", "focus_hints", "evidence_hashes"):
                prior[field].extend(record[field])
            for field in ("review_path", "review_sha256"):
                if field in record:
                    prior[field] = record[field]
        else:
            by_hash[key] = record
    result = sorted(by_hash.values(), key=lambda r: r["sha256"])
    for record in result:
        for field in ("locations", "focus_hints", "evidence_hashes"):
            record[field] = sorted(set(record[field]))
    return result


def load_records(root):
    records, snapshots = [], []
    for source in ("datadog", "openssf"):
        path = root / source / "npm" / f"{source}-malicious-npm-archive.manifest.json"
        raw = path.read_bytes()
        manifest = json.loads(raw)
        snapshots.append({"source": source, "sha256": digest(raw), "bytes": len(raw),
                          "updated_at": manifest.get("updatedAt"), "records": len(manifest["samples"])})
        for sample in manifest["samples"]:
            location = sample["storagePath"]
            locations = [location]
            local = root / source / "npm" / "tarballs" / Path(location).name
            if local.is_file():
                locations.insert(0, str(local))
            records.append({
                "name": sample["name"], "version": sample["version"],
                "sha256": sample["sha256"], "size_bytes": sample["sizeBytes"],
                "locations": locations, "focus_hints": [], "evidence_hashes": [],
                "provenance": [{"source": source, "source_id": sample["id"],
                                "advisory_id": sample.get("advisoryId"),
                                "advisory_url": sample.get("advisoryUrl"),
                                "behaviors": sample.get("behaviors", []),
                                "reasons": sample.get("reasons", []),
                                "label_status": "external_archive_label_unreviewed"}],
            })
    metadata_paths = sorted((root / "lpm/npm/metadata").glob("*.json"))
    metadata_hashes = []
    for path in metadata_paths:
        raw = path.read_bytes()
        metadata_hashes.append((path.name, digest(raw)))
        sample = json.loads(raw)
        review_path = Path(sample["reviewer"]["reviewPath"])
        review_raw = review_path.read_bytes()
        review = json.loads(review_raw).get("ai", {})
        narrative = json.dumps({key: review.get(key) for key in (
            "rationale", "evidenceFor", "attackSurface", "attackNarrative")}).lower()
        hints = [key for key, pattern in FOCUS.items() if re.search(pattern, narrative)]
        citations = review.get("sourceCitations", [])
        evidence_hashes = sorted({c["sourceSha256"] for c in citations
                                  if c.get("sourceSha256") and c.get("path") != "package.json"})
        records.append({
            **sample["package"], "sha256": sample["archive"]["sha256"],
            "size_bytes": sample["archive"]["sizeBytes"],
            "locations": [sample["archive"]["localPath"]],
            "focus_hints": hints, "evidence_hashes": evidence_hashes,
            "review_path": str(review_path), "review_sha256": digest(review_raw),
            "provenance": [{"source": "lpm", "source_id": sample["identity"],
                            "metadata_sha256": digest(raw),
                            "threat_type": sample["verdict"]["threatType"],
                            "intent_class": sample["verdict"]["intentClass"],
                            "model_confidence": sample["verdict"]["confidence"],
                            "label_status": "model_label_unconfirmed"}],
        })
    snapshots.append({"source": "lpm", "records": len(metadata_paths),
                      "metadata_index_sha256": digest(json.dumps(metadata_hashes).encode())})
    return consolidate(records), snapshots


def assign_splits(records, prior_names):
    groups = grouped(records)
    prior_groups = {groups[r["sha256"]] for r in records if corpus.family(r["name"]) in prior_names}
    for record in records:
        group = groups[record["sha256"]]
        record["group"] = group
        record["split"] = ("prior" if group in prior_groups else
                           "reserved" if int(order(group)[:8], 16) % 5 == 0 else "pilot_pool")


def select_pilot(records, count=400):
    selected, used_groups = [], set()
    candidates = sorted((r for r in records if r["split"] == "pilot_pool"),
                        key=lambda r: order(r["sha256"]))

    def take(predicate, quota, stratum):
        if quota <= 0:
            return 0
        taken = 0
        for record in candidates:
            if record["group"] in used_groups or not predicate(record):
                continue
            selected.append({**record, "selection_stratum": stratum})
            used_groups.add(record["group"])
            taken += 1
            if taken == quota:
                break
        return taken

    for hint in ("encrypted_activation", "destructive_files", "credential_files", "install_download"):
        take(lambda r: hint in r["focus_hints"], 60, hint)
    take(lambda r: any(p["source"] == "openssf" for p in r["provenance"]), 60, "openssf")
    take(lambda r: any(p["source"] == "datadog" for p in r["provenance"]),
         count - len(selected), "datadog")
    if len(selected) != count:
        raise ValueError("insufficient independent metadata groups for pilot")
    return selected


def public_record(record):
    return {key: record[key] for key in (
        "name", "version", "sha256", "size_bytes", "group", "split", "provenance",
        "focus_hints", "selection_stratum") if key in record}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--prior-manifest", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.private_output.exists():
        parser.error("snapshot directory exists")
    records, snapshots = load_records(args.root)
    prior_names = {corpus.family(p["name"]) for path in args.prior_manifest
                   for p in json.loads(path.read_text())["packages"]}
    assign_splits(records, prior_names)
    selected = select_pilot(records)
    corpus.write_json(args.private_output / "inventory.json", {"sources": snapshots, "packages": records})
    corpus.write_json(args.private_output / "selected.json", {"packages": selected})
    corpus.write_json(args.public_output / "selection.json", {"seed": SEED, "packages": [public_record(r) for r in selected]})
    summary = {"sources": snapshots, "unique_archives": len(records),
               "unique_versions": len({(r["name"], r["version"]) for r in records}),
               "metadata_groups": len({r["group"] for r in records}),
               "split_archives": dict(Counter(r["split"] for r in records)),
               "selection_strata": dict(Counter(r["selection_stratum"] for r in selected)),
               "inventory_sha256": digest((args.private_output / "inventory.json").read_bytes()),
               "reserved_index_sha256": digest("\n".join(r["sha256"] for r in records if r["split"] == "reserved").encode()),
               "grouping_limits": "Names/scopes, advisories and cited source hashes are provisional groups. "
                   "Code-similarity closure is required before reserved cases can become independent validation."}
    corpus.write_json(args.public_output / "inventory-summary.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
