#!/usr/bin/env python3
"""Freeze and fetch a reproducible npm source-analysis corpus without running packages."""

import argparse
import ast
import base64
import concurrent.futures
from collections import Counter
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


RANKING_COMMIT = "6ca165357f4cf1e127f38065455fc1c7680f8b16"
RANKING_URL = f"https://raw.githubusercontent.com/wooorm/npm-high-impact/{RANKING_COMMIT}/lib/top-download.js"
MAX_DOWNLOAD = 150 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_ENTRIES = 100_000
PACKAGE_NAME = re.compile(r"(?:@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+\Z")


def fetch(url, limit=MAX_DOWNLOAD):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {
        "registry.npmjs.org", "raw.githubusercontent.com", "api.npmjs.org"
    }:
        raise ValueError(f"unapproved download origin: {url}")
    for attempt in range(5):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "lpm-source-analysis-benchmark"})
            with urllib.request.urlopen(request, timeout=45) as response:
                if urllib.parse.urlsplit(response.url).hostname != parsed.hostname:
                    raise ValueError("cross-origin redirect")
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError(f"download exceeds {limit} bytes")
            return data
        except (urllib.error.URLError, TimeoutError) as error:
            if attempt == 4 or (isinstance(error, urllib.error.HTTPError) and error.code in (404, 410)):
                raise
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            time.sleep(min(2 ** attempt, 8))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def family(name):
    if name.startswith("@"):
        return name.split("/", 1)[0]
    for prefix in ("babel", "eslint", "jest", "lodash", "webpack", "rollup", "postcss"):
        if name == prefix or name.startswith((prefix + "-", prefix + ".")):
            return prefix
    return name


def select_ranked_packages(names, count, excluded, excluded_families=frozenset()):
    selected = [(rank, name) for rank, name in enumerate(names, 1)
                if name not in excluded and family(name) not in excluded_families][:count]
    if count < 1 or len(selected) != count:
        raise ValueError("count exceeds available ranking after exclusions")
    return selected


def validation_families(names, count, excluded_families):
    if count < 1:
        raise ValueError("validation count must be positive")
    sizes = Counter(family(name) for name in names if family(name) not in excluded_families)
    groups = sorted(sizes, key=lambda group: hashlib.sha256(
        ("lpm-source-validation-v2:" + group).encode()).digest())
    reachable = 1
    mask = (1 << (count + 1)) - 1
    predecessors = {}
    for group in groups:
        size = sizes[group]
        added = ((reachable << size) & mask) & ~reachable
        reachable |= added
        while added:
            bit = added & -added
            total = bit.bit_length() - 1
            predecessors[total] = (total - size, group)
            added ^= bit
        if reachable & (1 << count):
            selected = set()
            while count:
                count, group = predecessors[count]
                selected.add(group)
            return selected
    raise ValueError("cannot reserve the requested validation count using whole families")


def freeze(args):
    ranking = fetch(RANKING_URL, 2 * 1024 * 1024)
    names = ast.literal_eval(ranking.decode().split("=", 1)[1].strip())
    if len(set(names)) != len(names) or any(not PACKAGE_NAME.fullmatch(n) for n in names):
        raise ValueError("ranking contains invalid or duplicate package names")
    prior = json.loads(args.exclude_manifest.read_text())["packages"] if args.exclude_manifest else []
    excluded_families = ({family(p["name"]) for p in prior}
                         if getattr(args, "exclude_prior_families", False) else set())
    selected = select_ranked_packages(names, args.count, {package["name"] for package in prior},
                                      excluded_families)
    metadata_dir = args.cache / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)

    def pin(item):
        rank, name = item
        key = hashlib.sha256(name.encode()).hexdigest()
        metadata_path = metadata_dir / f"{key}.json"
        if metadata_path.exists():
            record = json.loads(metadata_path.read_text())
        else:
            encoded = urllib.parse.quote(name, safe="")
            metadata = json.loads(fetch(f"https://registry.npmjs.org/{encoded}/latest", 10 * 1024 * 1024))
            if metadata["name"] != name:
                raise ValueError(f"registry name mismatch: {name}")
            dist = metadata["dist"]
            integrity = dist.get("integrity")
            if not integrity:
                integrity = "sha1-" + base64.b64encode(bytes.fromhex(dist["shasum"])).decode()
            record = {
                "name": name, "version": metadata["version"],
                "tarball": dist["tarball"], "integrity": integrity,
                "resolved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "license": metadata.get("license"), "scripts": metadata.get("scripts", {}),
            }
            write_json(metadata_path, record)
        group = family(name)
        return {"rank": rank, **record, "family": group}

    packages = []
    unavailable = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        while selected:
            futures = {pool.submit(pin, item): item for item in selected}
            for future in concurrent.futures.as_completed(futures):
                rank, name = futures[future]
                try:
                    packages.append(future.result())
                except urllib.error.HTTPError as error:
                    error.close()
                    if not args.replace_unavailable or error.code not in (404, 410):
                        raise ValueError(f"metadata resolution failed for {name}: {error}") from error
                    unavailable.append({"name": name, "rank": rank, "http_status": error.code})
                if (len(packages) + len(unavailable)) % 100 == 0:
                    print(json.dumps({"resolved": len(packages), "unavailable": len(unavailable)}), flush=True)
            if len(packages) == args.count:
                break
            excluded = {p["name"] for p in prior + packages + unavailable}
            selected = select_ranked_packages(names, args.count - len(packages), excluded,
                                              excluded_families)
    packages.sort(key=lambda package: package["rank"])
    reserved = (validation_families([p["name"] for p in packages], args.validation_count,
                                   {family(p["name"]) for p in prior})
                if args.validation_count is not None else None)
    for package in packages:
        group = package["family"]
        validation = (group in reserved if reserved is not None
                      else int(hashlib.sha256(group.encode()).hexdigest()[:8], 16) % 5 == 0)
        package["split"] = "validation" if validation else "tuning"
    write_json(args.manifest, {
        "schema_version": 1, "ranking_url": RANKING_URL,
        "ranking_commit": RANKING_COMMIT, "ranking_updated_at": "2026-06-08T16:50:46Z",
        "ranking_sha256": hashlib.sha256(ranking).hexdigest(),
        "ranking_method": "npm-high-impact npmTopDownloads order, frozen upstream snapshot",
        "version_policy": "registry latest at resolved_at; immutable after freezing",
        "selection": {
            "excluded_manifest_sha256": (hashlib.sha256(args.exclude_manifest.read_bytes()).hexdigest()
                                         if args.exclude_manifest else None),
            "validation_count": args.validation_count,
            "exclude_prior_families": bool(excluded_families),
            "unavailable": sorted(unavailable, key=lambda entry: entry["rank"]),
            "split_method": ("whole-family exact subset, SHA-256 lpm-source-validation-v2 order; "
                             "prior families restricted to tuning" if reserved is not None
                             else "family SHA-256 modulo five"),
        },
        "packages": packages,
    })
    print(json.dumps({"manifest": str(args.manifest), "packages": len(packages),
                      "validation": sum(p["split"] == "validation" for p in packages)}), flush=True)


def verify_integrity(data, integrity):
    candidates = []
    strengths = {"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}
    for token in integrity.split():
        algorithm, separator, digest = token.partition("-")
        if separator and algorithm in strengths:
            candidates.append((strengths[algorithm], algorithm, digest.split("?", 1)[0]))
    if not candidates:
        raise ValueError("no supported integrity digest")
    strongest = max(item[0] for item in candidates)
    for strength, algorithm, expected in candidates:
        if strength == strongest and base64.b64encode(hashlib.new(algorithm, data).digest()).decode() == expected:
            return
    raise ValueError("tarball integrity mismatch")


def extract_archive(archive, destination):
    total = 0
    seen = {}
    root_name = None
    duplicates = 0
    with tarfile.open(archive, "r:gz") as source:
        for count, member in enumerate(source, 1):
            if count > MAX_ENTRIES:
                raise ValueError("archive entry limit exceeded")
            parts = PurePosixPath(member.name).parts
            if (not parts or PurePosixPath(member.name).is_absolute() or ".." in parts
                    or "\\" in member.name or "\x00" in member.name):
                raise ValueError(f"unsafe archive path: {member.name!r}")
            if root_name is None:
                root_name = parts[0]
            if parts[0] != root_name:
                raise ValueError("archive contains multiple roots")
            if member.isdir():
                continue
            if not member.isfile() or len(parts) < 2:
                raise ValueError(f"unsupported archive entry: {member.name!r}")
            relative = PurePosixPath(*parts[1:])
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError("archive expanded byte limit exceeded")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with source.extractfile(member) as stream:
                if relative in seen:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                    if digest.digest() != seen[relative]:
                        raise ValueError(f"conflicting duplicate archive path: {relative}")
                    duplicates += 1
                else:
                    with target.open("xb") as output:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                            output.write(chunk)
                    seen[relative] = digest.digest()
    return {"files": len(seen), "expanded_bytes": total, "identical_duplicates": duplicates}


def download(args):
    manifest = json.loads(args.manifest.read_text())
    packages = manifest["packages"]
    args.cache.mkdir(parents=True, exist_ok=True)
    failures = []

    def acquire(package):
        key = hashlib.sha256((package["name"] + "@" + package["version"] + package["integrity"]).encode()).hexdigest()
        root = args.cache / "packages" / key
        marker = root / "acquisition.json"
        if marker.exists():
            return {**package, "path": str((root / "source").resolve()), **json.loads(marker.read_text())}
        root.parent.mkdir(parents=True, exist_ok=True)
        data = fetch(package["tarball"])
        verify_integrity(data, package["integrity"])
        with tempfile.TemporaryDirectory(prefix="acquire-", dir=root.parent) as temporary:
            stage = Path(temporary)
            archive = stage / "package.tgz"
            archive.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            compressed_bytes = len(data)
            del data
            source = stage / "source"
            source.mkdir()
            stats = extract_archive(archive, source)
            record = {"tarball_sha256": digest, "compressed_bytes": compressed_bytes, **stats}
            write_json(stage / "acquisition.json", record)
            stage.rename(root)
        return {**package, "path": str((root / "source").resolve()), **record}

    records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = {pool.submit(acquire, package): package for package in packages}
        for done, future in enumerate(concurrent.futures.as_completed(pending), 1):
            package = pending[future]
            try:
                records.append(future.result())
            except Exception as error:
                failures.append({"name": package["name"], "version": package["version"], "error": str(error)})
            if done % 100 == 0 or done == len(packages):
                print(json.dumps({"finished": done, "total": len(packages), "failures": len(failures)}), flush=True)
    records.sort(key=lambda record: record["rank"])
    write_json(args.cache / "acquired.json", {"manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
                                             "packages": records, "failures": failures})
    if failures:
        raise SystemExit(f"{len(failures)} acquisition failures; see acquired.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze", "download"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--exclude-manifest", type=Path)
    parser.add_argument("--exclude-prior-families", action="store_true")
    parser.add_argument("--validation-count", type=int)
    parser.add_argument("--replace-unavailable", action="store_true")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.workers <= 16:
        parser.error("workers must be between 1 and 16")
    if args.action == "freeze":
        if args.manifest.exists():
            parser.error("manifest already exists; use a new path to refresh")
        freeze(args)
    else:
        download(args)


if __name__ == "__main__":
    main()
