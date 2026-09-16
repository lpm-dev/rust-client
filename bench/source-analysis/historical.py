#!/usr/bin/env python3
"""Acquire pinned historical controls as inert source files, without running them."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile

import corpus


def extract_archive(archive, destination, package):
    prefix = package["package_root"]
    if not prefix.endswith("/") or not prefix.strip("/"):
        raise ValueError("invalid package root")
    files = 0
    total = 0
    seen = set()
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > corpus.MAX_ENTRIES:
            raise ValueError("archive entry limit exceeded")
        for member in members:
            path = PurePosixPath(member.filename)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.filename
                    or "\x00" in member.orig_filename):
                raise ValueError("unsafe archive path")
            if not member.filename.startswith(prefix) or member.is_dir():
                continue
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise ValueError("unsupported archive entry")
            relative = PurePosixPath(member.filename[len(prefix):])
            if not relative.parts or relative.is_absolute() or relative in seen:
                raise ValueError("duplicate or empty archive path")
            seen.add(relative)
            total += member.file_size
            if total > corpus.MAX_EXPANDED:
                raise ValueError("archive expanded byte limit exceeded")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member, pwd=b"infected") as stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output, 1024 * 1024)
            files += 1
    manifest = json.loads((destination / "package.json").read_text())
    if any(manifest.get(key) != package[key] for key in ("name", "version")):
        raise ValueError("archived package identity mismatch")
    return {"files": files, "expanded_bytes": total}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    args.cache.mkdir(parents=True, exist_ok=True)
    records = []
    for package in manifest["packages"]:
        digest = package["archive_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid archive SHA-256")
        archive = args.cache / (digest + ".zip")
        data = archive.read_bytes() if archive.exists() else corpus.fetch(package["archive_url"])
        if len(data) != package["archive_bytes"] or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("historical archive integrity mismatch")
        if not archive.exists():
            archive.write_bytes(data)
        del data
        root = args.cache / digest
        marker = root / "acquisition.json"
        if not marker.exists():
            with tempfile.TemporaryDirectory(prefix="historical-", dir=args.cache) as temporary:
                stage = Path(temporary)
                source = stage / "source"
                source.mkdir()
                stats = extract_archive(archive, source, package)
                corpus.write_json(stage / "acquisition.json", stats)
                stage.rename(root)
        records.append({**package, **json.loads(marker.read_text()),
                        "path": str((root / "source").resolve())})
    corpus.write_json(args.cache / "acquired.json", {
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "packages": records, "failures": [],
    })
    print(json.dumps({"packages": len(records), "cache": str(args.cache)}))


if __name__ == "__main__":
    main()
