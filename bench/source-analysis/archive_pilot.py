#!/usr/bin/env python3
"""Inspect and scan pinned archives as data with bounded temporary extraction."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import tarfile
import time
import zipfile

import corpus
import run as runner


SCANNER_SHA256 = "c993cc8e9d02c2a8c5dc5e737545f36e80d38724fd80d53fe902092452190728"
SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
MARKERS = {
    "credential_path": re.compile(r"\.npmrc|\.aws|\.ssh|id_rsa|\.env\b|Login Data|Local State", re.I),
    "download_execute": re.compile(r"\b(?:curl|wget|https?\.get|fetch|exec|spawn|eval)\b"),
    "encrypted": re.compile(r"createDecipher|decrypt|AES|\bxor\b", re.I),
    "activation": re.compile(r"platform\(|hostname\(|process\.env|country|geolocation|locale", re.I),
    "destruction": re.compile(r"rmSync|rmdirSync|unlinkSync|rimraf|rm\s+-rf|writeFileSync"),
}
TOKEN = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|"
                   r"`(?:\\.|[^`\\])*`|\b(?:0x[\da-fA-F]+|\d+(?:\.\d+)?)\b|[A-Za-z_$][\w$]*|[^\s]")


def sha_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def normalized_hash(text):
    def tokens():
        for match in TOKEN.finditer(text):
            token = match.group()
            if token.startswith(("//", "/*")):
                continue
            if token[0] in "'\"`":
                yield "STRING"
            elif token[0].isdigit():
                yield "NUMBER"
            else:
                yield token
    return hashlib.sha256(" ".join(tokens()).encode()).hexdigest()


def source_reason(relative):
    if any(part.startswith(".") for part in relative.parts):
        return "hidden"
    if any(part in {"node_modules", "test", "__tests__"} for part in relative.parts):
        return "excluded_directory"
    if relative.name.endswith((".d.ts", ".d.mts", ".d.cts", ".map")):
        return "declaration_or_map"
    if relative.suffix not in SOURCE_SUFFIXES:
        return "unsupported_extension"
    return "selected_source"


def extract_zip(archive, destination, package):
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > corpus.MAX_ENTRIES:
            raise ValueError("archive entry limit exceeded")
        roots = []
        for member in members:
            path = PurePosixPath(member.filename)
            if (not path.parts or path.is_absolute() or ".." in path.parts
                    or "\\" in member.filename or "\x00" in member.orig_filename):
                raise ValueError("unsafe ZIP path")
            if path.name != "package.json" or member.file_size > 1024 * 1024:
                continue
            try:
                manifest = json.loads(source.read(member, pwd=b"infected"))
            except (ValueError, UnicodeError):
                continue
            if isinstance(manifest, dict) and all(manifest.get(k) == package[k] for k in ("name", "version")):
                roots.append(member.filename[:-len("package.json")])
        if len(roots) != 1:
            raise ValueError("missing or ambiguous matching ZIP package root")
        prefix = roots[0]
        total, files = 0, 0
        for member in members:
            if not member.filename.startswith(prefix) or member.is_dir():
                continue
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise ValueError("unsupported ZIP entry")
            relative = PurePosixPath(member.filename[len(prefix):])
            if not relative.parts:
                raise ValueError("empty ZIP path")
            total += member.file_size
            if total > corpus.MAX_EXPANDED:
                raise ValueError("archive expanded byte limit exceeded")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member, pwd=b"infected") as stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output, 1024 * 1024)
            files += 1
        return {"files": files, "expanded_bytes": total}


def prepare(package, downloads, destination):
    candidates = [downloads / package["sha256"]]
    candidates += [Path(p) for p in package.get("locations", []) if not p.startswith("r2://")]
    archive = next((p for p in candidates if p.is_file()), None)
    if archive is None:
        raise ValueError("archive unavailable")
    if archive.stat().st_size != package["size_bytes"] or sha_file(archive) != package["sha256"]:
        raise ValueError("archive integrity mismatch")
    if zipfile.is_zipfile(archive):
        stats = extract_zip(archive, destination, package)
    else:
        stats = corpus.extract_archive(archive, destination)
    manifest = json.loads((destination / "package.json").read_bytes())
    if any(manifest.get(k) != package[k] for k in ("name", "version")):
        raise ValueError("archive package identity mismatch")
    return stats, manifest


def inspect_tree(root, manifest):
    counts, sizes, files, snippets = Counter(), Counter(), [], []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        reason, size = source_reason(relative), path.stat().st_size
        counts[reason] += 1
        sizes[reason] += size
        record = {"path": relative.as_posix(), "bytes": size, "sha256": sha_file(path), "selection": reason}
        if size <= 4 * 1024 * 1024 and (path.suffix in SOURCE_SUFFIXES | {".sh", ".bat", ".ps1", ".cmd", ".json"}):
            text = path.read_bytes().decode("utf-8", errors="replace")
            markers = [name for name, pattern in MARKERS.items() if pattern.search(text)]
            record["markers"] = markers
            if markers and size >= 200:
                record["normalized_sha256"] = normalized_hash(text)
            if markers:
                excerpts = []
                for number, line in enumerate(text.splitlines(), 1):
                    if any(pattern.search(line) for pattern in MARKERS.values()):
                        excerpts.append({"line": number, "text": line[:1800]})
                    if len(excerpts) == 12:
                        break
                snippets.append({"path": relative.as_posix(), "markers": markers, "excerpts": excerpts})
        files.append(record)
    return {"file_counts": dict(counts), "byte_counts": dict(sizes), "files": files,
            "lifecycle": {k: v for k, v in manifest.get("scripts", {}).items()
                          if k in {"preinstall", "install", "postinstall", "prepare"}},
            "private_snippets": snippets}


def sanitize(row):
    metadata = row["analysis"].get("meta", {})
    for evidence in metadata.get("evidence", []):
        evidence.pop("excerpt", None)
    metadata.pop("urlDomains", None)
    return row


def scan_process(command, request):
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True,
                          env=dict(os.environ, RAYON_NUM_THREADS="4")) as process:
        try:
            output, errors = process.communicate(request, timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, output, errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "scan"))
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--downloads", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--temporary-root", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; preserve prior runs")
    if args.action == "scan" and (not args.binary or sha_file(args.binary) != SCANNER_SHA256):
        parser.error("frozen scanner hash mismatch")
    args.output.mkdir(parents=True)
    packages = json.loads(args.selection.read_text())["packages"]
    records = []
    for index, package in enumerate(packages, 1):
        record = {k: package[k] for k in ("sha256", "name", "version")}
        started = time.monotonic()
        try:
            if shutil.disk_usage(args.output).free < 2 * 1024**3:
                raise ValueError("less than 2 GiB extraction headroom")
            with tempfile.TemporaryDirectory(prefix="lpm-inert-archive-", dir=args.temporary_root) as temporary:
                root = Path(temporary) / "source"
                root.mkdir()
                record["acquisition"], manifest = prepare(package, args.downloads, root)
                if args.action == "inspect":
                    record["coverage"] = inspect_tree(root, manifest)
                else:
                    command = [str(args.binary.resolve())]
                    if os.uname().sysname == "Darwin":
                        command = ["/usr/bin/time", "-l", *command]
                    request = json.dumps({"name": package["name"], "version": package["version"], "path": str(root)})
                    result = scan_process(command, request + "\n")
                    rows = [json.loads(line) for line in result.stdout.splitlines()]
                    runner.validate_rows([package], rows, result.returncode)
                    record["result"] = sanitize(rows[0])
                    rss = re.search(r"(\d+)\s+maximum resident set size", result.stderr)
                    record["scanner_peak_rss_bytes"] = int(rss[1]) if rss else None
                record["status"] = "ok"
        except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, tarfile.TarError,
                subprocess.SubprocessError) as error:
            record["status"] = "failed"
            record["error_type"] = type(error).__name__
            record["error"] = str(error)[:400]
        record["wall_seconds"] = time.monotonic() - started
        corpus.write_json(args.output / (package["sha256"] + ".json"), record)
        records.append({k: record[k] for k in ("sha256", "status", "wall_seconds")})
        if index % 20 == 0 or index == len(packages):
            print(json.dumps({"processed": index, "total": len(packages),
                              "failed": sum(r["status"] == "failed" for r in records)}), flush=True)
    corpus.write_json(args.output / "run.json", {"action": args.action, "scanner_sha256": SCANNER_SHA256,
                      "selection_sha256": sha_file(args.selection), "records": records})


if __name__ == "__main__":
    main()
