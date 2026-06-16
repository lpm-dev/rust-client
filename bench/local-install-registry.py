#!/usr/bin/env python3
"""Deterministic local registry fixture for install performance benchmarks."""

from __future__ import annotations

import argparse
import base64
from collections import deque
import gzip
import hashlib
import io
import json
import os
import signal
import sys
import tarfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


DEFAULT_PACKAGES = 96
DEFAULT_ROOTS = 16
DEFAULT_VERSIONS = 32
DEFAULT_TARBALL_KIB = 512
LATEST_TIME = "2025-01-01T00:00:00.000Z"


class Fixture:
    def __init__(
        self,
        base_url: str,
        package_count: int,
        root_count: int,
        version_count: int,
        tarball_kib: int,
    ) -> None:
        if package_count < 1:
            raise ValueError("--packages must be >= 1")
        if root_count < 1:
            raise ValueError("--roots must be >= 1")
        if root_count > package_count:
            raise ValueError("--roots cannot exceed --packages")
        if version_count < 1:
            raise ValueError("--versions must be >= 1")
        if tarball_kib < 1:
            raise ValueError("--tarball-kib must be >= 1")

        self.base_url = base_url.rstrip("/")
        self.package_count = package_count
        self.root_count = root_count
        self.version_count = version_count
        self.tarball_kib = tarball_kib
        self.latest_version = f"1.0.{version_count - 1}"
        self.names = [package_name(i) for i in range(package_count)]
        self.root_names = self.names[:root_count]
        self.metadata: dict[str, bytes] = {}
        self.metadata_etags: dict[str, str] = {}
        self.tarballs: dict[tuple[str, str], bytes] = {}
        self._build()

    def _build(self) -> None:
        for index, name in enumerate(self.names):
            latest_tarball = make_tarball(
                name,
                self.latest_version,
                dependencies_for(index, self.names, self.root_count),
                self.tarball_kib,
            )
            self.tarballs[(name, self.latest_version)] = latest_tarball
            metadata = self._metadata_for(index, name, latest_tarball)
            metadata_bytes = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode()
            self.metadata[name] = metadata_bytes
            digest = hashlib.sha256(metadata_bytes).hexdigest()[:24]
            self.metadata_etags[name] = f'"lpm-local-{digest}"'

    def _metadata_for(self, index: int, name: str, latest_tarball: bytes) -> dict[str, Any]:
        versions: dict[str, Any] = {}
        times: dict[str, str] = {}
        latest_deps = dependencies_for(index, self.names, self.root_count)

        for version_index in range(self.version_count):
            version = f"1.0.{version_index}"
            is_latest = version == self.latest_version
            integrity = sri(latest_tarball) if is_latest else placeholder_sri(name, version)
            versions[version] = {
                "name": name,
                "version": version,
                "dist": {
                    "tarball": f"{self.base_url}{tarball_path(name, version)}",
                    "integrity": integrity,
                },
                "dependencies": latest_deps if is_latest else {},
            }
            times[version] = LATEST_TIME

        return {
            "name": name,
            "description": "local deterministic install benchmark fixture",
            "dist-tags": {"latest": self.latest_version},
            "versions": versions,
            "time": times,
            "modified": LATEST_TIME,
            "latestVersion": self.latest_version,
        }

    def metadata_response(self, name: str) -> tuple[int, bytes, str | None]:
        metadata = self.metadata.get(name)
        if metadata is None:
            return 404, json.dumps({"error": f"unknown package {name}"}).encode(), None
        return 200, metadata, self.metadata_etags[name]

    def tarball_response(self, name: str, version: str) -> tuple[int, bytes]:
        tarball = self.tarballs.get((name, version))
        if tarball is None:
            return 404, b"missing tarball"
        return 200, tarball

    def batch_response(self, requested: list[str], deep: bool) -> bytes:
        names = reachable_closure(requested, self.names, self.root_count) if deep else requested
        lines = []
        for name in names:
            metadata = self.metadata.get(name)
            if metadata is None:
                continue
            lines.append(
                json.dumps(
                    {"name": name, "metadata": json.loads(metadata)},
                    separators=(",", ":"),
                )
            )
        return ("\n".join(lines) + ("\n" if lines else "")).encode()


def package_name(index: int) -> str:
    return f"lpm-bench-pkg-{index:04d}"


def dependencies_for(index: int, names: list[str], root_count: int) -> dict[str, str]:
    deps: dict[str, str] = {}
    for offset in (root_count, root_count + 1):
        child_index = index + offset
        if child_index < len(names):
            child = names[child_index]
            deps[child] = "^1.0.0"
    return deps


def reachable_closure(seed_names: list[str], all_names: list[str], root_count: int) -> list[str]:
    by_name = {name: index for index, name in enumerate(all_names)}
    seen: set[str] = set()
    queue = deque(name for name in seed_names if name in by_name)
    ordered: list[str] = []
    while queue:
        name = queue.popleft()
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
        index = by_name[name]
        queue.extend(dependencies_for(index, all_names, root_count).keys())
    return ordered


def tarball_path(name: str, version: str) -> str:
    quoted = urllib.parse.quote(name, safe="@")
    return f"/tarballs/{quoted}/-/{quoted}-{version}.tgz"


def sri(data: bytes) -> str:
    digest = hashlib.sha512(data).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def placeholder_sri(name: str, version: str) -> str:
    digest = hashlib.sha512(f"{name}@{version}".encode()).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def deterministic_payload(name: str, version: str, kib: int) -> bytes:
    target = kib * 1024
    chunks: list[bytes] = []
    total = 0
    counter = 0
    while total < target:
        digest = hashlib.sha256(f"{name}@{version}:{counter}".encode()).hexdigest()
        chunk = f"module.exports['{counter}']='{digest}';\n".encode()
        chunks.append(chunk)
        total += len(chunk)
        counter += 1
    return b"".join(chunks)[:target]


def make_tarball(name: str, version: str, dependencies: dict[str, str], tarball_kib: int) -> bytes:
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w") as tar:
        package_json = json.dumps(
            {
                "name": name,
                "version": version,
                "main": "index.js",
                "dependencies": dependencies,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        append_tar_file(tar, "package/package.json", package_json, 0o644)
        append_tar_file(tar, "package/index.js", b"module.exports = require('./payload');\n", 0o644)
        append_tar_file(tar, "package/payload.js", deterministic_payload(name, version, tarball_kib), 0o644)

    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as gz:
        gz.write(raw_tar.getvalue())
    return compressed.getvalue()


def append_tar_file(tar: tarfile.TarFile, path: str, content: bytes, mode: int) -> None:
    info = tarfile.TarInfo(path)
    info.size = len(content)
    info.mode = mode
    info.mtime = 0
    tar.addfile(info, io.BytesIO(content))


def write_project(path: str, root_count: int) -> None:
    dependencies = {package_name(i): "^1.0.0" for i in range(root_count)}
    package_json = {
        "name": "lpm-local-install-benchmark",
        "version": "1.0.0",
        "private": True,
        "scripts": {"noop": "true"},
        "dependencies": dependencies,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(package_json, f, indent=2, sort_keys=True)
        f.write("\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "LpmLocalBenchRegistry/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "quiet", True):
            return
        super().log_message(fmt, *args)

    @property
    def fixture(self) -> Fixture:
        return getattr(self.server, "fixture")

    def do_GET(self) -> None:
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if path == "/-/npm/v1/keys":
            self.send_json(200, {"keys": []})
            return
        if path.startswith("/api/registry/"):
            self.send_metadata(path.removeprefix("/api/registry/"))
            return
        if path.startswith("/tarballs/"):
            self.send_tarball(path)
            return
        name = path.lstrip("/")
        if name:
            self.send_metadata(name)
            return
        self.send_json(200, {"ok": True})

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path != "/api/registry/batch-metadata":
            self.send_bytes(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body or b"{}")
            packages = [str(name) for name in payload.get("packages", [])]
            deep = bool(payload.get("deep", False))
        except json.JSONDecodeError:
            self.send_bytes(400, b"invalid json", "text/plain")
            return
        self.send_bytes(200, self.fixture.batch_response(packages, deep), "application/x-ndjson")

    def send_metadata(self, name: str) -> None:
        status, body, etag = self.fixture.metadata_response(name)
        if status == 200 and etag and self.headers.get("if-none-match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.end_headers()
            return
        headers = {"ETag": etag} if etag else None
        self.send_bytes(status, body, "application/json", headers)

    def send_tarball(self, path: str) -> None:
        parts = path.split("/")
        if len(parts) < 5 or parts[-2] != "-":
            self.send_bytes(404, b"bad tarball path", "text/plain")
            return
        name = parts[-3]
        filename = parts[-1]
        prefix = f"{name}-"
        if not filename.startswith(prefix) or not filename.endswith(".tgz"):
            self.send_bytes(404, b"bad tarball filename", "text/plain")
            return
        version = filename[len(prefix) : -len(".tgz")]
        status, body = self.fixture.tarball_response(name, version)
        self.send_bytes(status, body, "application/octet-stream")

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        self.send_bytes(status, json.dumps(payload, separators=(",", ":")).encode(), "application/json")

    def send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str | None] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                if value is not None:
                    self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def serve(args: argparse.Namespace) -> None:
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    host, port = httpd.server_address[:2]
    base_url = f"http://{host}:{port}"
    httpd.fixture = Fixture(base_url, args.packages, args.roots, args.versions, args.tarball_kib)
    httpd.quiet = args.quiet

    if args.ready_file:
        ready_dir = os.path.dirname(os.path.abspath(args.ready_file))
        os.makedirs(ready_dir, exist_ok=True)
        tmp = f"{args.ready_file}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "url": base_url,
                    "packages": args.packages,
                    "roots": args.roots,
                    "versions": args.versions,
                    "tarball_kib": args.tarball_kib,
                    "latest_version": httpd.fixture.latest_version,
                },
                f,
                sort_keys=True,
            )
            f.write("\n")
        os.replace(tmp, args.ready_file)

    def shutdown(_signum: int, _frame: Any) -> None:
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    sys.stderr.write(f"local install registry listening on {base_url}\n")
    sys.stderr.flush()
    httpd.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--packages", type=int, default=DEFAULT_PACKAGES)
    parser.add_argument("--roots", type=int, default=DEFAULT_ROOTS)
    parser.add_argument("--versions", type=int, default=DEFAULT_VERSIONS)
    parser.add_argument("--tarball-kib", type=int, default=DEFAULT_TARBALL_KIB)
    parser.add_argument("--ready-file")
    parser.add_argument("--write-project")
    parser.add_argument("--quiet", action=argparse.BooleanOptionalAction, default=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.write_project:
        write_project(args.write_project, args.roots)
        return 0
    serve(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
