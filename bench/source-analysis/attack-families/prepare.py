#!/usr/bin/env python3
"""Prepare inert, hash-pinned incident reconstructions for the frozen evaluation."""

import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_reference(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in {
            "raw.githubusercontent.com", "gist.githubusercontent.com"
        } or parsed.username or parsed.password or parsed.port not in {None, 443}):
        raise ValueError("unapproved reference origin")
    with urllib.request.build_opener(NoRedirect()).open(url, timeout=45) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("reference exceeds byte limit")
    return data


class DiffHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.files = {}
        self.current = None
        self.row = None
        self.capture = None
        self.depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        classes = dict(attrs).get("class", "").split()
        if self.capture:
            if tag not in {"br", "input", "img", "hr", "meta", "link"}:
                self.depth += 1
            return
        if "d2h-file-wrapper" in classes:
            self.current = None
        kind = None
        if tag == "span" and "d2h-file-name" in classes:
            kind = "file"
        elif tag == "td" and "d2h-code-linenumber" not in classes:
            self.row = next((prefix for name, prefix in (
                ("d2h-info", "@"), ("d2h-ins", "+"),
                ("d2h-del", "-"), ("d2h-cntx", " ")
            ) if name in classes), None)
        elif self.current and "d2h-code-line-ctn" in classes:
            kind = self.row
        elif self.current and self.row == "@" and "d2h-code-line" in classes:
            kind = "@"
        if kind:
            self.capture, self.depth, self.parts = kind, 1, []

    def handle_data(self, data):
        if self.capture:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if not self.capture:
            return
        self.depth -= 1
        if self.depth:
            return
        text = "".join(self.parts)
        if self.capture == "file":
            path = PurePosixPath(text)
            if (not text.startswith("package/") or ".." in path.parts
                    or "\\" in text or "\x00" in text or len(path.parts) < 2):
                raise ValueError("unsafe diff path")
            self.current = path.relative_to("package").as_posix()
            if self.current in self.files:
                raise ValueError("duplicate diff file")
            self.files[self.current] = []
        else:
            self.files[self.current].append((self.capture, text))
        self.capture = None


def apply_hunks(original, rows):
    if len(rows) == 1 and rows[0][0] == "@" and rows[0][1].strip() == "File without changes":
        return original
    if not rows:
        raise ValueError("missing diff hunks")
    old = original.splitlines()
    output, cursor, index = [], 0, 0
    while index < len(rows):
        kind, header = rows[index]
        match = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", header)
        if kind != "@" or not match:
            raise ValueError("invalid diff hunk header")
        start, before, new_start, after = map(int, match.groups())
        offset = max(start - 1, 0)
        if offset < cursor or offset > len(old):
            raise ValueError("overlapping or out-of-range diff hunk")
        output.extend(old[cursor:offset])
        cursor = offset
        if len(output) != max(new_start - 1, 0):
            raise ValueError("diff new-line offset mismatch")
        index += 1
        consumed = produced = 0
        while index < len(rows) and rows[index][0] != "@":
            kind, text = rows[index]
            if kind not in {" ", "+", "-"}:
                raise ValueError("invalid diff row")
            if kind in {" ", "-"}:
                if cursor >= len(old) or old[cursor] != text:
                    raise ValueError("diff context does not match clean archive")
                cursor += 1
                consumed += 1
            if kind in {" ", "+"}:
                output.append(text)
                produced += 1
            index += 1
        if (consumed, produced) != (before, after):
            raise ValueError("diff hunk line-count mismatch")
    output.extend(old[cursor:])
    return "\n".join(output) + "\n"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def inventory(root):
    return [{"path": p.relative_to(root).as_posix(), "bytes": p.stat().st_size,
             "sha256": sha256(p.read_bytes())}
            for p in sorted(root.rglob("*")) if p.is_file()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controls", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; preserve previous inputs")
    study = Path(__file__).resolve().parent
    references = json.loads((study / "references.json").read_text())
    controls = json.loads(args.controls.read_text())
    if controls["failures"]:
        parser.error("control acquisition has failures")
    if controls["manifest_sha256"] != sha256((study / "controls.json").read_bytes()):
        parser.error("control manifest hash mismatch")
    paths = {(p["name"], p["version"]): Path(p["path"]) for p in controls["packages"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="prepare-", dir=args.output.parent) as temporary:
        stage = Path(temporary)
        reference_dir = stage / "references"
        reference_dir.mkdir()
        for reference in references:
            data = fetch_reference(reference["url"])
            if len(data) != reference["bytes"] or sha256(data) != reference["sha256"]:
                raise ValueError("reference integrity mismatch")
            (reference_dir / reference["file"]).write_bytes(data)
        roots = {}
        eslint = stage / "eslint-downloader"
        shutil.copytree(paths[("eslint-scope", "3.7.1")], eslint)
        manifest = json.loads((eslint / "package.json").read_text())
        manifest["version"] = "3.7.2"
        manifest.setdefault("scripts", {})["postinstall"] = "node ./lib/build.js"
        write_json(eslint / "package.json", manifest)
        with (eslint / "lib/build.js").open("xb") as output:
            output.write((reference_dir / "eslint-build.js").read_bytes())
        roots["eslint-downloader"] = (eslint, "eslint-scope", "3.7.2")

        credential = stage / "eslint-credential-payload"
        credential.mkdir()
        shutil.copyfile(reference_dir / "eslint-pastebin.js", credential / "pastebin.js")
        write_json(credential / "package.json", {
            "name": "evaluation-eslint-credential-payload", "version": "0.0.0", "private": True,
        })
        roots["eslint-credential-payload"] = (credential, "evaluation-eslint-credential-payload", "0.0.0")

        ua = stage / "ua-parser-installer"
        shutil.copytree(paths[("ua-parser-js", "0.7.28")], ua)
        diff = DiffHTML()
        diff.feed((reference_dir / "ua-parser-diff.html").read_text())
        expected = {"package.json", "preinstall.js", "preinstall.sh", "preinstall.bat", "src/ua-parser.js"}
        if set(diff.files) != expected or diff.capture:
            raise ValueError("unexpected or incomplete incident diff")
        for name, rows in diff.files.items():
            path = ua / name
            original = path.read_text() if path.exists() else ""
            changed = apply_hunks(original, rows)
            if changed != original:
                path.write_text(changed)
        manifest = json.loads((ua / "package.json").read_text())
        if manifest["name"] != "ua-parser-js" or manifest["version"] != "0.7.29":
            raise ValueError("reconstructed identity mismatch")
        roots["ua-parser-installer"] = (ua, "ua-parser-js", "0.7.29")

        records = []
        for rank, (case_id, (root, name, version)) in enumerate(roots.items(), 1):
            records.append({
                "rank": rank, "case_id": case_id, "name": name, "version": version,
                "split": "validation", "path": str((args.output / root.name).resolve()),
                "files": inventory(root),
            })
        public_manifest = [{k: v for k, v in r.items() if k != "path"} for r in records]
        write_json(stage / "inputs.json", public_manifest)
        write_json(stage / "acquired.json", {
            "manifest_sha256": sha256((stage / "inputs.json").read_bytes()),
            "packages": records, "failures": [],
        })
        stage.rename(args.output)
    print(json.dumps({"cases": len(records), "output": str(args.output)}))


if __name__ == "__main__":
    main()
