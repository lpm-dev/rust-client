import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "export-env-validator.py"
spec = importlib.util.spec_from_file_location("env_validator_export", SCRIPT)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = [
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml",
            "crates/lpm-env/Cargo.toml", "crates/lpm-env/src/lib.rs",
            "crates/lpm-env-wasm/Cargo.toml", "crates/lpm-env-wasm/src/lib.rs",
            "scripts/export-env-validator.py",
        ]
        for name in self.inputs:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.com")
        self.git("remote", "add", "origin", "https://github.com/lpm-dev/rust-client.git")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.bindgen = self.root / "bindgen"
        self.bindgen.write_text("#!/usr/bin/env python3\nimport pathlib, sys\n"
            "if '--version' in sys.argv: print('wasm-bindgen 0.2.122')\n"
            "else:\n p = pathlib.Path(sys.argv[sys.argv.index('--out-dir')+1])\n"
            " (p/'validator_bg.wasm').write_bytes(b'wasm-fixture')\n"
            " (p/'validator.js').write_text('function initSync() {}\\nasync function __wbg_init() {}')\n")
        self.bindgen.chmod(0o755)
        self.output = self.root / "output"

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def export(self):
        argv = [str(SCRIPT), "--target-dir", str(self.root / "target"),
                "--wasm-bindgen", str(self.bindgen), "--output", str(self.output)]
        with patch.object(exporter, "__file__", str(self.root / "scripts/export-env-validator.py")), patch.object(sys, "argv", argv):
            exporter.main()

    def test_export_records_revision_all_build_inputs_and_artifact_hashes(self):
        self.export()
        provenance = json.loads((self.output / "provenance.json").read_text())
        self.assertEqual(provenance.get("revision"), self.git("rev-parse", "HEAD"))
        self.assertEqual(provenance.get("repository"), "https://github.com/lpm-dev/rust-client.git")
        for name in self.inputs:
            self.assertEqual(provenance["sources"].get(name), hashlib.sha256((self.root / name).read_bytes()).hexdigest())
        for name in ["validator.js", "wasm.js"]:
            self.assertEqual(provenance["artifacts"][name], hashlib.sha256((self.output / name).read_bytes()).hexdigest())

    def test_dirty_build_input_refuses_export_without_overwriting_output(self):
        self.output.mkdir()
        sentinel = self.output / "validator.js"
        sentinel.write_text("preserve")
        (self.root / "Cargo.toml").write_text("changed")
        with self.assertRaisesRegex(SystemExit, "clean"):
            self.export()
        self.assertEqual(sentinel.read_text(), "preserve")


class DecoderTests(unittest.TestCase):
    def test_portable_decoder_preserves_every_byte_without_buffer(self):
        for binary in [b"", bytes(range(256)), bytes(range(256)) * 4096]:
            with self.subTest(size=len(binary)):
                source = exporter.decoder_module(binary)
                program = source + '\nglobalThis.Buffer = undefined;\nimport { createHash } from "node:crypto";\nconsole.log(JSON.stringify({size: wasmBytes().length, hash: createHash("sha256").update(wasmBytes()).digest("hex")}));\n'
                result = subprocess.run(["node", "--input-type=module"], input=program, text=True, capture_output=True, check=True)
                self.assertEqual(json.loads(result.stdout), {"size": len(binary), "hash": hashlib.sha256(binary).hexdigest()})


if __name__ == "__main__":
    unittest.main()
