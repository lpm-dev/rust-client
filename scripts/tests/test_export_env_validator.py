import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "export-env-validator.py"
spec = importlib.util.spec_from_file_location("env_validator_export", SCRIPT)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


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
