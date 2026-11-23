import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "test-executable.py"
SPEC = importlib.util.spec_from_file_location("test_executable", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def artifact(name, kinds, test, executable):
    return json.dumps(
        {
            "reason": "compiler-artifact",
            "target": {"name": name, "kind": kinds},
            "profile": {"test": test},
            "executable": executable,
        }
    )


class TestExecutableTests(unittest.TestCase):
    def test_the_library_s_test_executable_is_named_as_cargo_wrote_it(self):
        path = '/tmp/odd "quoted" back\\slash/target/debug/deps/lpm_vault-0123'
        messages = [
            "not json lpm_vault",
            artifact("lpm_vault", ["lib"], False, None),
            artifact("lpm_vault_helper", ["lib"], True, "/elsewhere"),
            artifact("lpm_vault", ["bin"], True, "/a/binary/test"),
            artifact("lpm_vault", ["lib"], True, path),
            json.dumps({"reason": "build-finished", "success": True}),
        ]
        self.assertEqual(MODULE.test_executable(messages, "lpm_vault"), path)

    def test_a_build_without_one_says_so(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "lpm_vault"],
            input=artifact("lpm_vault", ["lib"], False, None) + "\n",
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cargo built no lpm_vault test executable", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
