import json
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("classify_result.py")


def classify(payload):
    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


class ClassifyResultTest(unittest.TestCase):
    def test_marks_install_engine_errors_as_runtime_mismatch(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 1,
                "fail_reason": "install exited 1",
                "install_json_tail": '{"error_code":"engine_mismatch","message":"node version 18.19.1 does not satisfy required >=20.0.0"}',
                "smoke_exit": 99,
            }
        )

        self.assertEqual(result["classification"], "runtime-mismatch")
        self.assertIn("engine mismatch", result["classification_detail"])

    def test_marks_types_only_packages_as_non_runtime(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 0,
                "require_fail": 1,
                "smoke_exit": 1,
                "package_surfaces": [
                    {
                        "dep": "@types/node",
                        "surface_kind": "types-only",
                        "peer_dependencies": [],
                    }
                ],
            }
        )

        self.assertEqual(result["classification"], "non-runtime-package")
        self.assertIn("types-only", result["classification_detail"])

    def test_marks_missing_peer_as_fixture_limitation(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 0,
                "require_fail": 1,
                "smoke_exit": 1,
                "smoke_log_tail": "Error: Cannot find module 'react'",
                "package_surfaces": [
                    {
                        "dep": "zustand",
                        "surface_kind": "runtime",
                        "peer_dependencies": ["react"],
                    }
                ],
            }
        )

        self.assertEqual(result["classification"], "fixture-limitation")
        self.assertIn("react", result["classification_detail"])

    def test_marks_missing_imported_peer_as_fixture_limitation(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 0,
                "require_fail": 1,
                "smoke_exit": 1,
                "smoke_log_tail": "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'react' imported from /tmp/example.mjs",
                "package_surfaces": [
                    {
                        "dep": "zustand",
                        "surface_kind": "runtime",
                        "peer_dependencies": ["react"],
                    }
                ],
            }
        )

        self.assertEqual(result["classification"], "fixture-limitation")
        self.assertIn("react", result["classification_detail"])

    def test_marks_entrypoint_contract_issues(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 0,
                "require_fail": 1,
                "smoke_exit": 1,
                "smoke_log_tail": 'Error: Vitest cannot be imported in a CommonJS module using require(). Please use "import" instead.',
            }
        )

        self.assertEqual(result["classification"], "entrypoint-mismatch")

    def test_marks_upstream_esm_interop_issues(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 0,
                "require_fail": 1,
                "smoke_exit": 1,
                "smoke_log_tail": "Error [ERR_REQUIRE_ESM]: require() of ES Module /tmp/example.js not supported.",
            }
        )

        self.assertEqual(result["classification"], "upstream-interop")

    def test_marks_runtime_api_gaps_as_runtime_mismatch(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 0,
                "require_fail": 1,
                "smoke_exit": 1,
                "smoke_log_tail": "SyntaxError: The requested module 'node:util' does not provide an export named 'styleText'",
            }
        )

        self.assertEqual(result["classification"], "runtime-mismatch")

    def test_marks_runtime_support_messages_as_runtime_mismatch(self):
        result = classify(
            {
                "verdict": "FAIL",
                "install_exit": 0,
                "smoke_exit": 1,
                "smoke_log_tail": "Node.js v18.19.1 is not supported by Astro! Please upgrade Node.js to a supported version: \">=18.20.8\"",
            }
        )

        self.assertEqual(result["classification"], "runtime-mismatch")


if __name__ == "__main__":
    unittest.main()