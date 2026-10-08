import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "relay_trust", Path(__file__).resolve().parents[1] / "relay-trust.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RelayTrustTests(unittest.TestCase):
    def test_reviewed_keys_receive_a_seven_day_validity_window(self):
        pins = ["a" * 64, "b" * 64]
        manifest = MODULE.build_manifest({"host": "relay.lpm.fyi", "spki_sha256": pins}, 1000)
        self.assertEqual(manifest["expires_at"] - manifest["issued_at"], 604800)
        self.assertEqual(manifest["spki_sha256"], pins)

    def test_wrong_host_empty_duplicate_and_malformed_keys_are_rejected(self):
        for host, pins in [
            ("attacker.example", ["a" * 64]),
            ("relay.lpm.fyi", []),
            ("relay.lpm.fyi", ["a" * 64] * 2),
            ("relay.lpm.fyi", ["A" * 64]),
            ("relay.lpm.fyi", ["invalid"]),
        ]:
            with self.subTest(host=host, pins=pins), self.assertRaises(ValueError):
                MODULE.build_manifest({"host": host, "spki_sha256": pins}, 1000)
