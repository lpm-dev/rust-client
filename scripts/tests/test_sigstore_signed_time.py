import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'signed_time', ROOT / 'scripts' / 'ci' / 'sigstore-signed-time.py')
signed_time = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signed_time)

FIXTURES = ROOT / 'crates' / 'lpm-cli' / 'tests' / 'fixtures'


def bundle(path):
    return json.loads(path.read_text())


def run(value, *flags):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'bundle.sigstore.json'
        path.write_text(json.dumps(value))
        output = io.StringIO()
        with redirect_stdout(output):
            signed_time.main(['sigstore-signed-time.py', *flags, str(path)])
        return output.getvalue().strip()


class SigstoreSignedTimeTests(unittest.TestCase):
    def test_a_rekor_v1_bundle_is_signed_at_its_integrated_time(self):
        release = bundle(FIXTURES / 'sigstore_bundles' / '21-real-lpm-release-v0.84.0.json')
        integrated = int(release['verificationMaterial']['tlogEntries'][0]['integratedTime'])
        self.assertEqual(run(release, '--epoch'), str(integrated))

    def test_a_rekor_v2_bundle_is_signed_at_its_timestamp(self):
        rekor_v2 = bundle(FIXTURES / 'sigstore_conformance' / 'rekor2-dsse-happy-path' / 'bundle.sigstore.json')
        self.assertEqual(run(rekor_v2), '2026-05-13T19:23:33Z')

    def test_an_integrated_time_without_a_set_does_not_count(self):
        case = bundle(FIXTURES / 'sigstore_conformance' / 'intoto-with-custom-trust-root' / 'bundle.sigstore.json')
        entry = case['verificationMaterial']['tlogEntries'][0]
        del entry['inclusionPromise']
        entry['integratedTime'] = '1700000000'
        self.assertEqual(run(case), '2023-02-01T00:00:00Z')

    def test_a_bundle_with_no_signed_time_is_refused(self):
        rekor_v2 = bundle(FIXTURES / 'sigstore_conformance' / 'rekor2-dsse-happy-path' / 'bundle.sigstore.json')
        del rekor_v2['verificationMaterial']['timestampVerificationData']
        with self.assertRaises(SystemExit):
            run(rekor_v2)


if __name__ == '__main__':
    unittest.main()
