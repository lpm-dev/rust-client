import importlib.util
import io
import json
import math
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from fractions import Fraction

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


    def test_a_set_where_rekors_api_returned_it_counts(self):
        release = bundle(FIXTURES / 'sigstore_bundles' / '21-real-lpm-release-v0.84.0.json')
        entry = release['verificationMaterial']['tlogEntries'][0]
        integrated = int(entry['integratedTime'])
        entry['verification'] = entry.pop('inclusionPromise')
        self.assertEqual(run(release, '--epoch'), str(integrated))

    def test_a_rekor_v2_entry_has_no_set_to_count(self):
        rekor_v2 = bundle(FIXTURES / 'sigstore_conformance' / 'rekor2-dsse-happy-path' / 'bundle.sigstore.json')
        entry = rekor_v2['verificationMaterial']['tlogEntries'][0]
        entry['integratedTime'] = '1700000000'
        entry['inclusionPromise'] = {'signedEntryTimestamp': 'MEUCIQD='}
        self.assertEqual(run(rekor_v2), '2026-05-13T19:23:33Z')

    def test_fractional_seconds_are_read_exactly(self):
        whole = signed_time.generalized_time_epoch('20260513192333Z')
        self.assertEqual(
            signed_time.generalized_time_epoch('20260513192333.25Z'), whole + Fraction(1, 4)
        )
        self.assertEqual(signed_time.generalized_time_epoch('19700101000001Z'), 1)
        # Twenty nines stay within the second, which a 28-digit decimal
        # would round up into the next.
        long_fraction = signed_time.generalized_time_epoch('20260513192333.' + '9' * 20 + 'Z')
        self.assertLess(long_fraction, whole + 1)
        self.assertEqual(math.floor(long_fraction), whole)
        # Longer than Python reads as an int from text.
        longest = signed_time.generalized_time_epoch('20260513192333.' + '9' * 4300 + '1Z')
        self.assertEqual(longest, whole + 1 - Fraction(9, 10**4301))

    def test_a_fraction_that_isnt_digits_is_refused(self):
        for fraction in ('1_0', '-5', ' 5', '', '٣'):
            with self.assertRaises(ValueError, msg=fraction):
                signed_time.generalized_time_epoch(f'20260513192333.{fraction}Z')

    def test_the_range_rounds_outward_so_a_fraction_past_its_end_is_caught(self):
        original = signed_time.candidate_times
        signed_time.candidate_times = lambda _bundle: [Fraction(201, 2), Fraction(801, 4)]
        try:
            self.assertEqual(run({}, '--epoch-range'), '100 201')
            self.assertEqual(run({}, '--epoch'), '100')
        finally:
            signed_time.candidate_times = original

    def test_the_range_covers_every_timestamp(self):
        rekor_v2 = bundle(FIXTURES / 'sigstore_conformance' / 'rekor2-dsse-happy-path' / 'bundle.sigstore.json')
        later = bundle(FIXTURES / 'sigstore_conformance' / 'rekor2-timestamp-with-embedded-cert' / 'bundle.sigstore.json')
        timestamps = rekor_v2['verificationMaterial']['timestampVerificationData']['rfc3161Timestamps']
        timestamps.insert(0, later['verificationMaterial']['timestampVerificationData']['rfc3161Timestamps'][0])
        earliest, latest = run(rekor_v2, '--epoch-range').split()
        self.assertEqual(int(earliest), 1754506296)
        self.assertEqual(int(latest), 1778700213)

    def test_only_the_first_entry_counts_as_the_updater_reads_it(self):
        rekor_v2 = bundle(FIXTURES / 'sigstore_conformance' / 'rekor2-dsse-happy-path' / 'bundle.sigstore.json')
        release = bundle(FIXTURES / 'sigstore_bundles' / '21-real-lpm-release-v0.84.0.json')
        rekor_v2['verificationMaterial']['tlogEntries'].append(release['verificationMaterial']['tlogEntries'][0])
        self.assertEqual(run(rekor_v2), '2026-05-13T19:23:33Z')

    def test_null_fields_read_as_absent(self):
        rekor_v2 = bundle(FIXTURES / 'sigstore_conformance' / 'rekor2-dsse-happy-path' / 'bundle.sigstore.json')
        rekor_v2['verificationMaterial']['tlogEntries'] = None
        self.assertEqual(run(rekor_v2), '2026-05-13T19:23:33Z')
        rekor_v2['verificationMaterial']['timestampVerificationData'] = None
        with self.assertRaises(SystemExit):
            run(rekor_v2)


if __name__ == '__main__':
    unittest.main()
