import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'signing_config',
    Path(__file__).resolve().parents[1] / 'ci' / 'sigstore-rekor-v2-signing-config.py')
signing_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing_config)

STAGED = {
    'mediaType': 'application/vnd.dev.sigstore.signingconfig.v0.2+json',
    'caUrls': [{'url': 'https://fulcio.sigstore.dev', 'majorApiVersion': 1,
                'validFor': {'start': '2022-04-13T20:06:15.000Z'}, 'operator': 'sigstore.dev'}],
    'oidcUrls': [{'url': 'https://oauth2.sigstore.dev/auth', 'majorApiVersion': 1,
                  'validFor': {'start': '2022-04-13T20:06:15.000Z'}}],
    'rekorTlogUrls': [{'url': 'https://log2025-1.rekor.sigstore.dev', 'majorApiVersion': 2,
                       'validFor': {'start': '2026-01-01T00:00:00Z'}}],
    'tsaUrls': [{'url': 'https://timestamp.sigstore.dev/api/v1/timestamp', 'majorApiVersion': 1,
                 'validFor': {'start': '2025-07-04T00:00:00Z'}}],
    'rekorTlogConfig': {'selector': 'ANY'},
    'tsaConfig': {'selector': 'ANY'},
}


def checked(config):
    return json.loads(signing_config.checked_config(json.dumps(config).encode()))


class SigningConfigTests(unittest.TestCase):
    def test_sigstores_config_passes_unchanged(self):
        self.assertEqual(checked(STAGED), STAGED)

    def test_proto_field_names_are_checked_and_rewritten(self):
        config = dict(STAGED)
        config['ca_urls'] = [{'url': 'https://fulcio.sigstore.dev', 'major_api_version': 1}]
        del config['caUrls']
        self.assertEqual(checked(config)['caUrls'],
                         [{'url': 'https://fulcio.sigstore.dev', 'majorApiVersion': 1}])

    def test_a_service_outside_sigstore_dev_is_refused_under_either_name(self):
        for field in ('caUrls', 'ca_urls'):
            config = {k: v for k, v in STAGED.items() if k != 'caUrls'}
            config[field] = [{'url': 'https://fulcio.example'}]
            with self.assertRaises(SystemExit, msg=field):
                checked(config)
        for url in (
            'http://fulcio.sigstore.dev',
            'https://fulcio.sigstore.dev.example',
            'https://evilsigstore.dev',
            'https://sigstore.dev@evil.example',
            'https://evil.example/fulcio.sigstore.dev',
            'https://evil.example#.sigstore.dev',
            '',
        ):
            for field in signing_config.SERVICE_LISTS:
                config = dict(STAGED, **{field: [{'url': url}]})
                with self.assertRaises(SystemExit, msg=f'{field}: {url!r}'):
                    checked(config)
        without_url = dict(STAGED, tsaUrls=[{'majorApiVersion': 1}])
        with self.assertRaises(SystemExit):
            checked(without_url)

    def test_unknown_or_repeated_fields_are_refused(self):
        with self.assertRaises(SystemExit):
            checked(dict(STAGED, futureUrls=[]))
        with self.assertRaises(SystemExit):
            checked(dict(STAGED, ca_urls=STAGED['caUrls']))
        # The same name twice, which json.loads would collapse to the last.
        raw = json.dumps(STAGED)[:-1] + ', "caUrls": [{"url": "https://fulcio.sigstore.dev"}]}'
        with self.assertRaises(SystemExit):
            signing_config.checked_config(raw.encode())


if __name__ == '__main__':
    unittest.main()
