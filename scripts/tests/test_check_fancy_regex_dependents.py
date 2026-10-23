import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'check', Path(__file__).resolve().parents[1] / 'check-fancy-regex-dependents.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def lockfile(packages):
    entries = []
    for name, version, dependencies in packages:
        lines = ['[[package]]', f'name = "{name}"', f'version = "{version}"']
        if dependencies:
            lines.append('dependencies = [' + ', '.join(f'"{dependency}"' for dependency in dependencies) + ']')
        entries.append('\n'.join(lines))
    return '\n\n'.join(entries) + '\n'


REVIEWED_GRAPH = [
    ('fancy-regex', '0.18.0', ['regex-automata']),
    ('zxcvbn', '3.1.1', ['fancy-regex', 'regex']),
    ('jsonschema', '0.46.5', ['fancy-regex 0.18.0']),
    ('termwiz', '0.23.3', ['fancy-regex 0.11.0']),
    ('lpm-env-backup', '0.81.0', ['zxcvbn']),
]


class CheckFancyRegexDependentsTests(unittest.TestCase):
    def run_check(self, packages):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Cargo.lock'
            path.write_text(lockfile(packages))
            with patch('sys.argv', ['check', '--lockfile', str(path)]), patch('builtins.print'):
                return check.main()

    def test_dependents_include_versioned_and_unversioned_references(self):
        self.assertEqual(
            check.dependents(lockfile(REVIEWED_GRAPH)),
            {('zxcvbn', '3.1.1'), ('jsonschema', '0.46.5'), ('termwiz', '0.23.3')})

    def test_the_reviewed_graph_passes(self):
        self.assertEqual(self.run_check(REVIEWED_GRAPH), 0)

    def test_a_new_dependent_fails(self):
        self.assertEqual(self.run_check(REVIEWED_GRAPH + [('regex-lite-wrapper', '1.0.0', ['fancy-regex'])]), 1)

    def test_a_new_version_of_a_reviewed_dependent_fails(self):
        graph = [entry if entry[0] != 'zxcvbn' else ('zxcvbn', '3.2.0', ['fancy-regex']) for entry in REVIEWED_GRAPH]
        self.assertEqual(self.run_check(graph), 1)

    def test_a_reviewed_dependent_that_is_gone_fails(self):
        self.assertEqual(self.run_check([entry for entry in REVIEWED_GRAPH if entry[0] != 'termwiz']), 1)

    def test_the_repository_lockfile_matches_the_reviewed_list(self):
        with patch('sys.argv', ['check']), patch('builtins.print'):
            self.assertEqual(check.main(), 0)


if __name__ == '__main__':
    unittest.main()
