#!/usr/bin/env python3
"""Fail unless the crates that depend on fancy-regex are exactly the reviewed ones.

fancy-regex backtracks, so a pattern it runs on untrusted input can take
exponential time. Cargo.lock is the resolved graph, so it shows every crate that
reaches fancy-regex, directly or not. A new dependent, a new version of one, or
one that's gone changes this list and needs a review of what its patterns run on.
"""
import argparse
from pathlib import Path
import sys
import tomllib

REVIEWED = {
    ('zxcvbn', '3.1.1'): (
        'lpm-env-backup: three fixed repeat patterns, (.+)\\1+ and its lazy forms, '
        'over at most the first 100 characters of a passphrase the person types; '
        'opening a backup never estimates strength'
    ),
    ('jsonschema', '0.46.5'): 'lpm-cli: on main before this check read Cargo.lock; review open',
    ('termwiz', '0.23.3'): 'on main before this check read Cargo.lock, outside the default graph; review open',
}


def dependents(lockfile):
    """The (name, version) of every locked package that depends on fancy-regex."""
    packages = tomllib.loads(lockfile).get('package', [])
    found = set()
    for package in packages:
        for dependency in package.get('dependencies', []):
            if dependency.split(' ')[0] == 'fancy-regex':
                found.add((package['name'], package['version']))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lockfile', type=Path, default=Path(__file__).resolve().parents[1] / 'Cargo.lock')
    args = parser.parse_args()
    found = dependents(args.lockfile.read_text())
    unreviewed = sorted(found - REVIEWED.keys())
    gone = sorted(REVIEWED.keys() - found)
    for name, version in unreviewed:
        print(f'::error::{name} {version} depends on fancy-regex and isn\'t reviewed. '
              'Review what its patterns run on, then add it to REVIEWED in scripts/check-fancy-regex-dependents.py.')
    for name, version in gone:
        print(f'::error::{name} {version} no longer depends on fancy-regex. Remove it from REVIEWED.')
    if unreviewed or gone:
        return 1
    print('fancy-regex dependents match the reviewed list: ' + ', '.join(f'{name} {version}' for name, version in sorted(found)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
