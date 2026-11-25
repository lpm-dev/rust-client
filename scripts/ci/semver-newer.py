"""Print yes when the first semantic version is newer than the second, by
SemVer 2.0.0 precedence, else no."""

import re
import sys


def precedence(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", version)
    if not match:
        sys.exit(f"not a semantic version: {version}")
    major, minor, patch, prerelease = match.groups()
    if prerelease is None:
        return (int(major), int(minor), int(patch), 1, ())
    # Numeric identifiers compare as numbers and rank below alphanumeric
    # ones; a longer list of equal identifiers ranks higher.
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in prerelease.split(".")
    )
    return (int(major), int(minor), int(patch), 0, identifiers)


if len(sys.argv) != 3:
    sys.exit("usage: semver-newer.py <version> <than-version>")
print("yes" if precedence(sys.argv[1]) > precedence(sys.argv[2]) else "no")
