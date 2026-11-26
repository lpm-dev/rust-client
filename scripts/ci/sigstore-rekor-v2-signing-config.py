"""Write Sigstore's signing config that signs through Rekor v2.

Reads Sigstore's TUF repository and writes `signing_config_rekor_v2.v0.2.json`
while Sigstore stages Rekor v2 in it, else the main `signing_config.v0.2.json`.
Only TUF's target hashes are checked, not its signatures: the config just
lists service URLs, and LPM verifies what gets signed against its own trust
root.

usage: sigstore-rekor-v2-signing-config.py <output>
"""

import hashlib
import json
import sys
import urllib.request

REPOSITORY = "https://tuf-repo-cdn.sigstore.dev"
CONFIGS = ("signing_config_rekor_v2.v0.2.json", "signing_config.v0.2.json")


def fetch(path):
    request = urllib.request.Request(f"{REPOSITORY}/{path}", headers={"User-Agent": "lpm-ci"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: sigstore-rekor-v2-signing-config.py <output>")
    timestamp = json.loads(fetch("timestamp.json"))
    snapshot_version = timestamp["signed"]["meta"]["snapshot.json"]["version"]
    snapshot = json.loads(fetch(f"{snapshot_version}.snapshot.json"))
    targets_version = snapshot["signed"]["meta"]["targets.json"]["version"]
    targets = json.loads(fetch(f"{targets_version}.targets.json"))["signed"]["targets"]
    for name in CONFIGS:
        if name not in targets:
            continue
        digest = targets[name]["hashes"]["sha256"]
        config = fetch(f"targets/{digest}.{name}")
        if hashlib.sha256(config).hexdigest() != digest:
            sys.exit(f"{name} does not match the hash Sigstore's targets list")
        with open(argv[1], "wb") as file:
            file.write(config)
        print(name)
        return
    sys.exit("Sigstore's TUF repository lists no v0.2 signing config")


if __name__ == "__main__":
    main(sys.argv)
