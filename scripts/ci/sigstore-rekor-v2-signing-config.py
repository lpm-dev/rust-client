"""Write Sigstore's signing config that signs through Rekor v2.

Reads Sigstore's TUF repository and writes `signing_config_rekor_v2.v0.2.json`
while Sigstore stages Rekor v2 in it, else the main `signing_config.v0.2.json`.
Only TUF's target hashes are checked, not its signatures, so the config is
rebuilt from its checked fields, and refused unless every service it names
is an HTTPS URL on sigstore.dev: cosign sends the job's OIDC token to the
certificate authority it names. LPM verifies what gets signed against its
own trust root.

usage: sigstore-rekor-v2-signing-config.py <output>
"""

import hashlib
import json
import sys
import urllib.parse
import urllib.request

REPOSITORY = "https://tuf-repo-cdn.sigstore.dev"
CONFIGS = ("signing_config_rekor_v2.v0.2.json", "signing_config.v0.2.json")

# Protobuf JSON accepts each field under its JSON name or its proto name,
# and cosign parses the config that way.
CONFIG_FIELDS = {
    "mediaType": ("mediaType", "media_type"),
    "caUrls": ("caUrls", "ca_urls"),
    "oidcUrls": ("oidcUrls", "oidc_urls"),
    "rekorTlogUrls": ("rekorTlogUrls", "rekor_tlog_urls"),
    "tsaUrls": ("tsaUrls", "tsa_urls"),
    "rekorTlogConfig": ("rekorTlogConfig", "rekor_tlog_config"),
    "tsaConfig": ("tsaConfig", "tsa_config"),
}
SERVICE_LISTS = ("caUrls", "oidcUrls", "rekorTlogUrls", "tsaUrls")
SERVICE_FIELDS = {
    "url": ("url",),
    "majorApiVersion": ("majorApiVersion", "major_api_version"),
    "validFor": ("validFor", "valid_for"),
    "operator": ("operator",),
}
VALID_FOR_FIELDS = {"start": ("start",), "end": ("end",)}
SELECTOR_FIELDS = {"selector": ("selector",), "count": ("count",)}


def canonical_fields(value, fields, what):
    """`value` with every field under its JSON name; unknown fields, and a
    field given under both names, are refused as cosign would read them."""
    if not isinstance(value, dict):
        sys.exit(f"the signing config's {what} is not an object")
    spelling = {name: canonical for canonical, names in fields.items() for name in names}
    result = {}
    for name, field in value.items():
        canonical = spelling.get(name)
        if canonical is None:
            sys.exit(f"the signing config's {what} has an unknown field `{name}`")
        if canonical in result:
            sys.exit(f"the signing config's {what} gives `{canonical}` twice")
        result[canonical] = field
    return result


def unique_keys(pairs):
    """A JSON object's fields, refusing one given twice: json.loads would
    keep the last, while another parser may keep the first."""
    fields = {}
    for name, value in pairs:
        if name in fields:
            sys.exit(f"the signing config gives `{name}` twice")
        fields[name] = value
    return fields


def checked_config(config):
    """The config rebuilt from its checked fields only. Every service it
    names must be an HTTPS URL on sigstore.dev: cosign sends the job's OIDC
    token to the certificate authority it names."""
    fields = canonical_fields(
        json.loads(config, object_pairs_hook=unique_keys), CONFIG_FIELDS, "top level"
    )
    for name in SERVICE_LISTS:
        services = []
        for service in fields.get(name) or []:
            service = canonical_fields(service, SERVICE_FIELDS, name)
            url = urllib.parse.urlsplit(service.get("url") or "")
            host = url.hostname or ""
            if url.scheme != "https" or not (host == "sigstore.dev" or host.endswith(".sigstore.dev")):
                sys.exit(f"the signing config names a service outside sigstore.dev: {service.get('url')}")
            if "validFor" in service:
                service["validFor"] = canonical_fields(service["validFor"], VALID_FOR_FIELDS, "validFor")
            services.append(service)
        fields[name] = services
    for name in ("rekorTlogConfig", "tsaConfig"):
        if name in fields:
            fields[name] = canonical_fields(fields[name], SELECTOR_FIELDS, name)
    return json.dumps(fields, indent=2).encode()


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
            file.write(checked_config(config))
        print(name)
        return
    sys.exit("Sigstore's TUF repository lists no v0.2 signing config")


if __name__ == "__main__":
    main(sys.argv)
