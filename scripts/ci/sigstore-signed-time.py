"""Print when a Sigstore bundle says its signature was made.

That is Rekor v1's integrated time when the entry carries a SET, else the
earliest RFC 3161 timestamp, which is all a Rekor v2 bundle has. Nothing is
verified here: release checks use the time to stand in for a publication
time that the updater under test then checks against what it verifies.

usage: sigstore-signed-time.py [--epoch] <bundle>
"""

import base64
import datetime
import json
import sys


def read_element(data, offset):
    """One DER element at `offset`: its tag, contents, and the next offset."""
    tag = data[offset]
    first = data[offset + 1]
    offset += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def children(contents):
    offset = 0
    while offset < len(contents):
        tag, value, offset = read_element(contents, offset)
        yield tag, value


def timestamp_time(response):
    """The genTime of a DER TimeStampResp (RFC 3161), as a UTC datetime."""
    _, fields, _ = read_element(response, 0)
    _, content_info = list(children(fields))[1]
    _, explicit = list(children(content_info))[1]
    _, signed_data = list(children(explicit))[0]
    _, encapsulated = list(children(signed_data))[2]
    _, content = list(children(encapsulated))[1]
    _, tst_info = list(children(content))[0]
    _, info = list(children(tst_info))[0]
    _, gen_time = list(children(info))[4]
    text = gen_time.decode("ascii").rstrip("Z").split(".")[0]
    return datetime.datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc)


def signed_time(bundle):
    material = bundle["verificationMaterial"]
    for entry in material.get("tlogEntries", []):
        integrated = int(entry.get("integratedTime") or 0)
        if integrated and entry.get("inclusionPromise"):
            return datetime.datetime.fromtimestamp(integrated, datetime.timezone.utc)
    timestamps = material.get("timestampVerificationData", {}).get("rfc3161Timestamps", [])
    times = [timestamp_time(base64.b64decode(t["signedTimestamp"])) for t in timestamps]
    if not times:
        sys.exit("the bundle has neither a Rekor SET nor an RFC 3161 timestamp")
    return min(times)


def main(argv):
    epoch = argv[1:2] == ["--epoch"]
    paths = argv[2:] if epoch else argv[1:]
    if len(paths) != 1:
        sys.exit("usage: sigstore-signed-time.py [--epoch] <bundle>")
    with open(paths[0], encoding="utf-8") as file:
        time = signed_time(json.load(file))
    print(int(time.timestamp()) if epoch else time.strftime("%Y-%m-%dT%H:%M:%SZ"))


if __name__ == "__main__":
    main(sys.argv)
