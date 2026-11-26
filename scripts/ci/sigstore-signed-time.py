"""Print when a Sigstore bundle says its signature was made.

That is Rekor v1's integrated time when the entry carries a SET, else the
earliest RFC 3161 timestamp, which is all a Rekor v2 bundle has. Nothing is
verified here: release checks use the time to stand in for a publication
time that the updater under test then checks against what it verifies.

With --epoch-range, prints the earliest and latest candidate times in
seconds since the epoch: every timestamp, since the updater uses the
earliest one that verifies, which may not be the earliest one present. A
window holding both holds whichever the updater uses.

usage: sigstore-signed-time.py [--epoch | --epoch-range] <bundle>
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


def candidate_times(bundle):
    """The integrated time a SET signs, else every timestamp's time."""
    material = bundle.get("verificationMaterial") or {}
    for entry in material.get("tlogEntries") or []:
        integrated = int(entry.get("integratedTime") or 0)
        promise = entry.get("inclusionPromise") or (entry.get("verification") or {}).get(
            "inclusionPromise"
        )
        if integrated and promise:
            return [datetime.datetime.fromtimestamp(integrated, datetime.timezone.utc)]
    timestamps = (material.get("timestampVerificationData") or {}).get("rfc3161Timestamps") or []
    times = [timestamp_time(base64.b64decode(t["signedTimestamp"])) for t in timestamps]
    if not times:
        sys.exit("the bundle has neither a Rekor SET nor an RFC 3161 timestamp")
    return times


def main(argv):
    usage = "usage: sigstore-signed-time.py [--epoch | --epoch-range] <bundle>"
    mode = argv[1] if len(argv) == 3 and argv[1] in ("--epoch", "--epoch-range") else None
    paths = argv[2:] if mode else argv[1:]
    if len(paths) != 1:
        sys.exit(usage)
    with open(paths[0], encoding="utf-8") as file:
        times = candidate_times(json.load(file))
    if mode == "--epoch-range":
        print(int(min(times).timestamp()), int(max(times).timestamp()))
    elif mode == "--epoch":
        print(int(min(times).timestamp()))
    else:
        print(min(times).strftime("%Y-%m-%dT%H:%M:%SZ"))


if __name__ == "__main__":
    main(sys.argv)
