"""Print when a Sigstore bundle says its signature was made.

That is the integrated time a Rekor v1 entry's SET signs, else the
earliest RFC 3161 timestamp, which is all a Rekor v2 bundle has. Nothing is
verified here: release checks use the time to stand in for a publication
time that the updater under test then checks against what it verifies.

With --epoch-range, prints the earliest and latest candidate times in
seconds since the epoch: every timestamp, since the updater uses the
earliest one that verifies, which may not be the earliest one present.
The earliest is rounded down and the latest up, so a window holding both
holds whichever the updater uses, to the fraction of a second it reads.

usage: sigstore-signed-time.py [--epoch | --epoch-range] <bundle>
"""

import base64
import datetime
import decimal
import fractions
import json
import math
import sys

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


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


def generalized_time_epoch(text):
    """Seconds since the epoch, exactly, of a DER GeneralizedTime such as
    20260513192333Z or 20260513192333.25Z, however many digits its
    fraction has."""
    whole, dot, fraction = text.rstrip("Z").partition(".")
    if dot and not (fraction.isascii() and fraction.isdigit()):
        raise ValueError(f"the GeneralizedTime {text!r} has a malformed fraction")
    seconds = datetime.datetime.strptime(whole, "%Y%m%d%H%M%S").replace(
        tzinfo=datetime.timezone.utc
    )
    elapsed = fractions.Fraction(int((seconds - EPOCH).total_seconds()))
    if fraction:
        # Parsed as a decimal, not an int: Python refuses ints over 4,300
        # digits from text.
        elapsed += fractions.Fraction(decimal.Decimal(f"0.{fraction}"))
    return elapsed


def timestamp_time(response):
    """The genTime of a DER TimeStampResp (RFC 3161), in seconds since the
    epoch."""
    _, fields, _ = read_element(response, 0)
    _, content_info = list(children(fields))[1]
    _, explicit = list(children(content_info))[1]
    _, signed_data = list(children(explicit))[0]
    _, encapsulated = list(children(signed_data))[2]
    _, content = list(children(encapsulated))[1]
    _, tst_info = list(children(content))[0]
    _, info = list(children(tst_info))[0]
    _, gen_time = list(children(info))[4]
    return generalized_time_epoch(gen_time.decode("ascii"))


def is_rekor_v2_entry(entry):
    """Whether the entry's body is the hashedrekord 0.0.2 entry Rekor v2
    writes, which has no SET."""
    try:
        body = json.loads(base64.b64decode(entry.get("canonicalizedBody") or ""))
    except ValueError:
        return False
    return (
        isinstance(body, dict)
        and body.get("kind") == "hashedrekord"
        and body.get("apiVersion") == "0.0.2"
    )


def candidate_times(bundle):
    """The integrated time the first entry's SET signs, else every
    timestamp's time, in seconds since the epoch: the entry and the times
    the updater reads."""
    material = bundle.get("verificationMaterial") or {}
    entries = material.get("tlogEntries") or []
    if entries:
        entry = entries[0] or {}
        integrated = int(entry.get("integratedTime") or 0)
        # A bundle carries the SET as its inclusion promise; an entry copied
        # from Rekor's API carries it under `verification`.
        signed = (entry.get("inclusionPromise") or {}).get("signedEntryTimestamp") or (
            entry.get("verification") or {}
        ).get("signedEntryTimestamp")
        if integrated and signed and not is_rekor_v2_entry(entry):
            return [fractions.Fraction(integrated)]
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
    earliest = math.floor(min(times))
    if mode == "--epoch-range":
        print(earliest, math.ceil(max(times)))
    elif mode == "--epoch":
        print(earliest)
    else:
        print((EPOCH + datetime.timedelta(seconds=earliest)).strftime("%Y-%m-%dT%H:%M:%SZ"))


if __name__ == "__main__":
    main(sys.argv)
