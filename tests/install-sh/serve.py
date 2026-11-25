#!/usr/bin/env python3
"""
Minimal fixture-backed HTTP server for the install.sh harness.

Usage: serve.py <fixture-dir> <port>

Serves files literally from <fixture-dir>. Any path that doesn't have
a corresponding file in the fixture dir returns 404. Suppresses access
logs so the harness output stays clean.

Special-case: a fixture file named `*.NOCL` is served WITHOUT a
Content-Length header so the harness can exercise the streaming-cap
path (mid-stream guard). The `.NOCL` suffix is stripped from the URL.

A fixture file named `*.STATUS` holds an HTTP status code; the URL
without that suffix answers with that status and an empty body.

POST /ticket-lookup stands in for Apple's notarization ticket database.
Each request's record name is appended to `ticket-requests`; the nth
request is answered with line n of `ticket-outcomes` (default `issued`):
`issued` returns the ticket in `ticket-issued` (default
`fixture-notarization-ticket`), `other` returns a different ticket,
`notfound`/`deleted`/`throttled`/`denied` return those record states,
`deletedstring`, `emptyerror` and `longerror` return malformed `deleted`
and `serverErrorCode` fields, `withnull` adds JSON nulls to an issued
ticket, `extrarecord` answers with two records, `emptyticket` with an empty
ticket,
`wrongrecord` answers about another record, `garbage` returns a non-JSON
page, `huge` streams 256 KiB without a length, `drop` closes the
connection, and a number answers with that status (a 3xx redirects to
`/redirected-ticket`).
"""

import base64
import http.server
import json
import os
import socketserver
import sys

DEFAULT_TICKET = b"fixture-notarization-ticket"


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <fixture-dir> <port>", file=sys.stderr)
        return 2
    fixture_dir = sys.argv[1]
    port = int(sys.argv[2])

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — stdlib API
            rel = self.path.lstrip("/").split("?", 1)[0]
            local = os.path.join(fixture_dir, rel)
            nocl = os.path.join(fixture_dir, rel + ".NOCL")
            status = os.path.join(fixture_dir, rel + ".STATUS")
            if os.path.isfile(status):
                with open(status, encoding="ascii") as f:
                    code = int(f.read().strip())
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if os.path.isfile(local):
                with open(local, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if os.path.isfile(nocl):
                with open(nocl, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                # Manual chunked encoding: <hex-len>\r\n<bytes>\r\n
                # followed by the zero-length terminator.
                self.wfile.write(f"{len(body):x}\r\n".encode("ascii"))
                self.wfile.write(body)
                self.wfile.write(b"\r\n0\r\n\r\n")
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802 — stdlib API
            if self.path != "/ticket-lookup":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            record_name = request["records"][0]["recordName"]
            requests = os.path.join(fixture_dir, "ticket-requests")
            with open(requests, "a", encoding="utf-8") as f:
                f.write(record_name + "\n")
            with open(requests, encoding="utf-8") as f:
                index = len(f.read().splitlines()) - 1
            outcome = "issued"
            outcomes = os.path.join(fixture_dir, "ticket-outcomes")
            if os.path.isfile(outcomes):
                with open(outcomes, encoding="utf-8") as f:
                    lines = f.read().split()
                if index < len(lines):
                    outcome = lines[index]
            if outcome == "drop":
                self.close_connection = True
                self.connection.shutdown(2)
                return
            if outcome.isdigit():
                self.send_response(int(outcome))
                if outcome.startswith("3"):
                    self.send_header("Location", "/redirected-ticket")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if outcome == "huge":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                chunk = b"x" * 65536
                for _ in range(4):
                    self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
                return
            if outcome == "garbage":
                self.answer(200, b"<html>captive portal</html>")
                return
            record = {"recordName": record_name}
            if outcome in ("issued", "other", "deleted", "deletedstring", "withnull", "extrarecord", "emptyticket"):
                ticket = DEFAULT_TICKET
                issued = os.path.join(fixture_dir, "ticket-issued")
                if os.path.isfile(issued):
                    with open(issued, "rb") as f:
                        ticket = f.read()
                if outcome == "other":
                    ticket = b"another-release-ticket"
                if outcome == "emptyticket":
                    ticket = b""
                record.update(
                    recordType="DeveloperIDTicket",
                    fields={
                        "signedTicket": {
                            "value": base64.b64encode(ticket).decode("ascii"),
                            "type": "BYTES",
                        }
                    },
                    deleted="yes" if outcome == "deletedstring" else outcome == "deleted",
                )
                if outcome == "withnull":
                    record.update(deleted=None, zoneID=None)
            elif outcome == "wrongrecord":
                record.update(recordName="2/2/" + "0" * 40, fields={})
            else:
                codes = {
                    "notfound": "NOT_FOUND",
                    "throttled": "THROTTLED",
                    "denied": "ACCESS_DENIED",
                    "emptyerror": "",
                    "longerror": "A" * 41,
                }
                record.update(reason="fixture", serverErrorCode=codes[outcome])
            records = [record, record] if outcome == "extrarecord" else [record]
            self.answer(200, json.dumps({"records": records}).encode("utf-8"))

        def answer(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:  # noqa: N802
            return

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), Handler) as httpd:
        print(f"ready on {port}", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
