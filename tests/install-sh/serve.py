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
"""

import http.server
import os
import socketserver
import sys


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
