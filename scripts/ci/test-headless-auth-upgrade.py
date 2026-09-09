"""Verify the real encrypted-file credential path across a released CLI upgrade."""

import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


def main():
    old, current = [str(Path(value).resolve()) for value in sys.argv[1:]]
    token = "headless-upgrade-loopback-test-token"

    class Registry(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            authorized = self.headers.get("Authorization") == "Bearer " + token
            body = json.dumps({"username": "upgrade-fixture", "profile_username": "upgrade-fixture", "organizations": []} if authorized else {"error": "unauthorized"}).encode()
            self.send_response(200 if authorized else 401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    with tempfile.TemporaryDirectory(prefix="lpm-auth-upgrade-") as directory:
        root = Path(directory)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("LPM_", "ACCEPTANCE_", "XDG_"))}
        env.update(HOME=str(root), DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent-lpm-test-bus",
                   LPM_NO_UPDATE_CHECK="1", NO_COLOR="1")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        registry = f"http://127.0.0.1:{server.server_port}"

        def run(binary, *args):
            result = subprocess.run([binary, *args], env=env, cwd=root,
                                    text=True, capture_output=True, timeout=45)
            output = (result.stdout + result.stderr).replace(token, "[test token]")
            assert result.returncode == 0, output
            return output

        try:
            run(old, "login", "--login-registry", registry, "--token", token, "--json")
            state = root / ".lpm"
            credentials = state / ".credentials"
            key = state / ".key"
            assert credentials.is_file() and key.is_file(), "fixture must use real file storage"
            config = state / "config.toml"
            config.write_text('save-prefix = "~"\n')
            before = {path: hashlib.sha256(path.read_bytes()).digest() for path in [credentials, key, config]}
            for binary in [old, current, current, old]:
                output = run(binary, "whoami", "--registry", registry, "--json")
                assert "upgrade-fixture" in output, output
                assert all(hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in before.items())
            print("PASS: released login survives upgrade, restart, and downgrade without changing saved state")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
