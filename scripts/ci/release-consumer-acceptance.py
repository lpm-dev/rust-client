"""Exercise published releases only inside a disposable CI account or container."""

import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import threading
import time
import urllib.request


if os.environ.get("LPM_RELEASE_ACCEPTANCE_DISPOSABLE") != "1":
    raise SystemExit("This test requires an explicitly disposable OS account.")

ROOT = Path(os.environ["LPM_RELEASE_ACCEPTANCE_OUTPUT"]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
LOGS = ROOT / "logs"
LOGS.mkdir(exist_ok=True)
WORK = ROOT / "work"
WORK.mkdir(exist_ok=True)
STABLE = "0.76.5"
OLD = "0.75.0"
NIGHTLY = "0.77.0-nightly.20260909.177.e3196a5"
TOKEN = "release-acceptance-loopback-only-token"
RESULTS = []
ENV = os.environ.copy()
for key in list(ENV):
    if key.startswith(("LPM_", "NPM_", "npm_config_", "NODE_")):
        ENV.pop(key)
ENV.update({"LPM_NO_UPDATE_CHECK": "1", "NO_COLOR": "1"})
PREFIX = Path.home() / ".lpm-release-consumer" / "npm prefix"
PREFIX.parent.mkdir(mode=0o700, exist_ok=True)
BIN = PREFIX if os.name == "nt" else PREFIX / "bin"
ENV["npm_config_prefix"] = str(PREFIX)
ENV["npm_config_cache"] = str(ROOT / "npm-cache")
ENV["PATH"] = str(BIN) + os.pathsep + ENV["PATH"]
NODE = shutil.which("node")
NPM = shutil.which("npm")
if os.name == "nt":
    NPM_COMMAND = [NODE, str(Path(NODE).parent / "node_modules/npm/bin/npm-cli.js")]
else:
    NPM_COMMAND = [NPM]
LPM = BIN / ("lpm.cmd" if os.name == "nt" else "lpm")
LPX = BIN / ("lpx.cmd" if os.name == "nt" else "lpx")


def record(name, passed, **details):
    row = {"name": name, "passed": passed, **details}
    RESULTS.append(row)
    (ROOT / "results.json").write_text(json.dumps(RESULTS, indent=2))
    print(json.dumps(row), flush=True)


def run(name, args, env=None, timeout=240, expected=0):
    started = time.monotonic()
    command = [str(arg) for arg in args]
    if os.name == "nt" and command[0].lower().endswith((".cmd", ".bat")):
        command = subprocess.list2cmdline(command)
    try:
        result = subprocess.run(
            command, env=env or ENV, cwd=WORK, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout,
            shell=isinstance(command, str),
        )
        code, output = result.returncode, result.stdout
    except subprocess.TimeoutExpired as error:
        code, output = 124, error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
    except OSError as error:
        code, output = 127, str(error)
    output = output.replace(TOKEN, "[loopback test token]")
    (LOGS / (name + ".log")).write_text(output)
    passed = code == expected if expected is not None else code != 0
    record(name, passed, code=code, seconds=round(time.monotonic() - started, 2), tail=output[-1000:])
    return code, output


def npm_install(name, version, extra=(), env=None):
    return run(name, NPM_COMMAND + ["install", "--global", "--no-audit", "--no-fund", "--foreground-scripts", "--registry=https://registry.npmjs.org", "@lpm-registry/cli@" + version, *extra], env)


def verify_version(name, executable, version, env=None):
    code, output = run(name, [executable, "--version"], env, timeout=30)
    record(name + "-matches", code == 0 and "lpm " + version in output, expected=version)


class Registry(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        authorized = self.headers.get("Authorization") == "Bearer " + TOKEN
        body = json.dumps({"username": "release-fixture", "profile_username": "release-fixture", "organizations": []} if authorized else {"error": "unauthorized"}).encode()
        self.send_response(200 if authorized else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
threading.Thread(target=server.serve_forever, daemon=True).start()
registry = "http://127.0.0.1:" + str(server.server_port)
lpm_dir = Path.home() / ".lpm"
lpm_dir.mkdir(exist_ok=True)
config = lpm_dir / "config.toml"
if config.exists():
    raise SystemExit("Disposable account unexpectedly has an LPM config; refusing to overwrite it.")
config.write_text('save-prefix = "~"\n')
config_hash = hashlib.sha256(config.read_bytes()).hexdigest()


def state_check(name, executable=LPM, env=None):
    record(name + "-config", hashlib.sha256(config.read_bytes()).hexdigest() == config_hash)
    code, output = run(name + "-auth", [executable, "whoami", "--registry", registry, "--json"], env, timeout=45)
    record(name + "-identity", code == 0 and "release-fixture" in output)


run("node-version", [NODE, "--version"])
run("npm-version", NPM_COMMAND + ["--version"])
npm_install("npm-install-old", OLD)
verify_version("npm-old-version", LPM, OLD)
run("store-loopback-credential", [LPM, "login", "--login-registry", registry, "--token", TOKEN, "--json"])
state_check("before-upgrade")
npm_install("npm-upgrade-stable", STABLE)
verify_version("npm-stable-version", LPM, STABLE)
run("npm-lpx-help", [LPX, "--help"])
state_check("after-stable-upgrade")
if os.name == "nt":
    run("windows-install-acls", ["pwsh", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $p = $env:npm_config_prefix; $items = @($env:USERPROFILE, (Split-Path $p), $p, (Join-Path $p 'lpm.cmd')); foreach ($item in $items) { $acl = Get-Acl -LiteralPath $item; [pscustomobject]@{Path=$item; Owner=$acl.Owner; Sddl=$acl.Sddl; Attributes=(Get-Item -LiteralPath $item).Attributes.ToString()} | ConvertTo-Json -Compress }"])
    for index, location in enumerate([Path.home(), PREFIX.parent, PREFIX, LPM]):
        run("windows-icacls-" + str(index), ["icacls", location])
run("npm-self-update-nightly-plan", [LPM, "self-update", "--channel", "nightly", "--refresh", "--json"])
if os.name == "nt":
    run("windows-remove-owner-rights-fixture-ace", ["icacls", PREFIX.parent, "/remove:g", "*S-1-3-4", "/T"])
    run("windows-plan-without-owner-rights-ace", [LPM, "self-update", "--channel", "nightly", "--refresh", "--json"])
    private_node = PREFIX.parent / "node-runtime"
    shutil.copytree(Path(NODE).parent, private_node)
    ENV["PATH"] = str(BIN) + os.pathsep + str(private_node) + os.pathsep + ENV["PATH"]
    run("windows-plan-with-private-node", [LPM, "self-update", "--channel", "nightly", "--refresh", "--json"])
run("npm-self-update-nightly", [LPM, "self-update", "--channel", "nightly", "--refresh"])
verify_version("npm-nightly-version", LPM, NIGHTLY)
state_check("after-nightly-upgrade")
# Explicit installation also verifies the nightly artifacts when self-update fails.
npm_install("npm-explicit-nightly", NIGHTLY)
verify_version("npm-explicit-nightly-version", LPM, NIGHTLY)
run("npm-self-update-return-stable", [LPM, "self-update", "--channel", "stable", "--refresh"])
verify_version("npm-return-stable-version", LPM, STABLE)
state_check("after-return-stable")
run("npm-uninstall", NPM_COMMAND + ["uninstall", "--global", "@lpm-registry/cli", "--no-audit", "--no-fund"])
record("npm-uninstall-removes-launcher", not LPM.exists())
npm_install("npm-reinstall-ignore-scripts", STABLE, ["--ignore-scripts"])
verify_version("npm-ignore-scripts-version", LPM, STABLE)
run("npm-ignore-scripts-lpx", [LPX, "--help"])
state_check("after-reinstall")

if os.name != "nt":
    shell_env = ENV.copy()
    shell_env["PATH"] = str(lpm_dir / "bin") + os.pathsep + shell_env["PATH"]
    installer = ROOT / "public-install.sh"
    run("fetch-public-installer", ["curl", "-fsSL", "--max-time", "30", "https://cli.lpm.dev/install", "-o", installer])
    code, _ = run("shell-install-stable", ["sh", installer], shell_env)
    if code != 0:
        run("shell-install-pinned-stable", ["sh", installer], shell_env | {"LPM_INSTALL_VERSION": "v" + STABLE})
    standalone = lpm_dir / "bin/lpm"
    verify_version("shell-stable-version", standalone, STABLE, shell_env)
    state_check("shell-existing-auth", standalone, shell_env)
    run("shell-self-update-nightly", [standalone, "self-update", "--channel", "nightly", "--refresh", "--json"], shell_env)
    verify_version("shell-nightly-version", standalone, NIGHTLY, shell_env)
    state_check("shell-after-update", standalone, shell_env)
    if platform.system() == "Darwin":
        run("shell-installer-nightly-recovery", ["sh", installer], shell_env | {"LPM_INSTALL_VERSION": "v" + NIGHTLY})
        verify_version("shell-recovered-nightly-version", standalone, NIGHTLY, shell_env)
        state_check("shell-after-recovery", standalone, shell_env)
    run("shell-self-update-stable", [standalone, "self-update", "--channel", "stable", "--refresh", "--json"], shell_env)
    verify_version("shell-return-stable-version", standalone, STABLE, shell_env)

if platform.system() == "Darwin":
    brew_env = ENV | {"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1"}
    run("brew-tap", ["brew", "tap", "lpm-dev/lpm"], brew_env, timeout=120)
    code, tap = run("brew-tap-path", ["brew", "--repo", "lpm-dev/lpm"], brew_env)
    if code == 0:
        formula = Path(tap.strip()) / "Formula/lpm.rb"
        current_formula = formula.read_bytes()
        old_formula = urllib.request.urlopen("https://raw.githubusercontent.com/lpm-dev/homebrew-lpm/eb8d05c702a729dec50511fc0745b07b457fb888/Formula/lpm.rb", timeout=30).read()
        try:
            formula.write_bytes(old_formula)
            run("brew-install-old", ["brew", "install", "lpm-dev/lpm/lpm"], brew_env, timeout=360)
        finally:
            formula.write_bytes(current_formula)
        run("brew-upgrade-stable", ["brew", "upgrade", "lpm-dev/lpm/lpm"], brew_env, timeout=360)
    run("brew-install-stable", ["brew", "install", "lpm-dev/lpm/lpm"], brew_env, timeout=360)
    code, prefix = run("brew-prefix", ["brew", "--prefix", "lpm-dev/lpm/lpm"], brew_env)
    if code == 0:
        brew_lpm = Path(prefix.strip()) / "bin/lpm"
        verify_version("brew-version", brew_lpm, STABLE, brew_env)
        run("brew-lpx-help", [brew_lpm.parent / "lpx", "--help"], brew_env)
        state_check("brew-existing-auth", brew_lpm, brew_env)
        run("brew-reinstall", ["brew", "reinstall", "lpm-dev/lpm/lpm"], brew_env, timeout=360)
        state_check("brew-after-reinstall", brew_lpm, brew_env)

server.shutdown()
failed = [row["name"] for row in RESULTS if not row["passed"]]
print(json.dumps({"checks": len(RESULTS), "failed": failed}), flush=True)
raise SystemExit(bool(failed))
