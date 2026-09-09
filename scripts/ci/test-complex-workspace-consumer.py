"""Run public npm workspace consumers and export portable frozen-install fixtures."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = {
    "name": "complex-workspace-consumer", "version": "1.0.0", "private": True,
    "workspaces": ["packages/*"],
    "catalogs": {
        "default": {"react": "18.3.1", "react-dom": "18.3.1", "esbuild": "0.25.9"},
        "modern": {"react": "19.1.1", "react-dom": "19.1.1", "rollup": "4.50.1"},
    },
    "overrides": {"is-number": "7.0.0"},
}
MEMBERS = {
    "classic": {"name": "@acceptance/classic", "version": "1.0.0", "private": True,
                "dependencies": {"react": "catalog:", "react-dom": "catalog:",
                                 "esbuild": "catalog:", "is-odd": "3.0.1"}},
    "modern": {"name": "@acceptance/modern", "version": "1.0.0", "private": True,
               "dependencies": {"react": "catalog:modern", "react-dom": "catalog:modern",
                                "rollup": "catalog:modern", "is-odd": "3.0.1"}},
}
PROBE = """
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
async function main() {
 const classic = createRequire(path.resolve('packages/classic/package.json'));
 const modern = createRequire(path.resolve('packages/modern/package.json'));
 for (const [r, version] of [[classic, '18.3.1'], [modern, '19.1.1']]) {
  const react = r('react');
  assert.equal(react.version, version);
  assert.equal(r('react-dom/server').renderToStaticMarkup(react.createElement('p', null, version)), `<p>${version}</p>`);
  assert.equal(r('is-odd')(3), true);
  const fromOdd = createRequire(r.resolve('is-odd'));
  assert.equal(fromOdd('is-number/package.json').version, '7.0.0');
 }
 const result = classic('esbuild').transformSync('const answer: number = 42', {loader: 'ts'});
 assert.ok(result.code.includes('42'));
 const bundle = await modern('rollup').rollup({input: 'virtual', plugins: [{name: 'fixture', resolveId: () => 'virtual', load: () => 'export const answer = 42'}]});
 const output = await bundle.generate({format: 'cjs'});
 assert.ok(output.output[0].code.includes('42'));
 await bundle.close();
 console.log(JSON.stringify({platform:process.platform, architecture:process.arch, node:process.version, react18:true, react19:true, esbuild:true, rollup:true, override:true}));
}
main().catch(error => {console.error(error); process.exitCode = 1});
"""
FLAGS = ["--no-security-summary", "--no-skills", "--no-editor-setup", "--no-audit-after-install"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixture")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=True)
    project = root / "project"
    if project.exists():
        raise RuntimeError("use a new output directory to keep the consumer isolated")
    if args.fixture:
        shutil.copytree(args.fixture, project)
    else:
        project.mkdir()
        (project / "package.json").write_text(json.dumps(ROOT, indent=2))
        for name, manifest in MEMBERS.items():
            directory = project / "packages" / name
            directory.mkdir(parents=True)
            (directory / "package.json").write_text(json.dumps(manifest, indent=2))
    (project / "probe.cjs").write_text(PROBE)
    test_home = root / "home"
    test_home.mkdir()
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("LPM_", "NPM_", "npm_config_", "XDG_", "ACTIONS_ID_TOKEN_"))
           and key not in {"GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "CI_JOB_TOKEN", "GITHUB_ACTIONS", "CI", "GITLAB_CI", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}}
    env.update(HOME=str(test_home), LPM_HOME=str(test_home / ".lpm"),
               XDG_CONFIG_HOME=str(test_home / ".config"), XDG_DATA_HOME=str(test_home / ".local/share"),
               XDG_CACHE_HOME=str(test_home / ".cache"), LPM_NO_UPDATE_CHECK="1",
               LPM_FORCE_FILE_AUTH="1", LPM_FORCE_FILE_VAULT="1", LPM_DISABLE_HOST_CLI_AUTH="1")
    results = []

    def run(label, command, extra_env=None):
        print("Running", label, flush=True)
        try:
            completed = subprocess.run(command, cwd=project, env=env | (extra_env or {}), capture_output=True, timeout=300)
            code = completed.returncode
            stdout, stderr = completed.stdout, completed.stderr
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr = 124, error.stdout or b"", error.stderr or b""
        (root / f"{label}.stdout.log").write_bytes(stdout)
        (root / f"{label}.stderr.log").write_bytes(stderr)
        results.append({"step": label, "exit": code})
        (root / "results.json").write_text(json.dumps(results, indent=2))
        print(label, "exit", code, flush=True)
        return code

    initial = [binary, "install", *FLAGS]
    if args.fixture:
        initial += ["--frozen-lockfile"]
    before = (project / "lpm.lock").read_bytes() if args.fixture else None
    if run("initial-install", initial, {"CI": "true"} if args.fixture else None) != 0:
        raise SystemExit(1)
    run("initial-runtime", ["node", "probe.cjs"])
    lock = (project / "lpm.lock").read_bytes()
    if before is not None:
        results.append({"step": "imported-lock-unchanged", "pass": lock == before})
    export = root / "portable-fixture"
    export.mkdir()
    for file in ["package.json", "lpm.lock", "probe.cjs"]:
        shutil.copy2(project / file, export / file)
    for name in MEMBERS:
        directory = export / "packages" / name
        directory.mkdir(parents=True)
        shutil.copy2(project / "packages" / name / "package.json", directory / "package.json")
    for label, command, ci in [
        ("warm-frozen", [binary, "install", "--frozen-lockfile", *FLAGS], False),
        ("ci-install", [binary, "ci", *FLAGS], True),
        ("offline-frozen", [binary, "install", "--offline", "--frozen-lockfile", *FLAGS], True),
    ]:
        run(label, command, {"CI": "true"} if ci else None)
        run(label + "-runtime", ["node", "probe.cjs"])
        results.append({"step": label + "-lock-unchanged", "pass": (project / "lpm.lock").read_bytes() == lock})
    results.append({"step": "lock-sha256", "value": hashlib.sha256(lock).hexdigest()})
    (root / "results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    raise SystemExit(int(any(item.get("exit", 0) != 0 or item.get("pass") is False for item in results)))


if __name__ == "__main__":
    main()
