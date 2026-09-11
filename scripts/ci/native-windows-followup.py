"""Repeat native Windows findings using the previous run's exact binary."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
root = Path(args.output).resolve()
root.mkdir(parents=True)
home = root / 'home'
home.mkdir()
env = {k: v for k, v in os.environ.items()
       if not k.startswith(('LPM_', 'NPM_', 'npm_config_', 'XDG_', 'ACTIONS_ID_TOKEN_'))
       and k not in {'GITHUB_TOKEN', 'GH_TOKEN', 'GITLAB_TOKEN', 'CI_JOB_TOKEN', 'GITHUB_ACTIONS',
                     'CI', 'GITLAB_CI', 'CI_JOB_JWT', 'CI_JOB_JWT_V2', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'}}
env.update(HOME=str(home), USERPROFILE=str(home), LPM_HOME=str(home / '.lpm'),
           XDG_CONFIG_HOME=str(home / '.config'), XDG_DATA_HOME=str(home / '.local/share'),
           XDG_CACHE_HOME=str(home / '.cache'), LPM_NO_UPDATE_CHECK='1', NO_COLOR='1',
           LPM_FORCE_FILE_AUTH='1', LPM_FORCE_FILE_VAULT='1', LPM_DISABLE_HOST_CLI_AUTH='1',
           LPM_SECURITY_POLICY_PATH=str(home / '.lpm/security-policy.toml'))
results = []
(root / 'binary.json').write_text(json.dumps({'binary': binary, 'sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest()}))


def run(label, cwd, command, timeout=120):
    with (root / f'{label}.stdout.log').open('wb') as out, (root / f'{label}.stderr.log').open('wb') as err:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err, creationflags=0x200)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=15)
            child.wait(timeout=15)
            code = 124
    result = {'label': label, 'argv': command, 'exit': code}
    results.append(result)
    (root / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(result), flush=True)
    return code


project = root / 'global-project'
project.mkdir()
(project / 'package.json').write_text(json.dumps({'name': 'qa-global', 'version': '1.0.0', 'private': True}))
with urllib.request.urlopen('https://registry.npmjs.org/cowsay/1.6.0', timeout=30) as response:
    metadata = json.load(response)
(root / 'cowsay-manifest.json').write_text(json.dumps({k: metadata[k] for k in ['name', 'version', 'bin']}, indent=2))
for n in range(2):
    run(f'global-install-{n}', project, [binary, 'install', '-g', 'cowsay@1.6.0'])
    bins = [str(p) for p in (home / '.lpm').rglob('cowsay*')]
    (root / f'global-files-{n}.json').write_text(json.dumps(bins, indent=2))
run('project-cowsay-control', project, [binary, 'install', 'cowsay@1.6.0', '--no-skills', '--no-editor-setup', '--no-security-summary', '--no-audit-after-install'])
run('project-cowsay-run', project, [str(project / 'node_modules/.bin/cowsay.cmd'), 'native-control'])

empty = root / 'empty'
empty.mkdir()
run('publish-missing-manifest', empty, [binary, 'publish', '--dry-run', '--yes'])
run('upgrade-missing-manifest', empty, [binary, 'upgrade', '-y'])

workspace_script = str(Path('scripts/ci/test-complex-workspace-consumer.py').resolve())
for n in range(5):
    run(f'workspace-{n}', Path.cwd(), [sys.executable, workspace_script, '--binary', binary,
                                     '--output', str(root / f'workspace-{n}')], timeout=180)

for n in range(2):
    short = Path(root.anchor) / f'lpm-native-{os.environ.get("GITHUB_RUN_ID", os.getpid())}-{n}'
    run(f'short-workspace-{n}', Path.cwd(), [sys.executable, workspace_script, '--binary', binary,
                                           '--output', str(short)], timeout=180)
    evidence = root / f'short-workspace-{n}'
    evidence.mkdir()
    for path in short.iterdir():
        if path.is_file() and path.suffix in {'.json', '.log'}:
            shutil.copy2(path, evidence / path.name)
    if (short / 'project/lpm.lock').exists():
        shutil.copy2(short / 'project/lpm.lock', evidence / 'lpm.lock')
