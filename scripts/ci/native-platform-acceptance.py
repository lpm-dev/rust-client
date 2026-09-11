"""Disposable native-platform acceptance probes; no production credentials."""

import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tarfile
import time
import traceback
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--verdaccio', required=True)
args = parser.parse_args()
BINARY = str(Path(args.binary).resolve())
ROOT = Path(args.output).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
NODE = shutil.which('node')
FLAGS = ['--no-skills', '--no-editor-setup', '--no-security-summary', '--no-audit-after-install']
results = []
commands = []


def save():
    (ROOT / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    (ROOT / 'commands.json').write_text(json.dumps(commands, indent=2), encoding='utf-8')


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def scenario(name, fn):
    print('SCENARIO', name, flush=True)
    started = time.monotonic()
    try:
        detail = fn()
        result = {'name': name, 'status': 'pass', 'detail': detail}
    except Exception as error:
        result = {'name': name, 'status': 'fail', 'error': str(error), 'trace': traceback.format_exc()}
    result['seconds'] = round(time.monotonic() - started, 3)
    results.append(result)
    save()
    print(json.dumps(result), flush=True)


def environment(home):
    home.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('LPM_', 'NPM_', 'npm_config_', 'XDG_', 'ACTIONS_ID_TOKEN_'))
           and k not in {'GITHUB_TOKEN', 'GH_TOKEN', 'GITLAB_TOKEN', 'CI_JOB_TOKEN', 'GITHUB_ACTIONS',
                         'CI', 'GITLAB_CI', 'CI_JOB_JWT', 'CI_JOB_JWT_V2', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'}}
    env.update(HOME=str(home), LPM_HOME=str(home / '.lpm'),
               XDG_CONFIG_HOME=str(home / '.config'), XDG_DATA_HOME=str(home / '.local/share'),
               XDG_CACHE_HOME=str(home / '.cache'), LPM_NO_UPDATE_CHECK='1',
               LPM_FORCE_FILE_AUTH='1', LPM_FORCE_FILE_VAULT='1', LPM_DISABLE_HOST_CLI_AUTH='1', NO_COLOR='1',
               LPM_SECURITY_POLICY_PATH=str(home / '.lpm/security-policy.toml'))
    return env


def run(label, cwd, argv, expect=0, env=None, timeout=180):
    command = [str(x) for x in argv]
    start = time.monotonic()
    try:
        output = subprocess.run(command, cwd=cwd, env=env or ENV, capture_output=True, timeout=timeout)
        code, stdout, stderr = output.returncode, output.stdout, output.stderr
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr = 124, error.stdout or b'', error.stderr or b''
    prefix = f'{len(commands):03d}-{label}'
    (ROOT / (prefix + '.stdout.log')).write_bytes(stdout)
    (ROOT / (prefix + '.stderr.log')).write_bytes(stderr)
    entry = {'label': label, 'cwd': str(cwd), 'argv': command, 'exit': code,
             'seconds': round(time.monotonic() - start, 3), 'log': prefix}
    commands.append(entry)
    save()
    if expect is not None:
        check(code == expect, f'{label}: exit={code}, expected={expect}; see {prefix}; '
              + (stdout + stderr).decode('utf-8', errors='replace')[-2500:])
    return code, stdout, stderr


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding='utf-8')


def project(name, manifest=None, registry=True):
    path = ROOT / name
    path.mkdir(parents=True, exist_ok=True)
    write_json(path / 'package.json', manifest or {'name': 'qa-consumer', 'version': '1.0.0', 'private': True})
    if registry:
        (path / '.npmrc').write_text(f'registry={URL}/\n//127.0.0.1:{PORT}/:_authToken={TOKEN}\n', encoding='utf-8')
        (path / '.npmrc').chmod(0o600)
    return path


def node(label, cwd, code):
    return run(label, cwd, [NODE, '-e', code])


def npm_pack(path):
    npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
    return run('npm-pack-control', path, [npm, 'pack', '--json', '--ignore-scripts'])


ENV = environment(ROOT / 'home')
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    PORT = sock.getsockname()[1]
URL = f'http://127.0.0.1:{PORT}'
registry_root = ROOT / 'registry'
registry_root.mkdir()
(registry_root / 'config.yaml').write_text('''storage: ./storage
auth:
  htpasswd:
    file: ./htpasswd
uplinks: {}
packages:
  "**":
    access: $all
    publish: $authenticated
    unpublish: $authenticated
log: {type: stdout, format: pretty, level: warn}
''')
registry_log = (ROOT / 'verdaccio.log').open('wb')
registry = subprocess.Popen([NODE, str(Path(args.verdaccio).resolve()), '--config', str(registry_root / 'config.yaml'),
                             '--listen', f'127.0.0.1:{PORT}'], stdout=registry_log, stderr=subprocess.STDOUT, cwd=registry_root)

try:
    for attempt in range(100):
        try:
            urllib.request.urlopen(URL + '/-/ping', timeout=1).read()
            break
        except Exception:
            if registry.poll() is not None:
                raise RuntimeError('Verdaccio terminated; see verdaccio.log')
            time.sleep(.2)
    request = urllib.request.Request(URL + '/-/user/org.couchdb.user:qa', method='PUT',
        data=json.dumps({'name': 'qa', 'password': 'disposable-acceptance-only', 'email': 'qa@example.test', 'type': 'user'}).encode(),
        headers={'Content-Type': 'application/json'})
    TOKEN = json.load(urllib.request.urlopen(request))['token']
    (ROOT / 'environment.json').write_text(json.dumps({'platform': platform.platform(), 'python': platform.python_version(),
        'binary': BINARY, 'binary_sha256': hashlib.sha256(Path(BINARY).read_bytes()).hexdigest(), 'node': NODE,
        'registry': URL, 'git_sha': os.environ.get('GITHUB_SHA')}, indent=2))

    publisher = project('publisher ü space', {'name': '@qa/native-probe', 'version': '1.0.0', 'description': 'Native platform acceptance',
         'license': 'MIT', 'main': 'index.cjs', 'bin': {'qa-native': 'bin/cli.cjs'}, 'files': ['index.cjs', 'bin', 'assets']})
    (publisher / 'bin').mkdir()
    (publisher / 'assets').mkdir()
    (publisher / 'index.cjs').write_text("module.exports = {version:'1.0.0', answer:42}\n")
    (publisher / 'bin/cli.cjs').write_text("#!/usr/bin/env node\nconsole.log('native-bin-ok')\n")
    (publisher / 'bin/cli.cjs').chmod(0o755)
    (publisher / 'assets/日本語 file.bin').write_bytes(bytes(range(256)))
    (publisher / 'unrelated.txt').write_text('keep publisher work')
    write_json(publisher / 'lpm.json', {'publish': {'npm': {'registry': URL, 'access': 'public'}}})

    def publish_first():
        run('registry-login', publisher, [BINARY, 'login', '--login-registry', URL, '--token', TOKEN])
        run('publish-v1', publisher, [BINARY, 'publish', '--npm', '--yes', '--ignore-scripts'])
        metadata = json.load(urllib.request.urlopen(URL + '/@qa%2Fnative-probe'))
        check('1.0.0' in metadata['versions'], 'registry did not retain published version')
        data = urllib.request.urlopen(metadata['versions']['1.0.0']['dist']['tarball']).read()
        (ROOT / 'published-v1.tgz').write_bytes(data)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            names = archive.getnames()
            check('package/unrelated.txt' not in names, 'excluded publisher file leaked')
            check(archive.extractfile('package/assets/日本語 file.bin').read() == bytes(range(256)), 'asset bytes changed')
        return {'tarball_entries': names}
    scenario('publish-private-registry-spaces-unicode', publish_first)

    consumer = project('consumer ü space')
    def install_first():
        run('install-v1', consumer, [BINARY, 'install', '@qa/native-probe@1.0.0', *FLAGS])
        node('runtime-v1', consumer, "require('node:assert/strict').equal(require('@qa/native-probe').version,'1.0.0')")
        check((consumer / 'node_modules/@qa/native-probe/assets/日本語 file.bin').read_bytes() == bytes(range(256)), 'installed binary asset differs')
        check(URL in (consumer / 'lpm.lock').read_text(), 'lockfile lost custom registry route')
    scenario('install-published-package-and-binary-assets', install_first)

    def bin_probe():
        write_json(consumer / 'package.json', json.loads((consumer / 'package.json').read_text()) | {'scripts': {'probe': 'qa-native'}})
        output = run('run-bin', consumer, [BINARY, 'run', 'probe'])
        check(b'native-bin-ok' in output[1], 'package bin did not execute')
        if os.name != 'nt':
            binary = consumer / 'node_modules/.bin/qa-native'
            check(os.access(binary, os.X_OK), 'bin lost executable permission')
    scenario('bin-shims-and-executable-permissions', bin_probe)

    def duplicate_publish():
        before = (publisher / 'package.json').read_bytes()
        output = run('publish-duplicate', publisher, [BINARY, 'publish', '--npm', '--yes', '--ignore-scripts'], expect=None)
        check(output[0] != 0, 'duplicate publication unexpectedly succeeded')
        check((publisher / 'package.json').read_bytes() == before, 'failed publication changed manifest')
    scenario('duplicate-publish-preserves-project', duplicate_publish)

    def update_probe():
        manifest = json.loads((publisher / 'package.json').read_text())
        manifest['version'] = '1.1.0'
        write_json(publisher / 'package.json', manifest)
        (publisher / 'index.cjs').write_text("module.exports = {version:'1.1.0', answer:43}\n")
        run('publish-v2', publisher, [BINARY, 'publish', '--npm', '--yes', '--ignore-scripts'])
        metadata = json.load(urllib.request.urlopen(URL + '/@qa%2Fnative-probe'))
        write_json(ROOT / 'metadata-after-v2.json', metadata)
        check('1.1.0' in metadata['versions'], 'registry did not store v2')
        warm = run('install-update-v2', consumer, [BINARY, 'install', '@qa/native-probe@1.1.0', *FLAGS], expect=None)
        if warm[0] != 0:
            run('isolated-cache-clean', consumer, [BINARY, 'cache', 'clean'])
            run('install-v2-clean-cache-control', consumer, [BINARY, 'install', '@qa/native-probe@1.1.0', *FLAGS])
        node('runtime-v2-control', consumer, "require('node:assert/strict').equal(require('@qa/native-probe').version,'1.1.0')")
        check(warm[0] == 0, 'Warm-cache explicit new version failed; registry metadata has v2 and clean-cache install succeeds')
        node('runtime-v2', consumer, "require('node:assert/strict').equal(require('@qa/native-probe').version,'1.1.0')")
    scenario('publish-update-and-reinstall', update_probe)

    def frozen():
        before = (consumer / 'lpm.lock').read_bytes()
        shutil.rmtree(consumer / 'node_modules')
        run('clean-frozen', consumer, [BINARY, 'install', '--frozen-lockfile', *FLAGS])
        node('frozen-runtime', consumer, "require('node:assert/strict').equal(require('@qa/native-probe').version,'1.1.0')")
        run('offline-frozen', consumer, [BINARY, 'install', '--offline', '--frozen-lockfile', *FLAGS])
        check((consumer / 'lpm.lock').read_bytes() == before, 'frozen install rewrote lockfile')
    scenario('clean-and-offline-frozen-install', frozen)

    def remove_probe():
        sentinel = consumer / 'user-work.txt'
        sentinel.write_text('preserve')
        run('uninstall', consumer, [BINARY, 'uninstall', '@qa/native-probe'])
        check('@qa/native-probe' not in json.loads((consumer / 'package.json').read_text()).get('dependencies', {}), 'uninstall kept dependency')
        check(not (consumer / 'node_modules/@qa/native-probe').exists(), 'uninstall kept linked package')
        check(not (consumer / 'node_modules/.bin/qa-native.cmd').exists(), 'uninstall kept Windows bin shim')
        check(sentinel.read_text() == 'preserve', 'uninstall changed user file')
    scenario('uninstall-preserves-unrelated-files', remove_probe)

    def public_upgrade():
        p = project('public-upgrade', registry=False)
        run('public-install', p, [BINARY, 'install', 'is-number@6.0.0', *FLAGS])
        run('public-upgrade', p, [BINARY, 'upgrade', 'is-number', '--major', '--yes'])
        node('upgrade-runtime', p, "require('node:assert/strict').equal(require('is-number/package.json').version,'7.0.0')")
        run('public-uninstall', p, [BINARY, 'uninstall', 'is-number'])
    scenario('public-npm-upgrade-and-remove', public_upgrade)

    def workspace():
        p = project('workspace ü space', {'name': 'qa-workspace', 'version': '1.0.0', 'private': True, 'workspaces': ['packages/*']})
        for member in ['core', 'app']:
            m = {'name': '@qa/' + member, 'version': '1.0.0', 'private': True, 'main': 'index.cjs', 'scripts': {'test': 'node test.cjs'}}
            if member == 'app':
                m['dependencies'] = {'@qa/core': 'workspace:*', '@qa/native-probe': '1.1.0'}
            write_json(p / 'packages' / member / 'package.json', m)
        (p / 'packages/core/index.cjs').write_text('module.exports = 42')
        (p / 'packages/core/test.cjs').write_text("require('node:fs').writeFileSync('ran.txt','core')")
        (p / 'packages/app/test.cjs').write_text("require('node:assert/strict').equal(require('@qa/core'),42); require('node:assert/strict').equal(require('@qa/native-probe').answer,43); require('node:fs').writeFileSync('ran.txt','app')")
        run('workspace-install', p, [BINARY, 'install', *FLAGS])
        run('workspace-run', p, [BINARY, 'run', 'test', '--all'])
        check((p / 'packages/app/ran.txt').read_text() == 'app', 'workspace app task did not run')
        check((p / 'packages/core/ran.txt').read_text() == 'core', 'workspace core task did not run')
        run('workspace-uninstall-filter', p, [BINARY, 'uninstall', '@qa/native-probe', '--filter', '@qa/app'])
        check('@qa/core' in json.loads((p / 'packages/app/package.json').read_text())['dependencies'], 'uninstall removed workspace dependency')
        return {'core_link': str((p / 'packages/app/node_modules/@qa/core').resolve())}
    scenario('workspace-links-recursive-run-targeted-remove', workspace)

    def source_copy():
        source = project('source-package', {'name': '@qa/source', 'version': '1.0.0', 'description': 'Source fixture', 'license': 'MIT', 'files': ['lpm.config.json', 'src']})
        (source / 'src').mkdir()
        (source / 'src/hello.txt').write_text('hello source')
        write_json(source / 'lpm.config.json', {'files': [{'src': 'src/hello.txt', 'dest': 'hello.txt'}]})
        write_json(source / 'lpm.json', {'publish': {'npm': {'registry': URL}}})
        run('publish-source', source, [BINARY, 'publish', '--npm', '--yes', '--ignore-scripts'])
        p = project('source-consumer')
        run('source-add', p, [BINARY, 'add', '@qa/source', '--yes'])
        check((p / 'components/hello.txt').read_text() == 'hello source', 'source add missing file')
        run('source-remove', p, [BINARY, 'remove', '@qa/source'])
        check(not (p / 'components/hello.txt').exists(), 'source removal retained unchanged file')
    scenario('source-publish-add-remove', source_copy)

    def long_path():
        p = project('long-path/' + '/'.join(['segment with spaces-' + str(i) + 'x' * 22 for i in range(7)]))
        run('long-path-install', p, [BINARY, 'install', '@qa/native-probe@1.0.0', *FLAGS])
        node('long-path-runtime', p, "require('node:assert/strict').equal(require('@qa/native-probe').answer,42)")
        return {'path_length': len(str(p))}
    scenario('project-path-over-260-characters', long_path)

    def locked_file():
        p = project('open-file-lock')
        run('locked-initial-install', p, [BINARY, 'install', '@qa/native-probe@1.0.0', *FLAGS])
        file = p / 'node_modules/@qa/native-probe/index.cjs'
        if os.name == 'nt':
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
            kernel.CreateFileW.restype = ctypes.c_void_p
            handle = kernel.CreateFileW(str(file), 0x80000000, 1, None, 3, 0, None)
            check(handle not in (None, ctypes.c_void_p(-1).value), 'fixture failed to acquire a no-delete-share handle')
        else:
            handle = file.open('rb')
        try:
            output = run('update-with-open-file', p, [BINARY, 'install', '@qa/native-probe@1.1.0', *FLAGS], expect=None)
            if output[0] == 0:
                node('open-file-update-runtime', p, "require('node:assert/strict').equal(require('@qa/native-probe').answer,43)")
            else:
                check(json.loads((p / 'package.json').read_text())['dependencies']['@qa/native-probe'] == '1.0.0', 'failed locked update changed manifest')
        finally:
            if os.name == 'nt':
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel.CloseHandle(handle)
            else:
                handle.close()
        run('open-file-update-retry', p, [BINARY, 'install', '@qa/native-probe@1.1.0', *FLAGS])
        node('retry-runtime', p, "require('node:assert/strict').equal(require('@qa/native-probe').answer,43)")
    scenario('open-package-file-during-update-and-retry', locked_file)

    def native_dependencies():
        p = project('native-dependencies', registry=False)
        run('native-install', p, [BINARY, 'install', 'esbuild@0.25.9', 'sharp@0.34.3', 'bcrypt@6.0.0', *FLAGS], timeout=300)
        node('native-runtime', p, "const a=require('node:assert/strict'); a.ok(require('esbuild').transformSync('let a: number=42',{loader:'ts'}).code.includes('42')); a.ok(require('bcrypt').compareSync('qa',require('bcrypt').hashSync('qa',4))); require('sharp')({create:{width:2,height:3,channels:4,background:'red'}}).png().toBuffer().then(x=>{a.ok(x.length>0);console.log('three-native-runtime-probes-ok')}).catch(e=>{console.error(e);process.exit(1)})")
    scenario('real-native-optional-dependencies-runtime', native_dependencies)

finally:
    registry.terminate()
    try:
        registry.wait(timeout=10)
    except subprocess.TimeoutExpired:
        registry.kill()
    registry_log.close()
    save()

raise SystemExit(int(any(x['status'] == 'fail' for x in results)))
