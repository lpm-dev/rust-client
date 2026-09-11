"""Disposable native-platform acceptance probes; no production credentials."""

import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import signal
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
    prefix = f'{len(commands):03d}-{label}'
    stdout_path = ROOT / (prefix + '.stdout.log')
    stderr_path = ROOT / (prefix + '.stderr.log')
    with stdout_path.open('wb') as out, stderr_path.open('wb') as err:
        child = subprocess.Popen(command, cwd=cwd, env=env or ENV, stdout=out, stderr=err,
                                 start_new_session=os.name != 'nt',
                                 creationflags=0x200 if os.name == 'nt' else 0)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=15)
            else:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=15)
            code = 124
    stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
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
        before = (p / 'package.json').read_bytes()
        first = run('source-add', p, [BINARY, 'add', '@qa/source', '--yes'], expect=None)
        if first[0] != 0:
            repeat = run('source-add-repeat', p, [BINARY, 'add', '@qa/source', '--yes'], expect=None)
            check((p / 'package.json').read_bytes() == before, 'failed source add changed manifest')
            check(repeat[0] == 0, 'source add rejected an in-project destination twice; see source-add logs')
        check((p / 'components/hello.txt').read_text() == 'hello source', 'source add missing file')
        run('source-remove', p, [BINARY, 'remove', '@qa/source'])
        check(not (p / 'components/hello.txt').exists(), 'source removal retained unchanged file')
    scenario('source-publish-add-remove', source_copy)

    def long_path():
        if os.name == 'nt':
            p = project('long-path/' + 'x' * max(1, 220 - len(str(ROOT / 'long-path'))))
        else:
            p = project('long-path/' + '/'.join(['segment with spaces-' + str(i) + 'x' * 22 for i in range(7)]))
        run('long-path-install', p, [BINARY, 'install', '@qa/native-probe@1.0.0', *FLAGS])
        node('long-path-runtime', p, "require('node:assert/strict').equal(require('@qa/native-probe').answer,42)")
        asset = p / 'node_modules/@qa/native-probe/assets/日本語 file.bin'
        check(len(str(asset)) > 260 and asset.read_bytes() == bytes(range(256)), 'long package asset not readable')
        return {'project_path_length': len(str(p)), 'asset_path_length': len(str(asset))}
    scenario('package-file-path-over-260-characters', long_path)

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

    def shell_path():
        p = project('shell path ! & (parentheses) ü')
        run('shell-path-install', p, [BINARY, 'install', '@qa/native-probe@1.0.0', *FLAGS])
        manifest = json.loads((p / 'package.json').read_text())
        manifest['scripts'] = {'probe': 'qa-native'}
        write_json(p / 'package.json', manifest)
        output = run('shell-path-run', p, [BINARY, 'run', 'probe'])
        check(b'native-bin-ok' in output[1], 'bin command failed in shell-sensitive path')
    scenario('bin-execution-in-shell-sensitive-path', shell_path)

    def linked_project():
        p = project('linked-project-target')
        link = ROOT / 'linked-project-alias'
        link.symlink_to(p, target_is_directory=True)
        run('linked-path-install', link, [BINARY, 'install', '@qa/native-probe@1.0.0', *FLAGS])
        node('linked-path-runtime', link, "require('node:assert/strict').equal(require('@qa/native-probe').answer,42)")
        run('linked-path-uninstall', link, [BINARY, 'uninstall', '@qa/native-probe'])
        check(p.exists() and link.is_symlink(), 'uninstall damaged project alias')
    scenario('install-and-remove-through-directory-symlink', linked_project)

    def native_compile():
        p = project('native compile ü space', {'name': 'qa-native-compile', 'version': '1.0.0', 'private': True,
             'scripts': {'build': 'node-gyp rebuild', 'test': 'node probe.cjs'}}, registry=False)
        write_json(p / 'binding.gyp', {'targets': [{'target_name': 'qa_native', 'sources': ['addon.c']}]})
        (p / 'addon.c').write_text('''#include <node_api.h>
static napi_value answer(napi_env env, napi_callback_info info) {
  napi_value value; napi_create_int32(env, 42, &value); return value;
}
static napi_value init(napi_env env, napi_value exports) {
  napi_value fn; napi_create_function(env, "answer", NAPI_AUTO_LENGTH, answer, 0, &fn);
  napi_set_named_property(env, exports, "answer", fn); return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
''')
        (p / 'probe.cjs').write_text("require('node:assert/strict').equal(require('./build/Release/qa_native.node').answer(),42); console.log('compiled-addon-ok')")
        run('node-gyp-install', p, [BINARY, 'install', 'node-gyp@13.0.2', *FLAGS], timeout=300)
        run('native-source-build', p, [BINARY, 'run', 'build'], timeout=300)
        output = run('native-source-runtime', p, [BINARY, 'run', 'test'])
        check(b'compiled-addon-ok' in output[1], 'compiled N-API addon not usable')
    scenario('compile-and-load-real-native-addon', native_compile)

    def global_install():
        p = project('global-consumer', registry=False)
        first = run('global-install', p, [BINARY, 'install', '-g', 'cowsay@1.6.0'], expect=None)
        second = run('global-install-repeat', p, [BINARY, 'install', '-g', 'cowsay@1.6.0'], expect=None)
        bins = list((ROOT / 'home/.lpm/global/installs').glob('**/.bin/cowsay*'))
        write_json(ROOT / 'global-materialized-bins.json', [str(x) for x in bins])
        check(first[0] == 0, f'global install failed despite materialized bins: {bins}')
        check(second[0] != 0 and b'already installed globally' in second[2], 'duplicate global install did not explain the update command')
        command = ROOT / 'home/.lpm/bin' / ('cowsay.cmd' if os.name == 'nt' else 'cowsay')
        output = run('global-command', p, [command, 'native global command'])
        check(b'native global command' in output[1], 'global command did not preserve arguments')
        run('global-list', p, [BINARY, 'global', 'list'])
        run('global-downgrade', p, [BINARY, 'global', 'update', 'cowsay@1.5.0'])
        run('global-upgrade', p, [BINARY, 'global', 'update', 'cowsay@1.6.0'])
        output = run('global-updated-command', p, [command, 'updated command'])
        check(b'updated command' in output[1], 'updated global command failed')
        run('global-uninstall', p, [BINARY, 'uninstall', '-g', 'cowsay'])
        check(not command.exists(), 'global command survived uninstall')
        run('global-alias-install', p, [BINARY, 'install', '-g', 'cowsay@1.6.0', '--alias', 'cowsay=native-cow'])
        alias = command.with_name('native-cow.cmd' if os.name == 'nt' else 'native-cow')
        output = run('global-alias-command', p, [alias, 'alias command'])
        check(b'alias command' in output[1], 'aliased command failed')
        check(not command.exists(), 'alias unexpectedly emitted the original command')
        run('global-alias-uninstall', p, [BINARY, 'uninstall', '-g', 'cowsay'])
        check(not alias.exists(), 'aliased command survived uninstall')
    scenario('real-global-bin-install-and-repeat', global_install)

    def publish_hook():
        p = project('publish-hook', {'name': '@qa/hook', 'version': '1.0.0', 'description': 'Publish hook fixture',
            'license': 'MIT', 'main': 'index.cjs', 'files': ['index.cjs'], 'scripts': {'prepack': 'node hook.cjs'}})
        (p / 'index.cjs').write_text('module.exports = 42')
        (p / 'hook.cjs').write_text("require('node:fs').writeFileSync('hook-ran.txt','ok')")
        write_json(p / 'lpm.json', {'publish': {'npm': {'registry': URL}}})
        run('hook-node-control', p, [NODE, 'hook.cjs'])
        (p / 'hook-ran.txt').unlink()
        first = run('publish-hook', p, [BINARY, 'publish', '--npm', '--dry-run', '--yes'], expect=None, timeout=180)
        second = run('publish-hook-repeat', p, [BINARY, 'publish', '--npm', '--dry-run', '--yes'], expect=None, timeout=180)
        run('publish-hook-disabled-control', p, [BINARY, 'publish', '--npm', '--dry-run', '--yes', '--ignore-scripts'])
        check(first[0] == second[0] == 0, f'publish hook failed/timed out twice: {first[0]}, {second[0]}; direct Node and --ignore-scripts controls pass')
        check((p / 'hook-ran.txt').read_text() == 'ok', 'prepack hook did not run')
    scenario('publish-lifecycle-hook-and-controls', publish_hook)

finally:
    registry.terminate()
    try:
        registry.wait(timeout=10)
    except subprocess.TimeoutExpired:
        registry.kill()
    registry_log.close()
    save()

raise SystemExit(int(any(x['status'] == 'fail' for x in results)))
