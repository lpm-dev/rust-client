#!/usr/bin/env python3
"""Compare task cache behavior with an actual esbuild fixture and a keyed HTTP cache."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import threading
import time


class Cache(http.server.BaseHTTPRequestHandler):
    artifacts = {}
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            artifact = self.artifacts.get(self.path)
        if artifact is None:
            self.send_error(404)
            return
        body, headers = artifact
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        headers = {name: self.headers[name] for name in ['x-artifact-tag', 'x-artifact-sha']}
        with self.lock:
            self.artifacts[self.path] = (body, headers)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"urls":[]}')

    def log_message(self, *_):
        pass


def setup(root, tools, url, portable):
    root.mkdir(parents=True)
    (root / 'src').mkdir()
    (root / 'node_modules').symlink_to(tools / 'node_modules', target_is_directory=True)
    (root / 'package.json').write_text(json.dumps({'name': 'portable-cache-bench', 'version': '1.0.0', 'scripts': {'build': 'node build.cjs'}}))
    task = {'cache': True, 'cacheEnv': [], 'outputs': ['dist/**']}
    if portable:
        task['cachePortable'] = True
    (root / 'lpm.json').write_text(json.dumps({'tasks': {'build': task}, 'remoteCache': {'enabled': True, 'url': url}}))
    imports = []
    calls = []
    for i in range(400):
        contents = []
        for j in range(80):
            token = hashlib.sha256(f'{i}/{j}'.encode()).hexdigest()
            contents.append(f'export const value{j}: string = "{token}";')
        (root / 'src' / f'module{i}.ts').write_text('\n'.join(contents))
        imports.append(f'import * as m{i} from "./module{i}";')
        calls.append(f'm{i}')
    (root / 'src/index.ts').write_text('\n'.join(imports) + '\nconsole.log(' + ','.join(calls) + ');\n')
    (root / 'build.cjs').write_text("require('esbuild').buildSync({entryPoints:['src/index.ts'],bundle:true,minify:true,outfile:'dist/bundle.js',logLevel:'silent'}); require('fs').writeFileSync('executed-marker','ran');")


def run(binary, project, home, result_path, bypass=False):
    env = {name: os.environ[name] for name in ['PATH', 'LANG', 'TMPDIR', 'SystemRoot'] if name in os.environ}
    env.update({'HOME': str(home), 'LPM_HOME': str(home / '.lpm'), 'LPM_FORCE_FILE_AUTH': '1', 'LPM_FORCE_FILE_VAULT': '1', 'LPM_DISABLE_HOST_CLI_AUTH': '1', 'LPM_NO_UPDATE_CHECK': '1', 'LPM_REMOTE_CACHE_TOKEN': 'fixture-token', 'LPM_REMOTE_CACHE_SIGNATURE_KEY': 'fixture-signing-key', 'NO_COLOR': '1'})
    args = [str(binary), 'run', 'build'] + (['--no-cache'] if bypass else [])
    cmd = ['/usr/bin/time', '-l' if platform.system() == 'Darwin' else '-v', '-o', str(result_path), *args]
    host_loadavg = os.getloadavg()
    start = time.perf_counter()
    out = subprocess.run(cmd, cwd=project, env=env, capture_output=True, text=True, check=True)
    elapsed = (time.perf_counter() - start) * 1000
    report = result_path.read_text()
    if platform.system() == 'Darwin':
        rss = int(re.search(r'(\d+)\s+maximum resident set size', report)[1])
    else:
        rss = int(re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', report)[1]) * 1024
    output = project / 'dist/bundle.js'
    assert output.exists(), out
    return {'ms': elapsed, 'rss_bytes': rss, 'executed': (project / 'executed-marker').exists(), 'output_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'host_loadavg': host_loadavg}


def reset(project, home, local):
    shutil.rmtree(project / 'dist', ignore_errors=True)
    (project / 'executed-marker').unlink(missing_ok=True)
    if local:
        shutil.rmtree(home / '.lpm/cache/tasks', ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True, help='npm prefix containing esbuild@0.25.12')
    parser.add_argument('--work-dir', type=Path, required=True, help='new dedicated fixture directory')
    parser.add_argument('--samples', type=int, default=20)
    args = parser.parse_args()
    assert args.samples > 0
    args.work_dir.mkdir(parents=True, exist_ok=False)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Cache)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}/v8'
    variants = {'before': args.before.resolve(), 'after': args.after.resolve()}
    fixtures = {}
    raw = {}
    for label, binary in variants.items():
        base = args.work_dir / label
        fixtures[label] = {}
        for mode, portable in [('portable', True), ('default', False)]:
            pairs = []
            for role in ['producer', 'consumer']:
                project = base / mode / role / 'checkout'
                home = base / mode / role / 'home'
                home.mkdir(parents=True)
                setup(project, args.tools.resolve(), url, portable)
                pairs.append((project, home))
                run(binary, project, home, base / 'time.txt')
            fixtures[label][mode] = pairs
    # Deterministic gates seed both artifact formats and runtime digest records.
    # Before has separate producer/consumer keys; after must share a portable key.
    states = ['default-local', 'portable-local', 'portable-remote', 'portable-remote-cold-digest', 'portable-cold-digest', 'uncached-build']
    raw = {state: {label: [] for label in variants} for state in states}
    for sample in range(args.samples):
        offset = sample % len(states)
        for state in states[offset:] + states[:offset]:
            for label in (['before', 'after'] if sample % 2 == 0 else ['after', 'before']):
                mode = 'default' if state == 'default-local' else 'portable'
                role = 1 if state.startswith('portable-remote') else 0
                project, home = fixtures[label][mode][role]
                reset(project, home, local=state.startswith('portable-remote'))
                if state.startswith('portable-remote'):
                    # Only producer entries remain remotely; this tests cross-root reuse.
                    producer, _ = fixtures[label][mode][0]
                    with Cache.lock:
                        Cache.artifacts.clear()
                    reset(producer, fixtures[label][mode][0][1], local=True)
                    run(variants[label], producer, fixtures[label][mode][0][1], args.work_dir / 'seed-time.txt')
                if state in ['portable-cold-digest', 'portable-remote-cold-digest']:
                    shutil.rmtree(home / '.lpm/cache/metadata/runtime-digests-v1', ignore_errors=True)
                result = run(variants[label], project, home, args.work_dir / f'{label}-time.txt', bypass=state == 'uncached-build')
                expected_execution = state == 'uncached-build' or (state.startswith('portable-remote') and label == 'before')
                assert result['executed'] == expected_execution, (state, label, result)
                raw[state][label].append(result)
    summary = {state: {label: {'median_ms': statistics.median(x['ms'] for x in rows), 'median_rss_bytes': statistics.median(x['rss_bytes'] for x in rows), 'executions': sum(x['executed'] for x in rows)} for label, rows in values.items()} for state, values in raw.items()}
    all_hashes = {row['output_sha256'] for values in raw.values() for rows in values.values() for row in rows}
    assert len(all_hashes) == 1, all_hashes
    report = {'environment': {'platform': platform.platform(), 'python': platform.python_version(), 'logical_cpu_count': os.cpu_count(), 'node': subprocess.check_output(['node', '--version'], text=True).strip(), 'samples_per_binary_per_state': args.samples, 'fixture_modules': 400, 'source_bytes': sum(p.stat().st_size for p in fixtures['before']['portable'][0][0].glob('src/*.ts')), 'esbuild': subprocess.check_output(['node', '-p', "require('esbuild/package.json').version"], cwd=args.tools, text=True).strip()}, 'summary': summary, 'raw': raw}
    (args.work_dir / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'environment': report['environment'], 'summary': summary}, indent=2))
    server.shutdown()


if __name__ == '__main__':
    main()
