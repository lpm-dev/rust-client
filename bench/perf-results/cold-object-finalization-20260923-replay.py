import sys
import base64
import concurrent.futures
import hashlib
import http.server
import json
import pathlib
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path('/tmp/lpm-cold-local-cost')
REPO = pathlib.Path.cwd()
DATA = ROOT / 'frozen-registry'
DATA.mkdir(exist_ok=True)
entries = {}
locks = {}
state_lock = threading.Lock()
events = []
misses = []
frozen = False
profile = 'capture'
phase = 'capture'

def identity(path, accept):
    path = urllib.parse.unquote(path)
    kind = 'tarball' if '/-/' in path else ('abbreviated' if 'install-v1' in accept else 'json')
    return (path, kind)

def capture(key):
    encoded = hashlib.sha256(json.dumps(key).encode()).hexdigest()
    meta_file = DATA / (encoded + '.json')
    body_file = DATA / (encoded + '.body')
    if meta_file.exists():
        meta = json.loads(meta_file.read_text())
        return meta, body_file.read_bytes()
    accept = 'application/vnd.npm.install-v1+json' if key[1] == 'abbreviated' else 'application/json'
    req = urllib.request.Request('https://registry.npmjs.org' + key[0], headers={'Accept': accept})
    try:
        response = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        meta = dict(path=key[0], kind=key[1], status=response.status,
                    content_type=response.headers.get('Content-Type', 'application/octet-stream'),
                    headers=dict(response.headers.items()), sha256=hashlib.sha256(body).hexdigest())
    body_file.write_bytes(body)
    meta_file.write_text(json.dumps(meta, indent=2))
    return meta, body

def localize(entry):
    meta, body = entry
    exact = False
    if meta['status'] == 200 and 'json' in meta['content_type']:
        obj = json.loads(body)
        exact = 'version' in obj and 'versions' not in obj
        def rewrite(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    if k == 'tarball' and isinstance(v, str) and v.startswith('https://registry.npmjs.org/'):
                        value[k] = url + v.removeprefix('https://registry.npmjs.org')
                    else:
                        rewrite(v)
            elif isinstance(value, list):
                for v in value:
                    rewrite(v)
        rewrite(obj)
        body = json.dumps(obj, separators=(',', ':')).encode()
    return meta, body, exact

class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    def log_message(self, *args):
        pass
    def do_POST(self):
        global frozen, phase
        value=json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        if 'frozen' in value: frozen=value['frozen']
        phase=value.get('phase',phase)
        self.send_response(200); self.send_header('Content-Length','0'); self.end_headers()
    def do_GET(self):
        request_phase = phase
        if self.path=='/_status':
            with state_lock: body=json.dumps(dict(events=events,misses=misses)).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
        start = time.monotonic_ns()
        key = identity(self.path, self.headers.get('Accept', '*/*'))
        with state_lock:
            gate = locks.setdefault(key, threading.Lock())
        with gate:
            entry = entries.get(key)
            if entry is None:
                if frozen:
                    misses.append((request_phase, key))
                    entry = ({'status': 502, 'content_type': 'text/plain'}, b'uncaptured response', False)
                else:
                    try:
                        entry = localize(capture(key))
                        entries[key] = entry
                    except Exception as error:
                        entry = ({'status': 502, 'content_type': 'text/plain'}, str(error).encode(), False)
        meta, body, exact = entry
        delay = 0
        if key[1] != 'tarball':
            if profile == 'equal':
                delay = 0.04
            elif profile == 'endpoint':
                delay = 0.22 if exact else 0.055
        if delay:
            time.sleep(delay)
        headers_at = time.monotonic_ns()
        self.send_response(meta['status'])
        self.send_header('Content-Type', meta['content_type'])
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'public, max-age=300')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        with state_lock:
            events.append(dict(phase=request_phase, path=self.path, key=key, exact=exact,
                               user_agent=self.headers.get('User-Agent'),
                               received_ns=start, headers_ns=headers_at, completed_ns=time.monotonic_ns(),
                               status=meta['status'], bytes=len(body)))



def verify_captured_archives():
    expected={}
    for meta_file in DATA.glob('*.json'):
        meta=json.loads(meta_file.read_text());body=meta_file.with_suffix('.body').read_bytes()
        assert hashlib.sha256(body).hexdigest()==meta['sha256']
        if meta['status']!=200 or 'json' not in meta['content_type']: continue
        obj=json.loads(body)
        def collect(value):
            if isinstance(value,dict):
                dist=value.get('dist')
                if isinstance(dist,dict) and dist.get('integrity') and dist.get('tarball'):
                    path=urllib.parse.unquote(urllib.parse.urlparse(dist['tarball']).path)
                    expected.setdefault(path,set()).add(dist['integrity'])
                for child in value.values(): collect(child)
            elif isinstance(value,list):
                for child in value: collect(child)
        collect(obj)
    records=[]
    for meta_file in DATA.glob('*.json'):
        meta=json.loads(meta_file.read_text())
        if meta['kind']!='tarball' or meta['status']!=200:continue
        body=meta_file.with_suffix('.body').read_bytes();integrities=expected.get(meta['path'])
        assert integrities,meta['path']
        for integrity in integrities:
            assert any(base64.b64encode(hashlib.new(item.split('-',1)[0],body).digest()).decode()==item.split('-',1)[1] for item in integrity.split()),meta['path']
        records.append(dict(path=meta['path'],bytes=len(body),sha256=meta['sha256'],integrity=sorted(integrities)))
    (ROOT/'replay-archive-parity.json').write_text(json.dumps(records,indent=2))
    return len(records)

server = Server(('127.0.0.1', 0), Handler)
url = f'http://127.0.0.1:{server.server_port}'
threading.Thread(target=server.serve_forever, daemon=True).start()
profile='zero'
for meta_file in DATA.glob('*.json'):
    meta=json.loads(meta_file.read_text())
    entries[(meta['path'],meta['kind'])]=localize((meta,meta_file.with_suffix('.body').read_bytes()))
if '--prepare' not in sys.argv: frozen=True
config=dict(output=str(ROOT/'local-cold-scored'), samples=60, diagnostics=8, states=['ci-cold-cache'],variants=[dict(id='baseline',manager='lpm',binary=str(ROOT/'lpm-baseline')),dict(id='candidate',manager='lpm',binary=str(ROOT/'lpm-candidate')),dict(id='bun',manager='bun')],balancedOrders=True,sharedLpmRoot=True,keepWork=True,fixture=str(ROOT/'next-fixture'),registry=url)
if '--prepare' in sys.argv:
    config.update(output=str(ROOT/'local-cold-prepare'),samples=0,diagnostics=0)
    config['variants']=[v for v in config['variants'] if v['id']!='candidate']
(ROOT/'replay-config.json').write_text(json.dumps(config,indent=2))
try:
    with (ROOT/'local-cold.log').open('w') as log:
        result=subprocess.run(['node',str(ROOT/'replay-runner.mjs'),str(ROOT/'replay-config.json')],cwd=REPO,stdout=log,stderr=subprocess.STDOUT)
    (ROOT/'replay-status.json').write_text(json.dumps(dict(returncode=result.returncode,misses=misses,events=events),indent=2))
    if result.returncode or misses: raise RuntimeError((result.returncode,misses))
    print('Verified',verify_captured_archives(),'original archive integrities',flush=True)
finally:
    server.shutdown()
