import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export function benchmarkTls(root) {
  const directory = fs.mkdtempSync(path.join(root, 'tls-'));
  fs.chmodSync(directory, 0o700);
  const run = args => execFileSync('openssl', args, { cwd: directory, stdio: 'ignore' });
  run(['req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', 'ca-key.pem', '-out', 'ca.pem',
    '-subj', '/CN=LPM Benchmark CA', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE']);
  run(['req', '-new', '-newkey', 'rsa:2048', '-noenc', '-keyout', 'server-key.pem', '-out', 'server.csr', '-subj', '/CN=registry.npmjs.org']);
  fs.writeFileSync(path.join(directory, 'extensions.cnf'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:registry.npmjs.org\n');
  run(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem', '-CAcreateserial',
    '-out', 'server.pem', '-days', '1', '-extfile', 'extensions.cnf']);
  for (const name of ['ca-key.pem', 'server-key.pem']) fs.chmodSync(path.join(directory, name), 0o600);
  return { directory, ca: path.join(directory, 'ca.pem'), key: fs.readFileSync(path.join(directory, 'server-key.pem')),
    cert: fs.readFileSync(path.join(directory, 'server.pem')), close: () => fs.rmSync(directory, { recursive: true }) };
}
