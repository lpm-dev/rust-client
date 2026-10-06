import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

const binary = resolve(process.argv[2] ?? 'target/debug/lpm-rs');
const directory = mkdtempSync(join(tmpdir(), 'lpm-env-types-'));
function run(command, args, env) {
  const result = spawnSync(command, args, { cwd: directory, env, encoding: 'utf8', timeout: 60000 });
  assert.equal(result.status, 0, `${command}: ${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
}
try {
  const home = join(directory, 'home');
  mkdirSync(home);
  const env = { ...process.env, HOME: home, USERPROFILE: home, LPM_STORE_DIR: join(home, 'store'), LPM_NO_KEYRING: '1' };
  for (const key of Object.keys(env)) {
    if (/^(?:ACTIONS_|GITHUB_|CI$|LPM_ENV|LPM_CI|LPM_VAULT)/.test(key)) delete env[key];
  }
  writeFileSync(join(directory, 'package.json'), '{"name":"generated-env-consumer","private":true,"type":"commonjs"}');
  writeFileSync(join(directory, 'lpm.json'), JSON.stringify({ envSchema: { vars: {
    COUNT: { format: 'integer', required: true },
    PORT: { format: 'port', default: '3000' },
    ENABLED: { format: 'boolean', default: 'false' },
    OPTIONAL: {},
    MODE: { enum: ['dev', 'prod'], default: 'dev' },
    SECRET: { secret: true, required: true },
    NEXT_PUBLIC_TEXT: { client: true, default: 'public' },
  } } }));
  run(binary, ['env', 'generate'], env);
  writeFileSync(join(directory, 'consumer.mts'), `
import { createEnv, getEnv, EnvError } from './env.generated/server.js';
import { createEnv as createClient } from './env.generated/client.js';
const env = createEnv({ COUNT: '1', SECRET: 'value' });
const count: bigint = env.COUNT;
const port: number = env.PORT;
const enabled: boolean = env.ENABLED;
const optional: string | undefined = env.OPTIONAL;
const mode: 'dev' | 'prod' = env.MODE;
const publicValue: string = createClient({}).NEXT_PUBLIC_TEXT;
// @ts-expect-error private declarations never enter the client module
createClient({}).SECRET;
// @ts-expect-error optional values require a presence check
const required: string = env.OPTIONAL;
// @ts-expect-error validated output is immutable
env.PORT = 1234;
// @ts-expect-error explicit input accepts raw strings
createEnv({ COUNT: 1 });
const issues: readonly { key: string; code: string; constraint?: string }[] = new EnvError([]).issues;
const startup: ReturnType<typeof getEnv> = env;
`);
  run('tsc', ['--noEmit', '--strict', '--target', 'ES2020', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', 'consumer.mts'], env);
  writeFileSync(join(directory, 'consumer.cjs'), `
const assert = require('node:assert/strict');
(async () => {
  const { createEnv } = await import('./env.generated/server.js');
  const result = createEnv({COUNT:'1', SECRET:'value'});
  assert.equal(result.COUNT, 1n);
  assert.equal(result.PORT, 3000);
  assert.equal(result.ENABLED, false);
  assert.equal(result.OPTIONAL, undefined);
})().catch(error => { console.error(error); process.exitCode = 1; });
`);
  run(process.execPath, ['consumer.cjs'], env);
  console.log('Generated declarations and ESM consumers passed');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
