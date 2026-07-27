#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}
if (args.selfTest) {
  runSelfTests();
  process.exit(0);
}

const members = positiveInt(args.members, 240, '--members');
const samples = positiveInt(args.samples, 20, '--samples');
const warmups = nonNegativeInt(args.warmups, 3, '--warmups');
const timeoutMs = positiveInt(args.timeoutMs, 60_000, '--timeout-ms');
const managers = parseManagers(args.managers ?? 'lpm,bun,pnpm,npm');
const outputDir = path.resolve(args.output ?? defaultOutputDir());
const keepProjects = Boolean(args.keepProjects);
const binaries = resolveBinaries(args, managers);
const specs = managers.map((manager) => makeManagerSpec(manager, binaries[manager]));
const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-recursive-workspace-bench-'));
const rows = [];

fs.mkdirSync(outputDir, { recursive: true });
fs.writeFileSync(
  path.join(outputDir, 'plan.json'),
  `${JSON.stringify(
    {
      members,
      samples,
      warmups,
      managers,
      timeout_ms: timeoutMs,
      output_dir: outputDir,
      work_root: keepProjects ? workRoot : null,
      mode: 'up-to-date',
      commands: Object.fromEntries(specs.map((spec) => [spec.manager, displayCommand(spec)])),
    },
    null,
    2,
  )}\n`,
);

try {
  for (const spec of specs) {
    prepareManager(spec);
  }

  for (let warmup = 1; warmup <= warmups; warmup += 1) {
    for (const spec of rotated(specs, warmup - 1)) {
      runInstall(spec);
    }
    console.log(`warmup ${warmup}/${warmups} complete`);
  }

  for (let sample = 1; sample <= samples; sample += 1) {
    const ordered = rotated(specs, sample - 1);
    for (let order = 0; order < ordered.length; order += 1) {
      const spec = ordered[order];
      const result = runInstall(spec);
      const row = {
        manager: spec.manager,
        sample,
        order: order + 1,
        wall_ms: round(result.wallMs),
        stdout_bytes: Buffer.byteLength(result.stdout),
        stderr_bytes: Buffer.byteLength(result.stderr),
      };
      rows.push(row);
      console.log(
        `sample ${sample}/${samples} ${spec.manager} (${order + 1}/${ordered.length}): ${row.wall_ms} ms`,
      );
    }
  }

  const summary = summarize(rows, specs);
  fs.writeFileSync(path.join(outputDir, 'rows.json'), `${JSON.stringify(rows, null, 2)}\n`);
  fs.writeFileSync(path.join(outputDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  fs.writeFileSync(path.join(outputDir, 'summary.md'), `${renderMarkdown(summary)}\n`);
  console.log(`Wrote ${path.join(outputDir, 'rows.json')}`);
  console.log(`Wrote ${path.join(outputDir, 'summary.json')}`);
  console.log(`Wrote ${path.join(outputDir, 'summary.md')}`);
  console.log('');
  console.log(renderMarkdown(summary));
} catch (error) {
  fs.writeFileSync(path.join(outputDir, 'failure.log'), `${error.stack || error}\n`);
  throw error;
} finally {
  if (keepProjects) {
    console.log(`Kept benchmark projects: ${workRoot}`);
  } else {
    removeTree(workRoot);
  }
}

function prepareManager(spec) {
  spec.projectDir = path.join(workRoot, spec.manager, 'project');
  spec.homeDir = path.join(workRoot, spec.manager, 'home');
  spec.lpmHome = path.join(workRoot, spec.manager, 'lpm-home');
  fs.mkdirSync(spec.homeDir, { recursive: true });
  createFixture(spec.projectDir, members, spec.manager === 'pnpm');
  spec.env = buildEnv(spec);
  spec.version = commandVersion(spec);
  runInstall(spec);
  spec.lockfiles = findLockfiles(spec.projectDir, spec.primaryLockfileNames);
  if (spec.lockfiles.length === 0) {
    throw new Error(
      `${spec.manager} completed setup without creating ${spec.primaryLockfileNames.join(' or ')}`,
    );
  }
  spec.lockfileSidecars = findLockfiles(spec.projectDir, spec.lockfileSidecarNames);
  console.log(
    `seeded ${spec.manager} ${spec.version} (${spec.lockfiles.length} lockfile${spec.lockfiles.length === 1 ? '' : 's'}, ${spec.lockfileSidecars.length} sidecar${spec.lockfileSidecars.length === 1 ? '' : 's'})`,
  );
}

function createFixture(projectDir, memberCount, includePnpmWorkspace) {
  fs.mkdirSync(path.join(projectDir, 'packages'), { recursive: true });
  writeJson(path.join(projectDir, 'package.json'), {
    name: `recursive-workspace-${memberCount}`,
    version: '1.0.0',
    private: true,
    workspaces: ['packages/*'],
  });
  if (includePnpmWorkspace) {
    fs.writeFileSync(
      path.join(projectDir, 'pnpm-workspace.yaml'),
      "packages:\n  - 'packages/*'\n",
    );
  }

  for (let index = 0; index < memberCount; index += 1) {
    const member = `m${String(index).padStart(3, '0')}`;
    writeJson(path.join(projectDir, 'packages', member, 'package.json'), {
      name: `@bench/${member}`,
      version: '1.0.0',
      private: true,
    });
  }
}

function makeManagerSpec(manager, binary) {
  const definitions = {
    lpm: {
      args: [
        'install',
        '--no-security-summary',
        '--no-skills',
        '--no-editor-setup',
        '--no-audit-after-install',
      ],
      primaryLockfileNames: ['lpm.lock'],
      lockfileSidecarNames: ['lpm.lockb'],
    },
    bun: {
      args: ['install', '--ignore-scripts'],
      primaryLockfileNames: ['bun.lock', 'bun.lockb'],
      lockfileSidecarNames: [],
    },
    pnpm: {
      args: ['install', '--ignore-scripts', '--reporter', 'append-only'],
      primaryLockfileNames: ['pnpm-lock.yaml'],
      lockfileSidecarNames: [],
    },
    npm: {
      args: ['install', '--ignore-scripts', '--no-audit', '--no-fund'],
      primaryLockfileNames: ['package-lock.json'],
      lockfileSidecarNames: [],
    },
  };
  const definition = definitions[manager];
  return {
    manager,
    binary,
    args: definition.args,
    primaryLockfileNames: definition.primaryLockfileNames,
    lockfileSidecarNames: definition.lockfileSidecarNames,
  };
}

function buildEnv(spec) {
  const keep = [
    'PATH',
    'SHELL',
    'LANG',
    'LC_ALL',
    'TMPDIR',
    'TMP',
    'TEMP',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'NODE_EXTRA_CA_CERTS',
    'SystemRoot',
    'WINDIR',
    'COMSPEC',
    'PATHEXT',
  ];
  const env = {};
  for (const key of keep) {
    if (process.env[key] != null) env[key] = process.env[key];
  }
  env.HOME = spec.homeDir;
  env.USERPROFILE = spec.homeDir;
  env.XDG_CACHE_HOME = path.join(spec.homeDir, '.cache');
  env.XDG_CONFIG_HOME = path.join(spec.homeDir, '.config');
  env.XDG_DATA_HOME = path.join(spec.homeDir, '.local', 'share');
  env.NPM_CONFIG_USERCONFIG = path.join(spec.homeDir, '.npmrc');
  env.npm_config_userconfig = env.NPM_CONFIG_USERCONFIG;
  env.NPM_CONFIG_CACHE = path.join(spec.homeDir, '.npm');
  env.npm_config_cache = env.NPM_CONFIG_CACHE;
  env.NPM_CONFIG_UPDATE_NOTIFIER = 'false';
  env.PNPM_HOME = path.join(spec.homeDir, '.pnpm-home');
  env.BUN_INSTALL = path.join(spec.homeDir, '.bun');
  env.BUN_INSTALL_CACHE_DIR = path.join(spec.homeDir, '.bun', 'install', 'cache');
  env.COREPACK_HOME = path.join(spec.homeDir, '.cache', 'corepack');
  env.NO_UPDATE_NOTIFIER = '1';
  env.LPM_NO_UPDATE_CHECK = '1';
  env.CI = '1';
  if (spec.manager === 'lpm') {
    env.LPM_HOME = spec.lpmHome;
    env.LPM_STORE_VERSION = 'v2';
  }
  return env;
}

function runInstall(spec) {
  const started = process.hrtime.bigint();
  const result = spawnSync(spec.binary, spec.args, {
    cwd: spec.projectDir,
    env: spec.env,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    timeout: timeoutMs,
    windowsHide: true,
  });
  const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
  if (result.error || result.status !== 0) {
    throw new Error(failureDetail(spec, result));
  }
  return {
    wallMs,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function commandVersion(spec) {
  const result = spawnSync(spec.binary, ['--version'], {
    cwd: spec.projectDir,
    env: spec.env,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    timeout: timeoutMs,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${spec.manager} version check failed: ${failureResult(result)}`);
  }
  return String(result.stdout || result.stderr || '').trim().replace(/\s+/g, ' ');
}

function findLockfiles(root, lockfileNames) {
  const names = new Set(lockfileNames);
  if (names.size === 0) return [];
  const found = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const candidate = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        pending.push(candidate);
      } else if (entry.isFile() && names.has(entry.name)) {
        found.push({
          path: path.relative(root, candidate) || entry.name,
          bytes: fs.statSync(candidate).size,
        });
      }
    }
  }
  return found.sort((left, right) => left.path.localeCompare(right.path));
}

function summarize(allRows, managerSpecs) {
  const results = {};
  for (const spec of managerSpecs) {
    const selected = allRows.filter((row) => row.manager === spec.manager);
    const walls = selected.map((row) => row.wall_ms).sort((left, right) => left - right);
    results[spec.manager] = {
      version: spec.version,
      binary: spec.binary,
      command: displayCommand(spec),
      samples: selected.length,
      wall_ms_median: percentile(walls, 0.5),
      wall_ms_p95: percentile(walls, 0.95),
      wall_ms_min: walls[0],
      wall_ms_max: walls.at(-1),
      wall_ms_mean: round(walls.reduce((sum, value) => sum + value, 0) / walls.length),
      lockfile_count: spec.lockfiles.length,
      lockfile_bytes: spec.lockfiles.reduce((sum, lockfile) => sum + lockfile.bytes, 0),
      lockfiles: spec.lockfiles,
      lockfile_sidecar_count: spec.lockfileSidecars.length,
      lockfile_sidecar_bytes: spec.lockfileSidecars.reduce(
        (sum, lockfile) => sum + lockfile.bytes,
        0,
      ),
      lockfile_sidecars: spec.lockfileSidecars,
    };
  }
  const fastestMedian = Math.min(...Object.values(results).map((result) => result.wall_ms_median));
  for (const result of Object.values(results)) {
    result.relative_to_fastest = round(result.wall_ms_median / fastestMedian);
  }
  return {
    generated_at: new Date().toISOString(),
    platform: `${process.platform}-${process.arch}`,
    os_release: os.release(),
    cpu: os.cpus()[0]?.model ?? 'unknown',
    node: process.version,
    fixture: {
      members,
      dependency_shape: 'independent',
      workspace_declaration: {
        lpm: 'package.json#workspaces',
        bun: 'package.json#workspaces',
        pnpm: 'package.json#workspaces plus pnpm-workspace.yaml',
        npm: 'package.json#workspaces',
      },
    },
    mode: 'up-to-date',
    methodology: {
      seed_runs_per_manager: 1,
      warmups,
      samples,
      scheduling: 'round-robin with rotating first manager',
      project_isolation: 'one fixture, HOME, cache, and store per manager',
      network_required: false,
    },
    manager_order: managers,
    results,
  };
}

function renderMarkdown(summary) {
  const lines = [
    '# Recursive workspace install benchmark',
    '',
    `- Generated: ${summary.generated_at}`,
    `- Platform: ${summary.platform} (${summary.os_release})`,
    `- CPU: ${summary.cpu}`,
    `- Fixture: ${summary.fixture.members} independent, dependency-free workspace members`,
    `- Mode: ${summary.mode}; one unmeasured seed, ${summary.methodology.warmups} warmups, ${summary.methodology.samples} measured runs`,
    '- Scheduling: round-robin with a rotating first manager',
    '- Isolation: one fixture, HOME, cache, and store per manager',
    '- Workspace declaration: package.json workspaces; the pnpm fixture additionally contains pnpm-workspace.yaml',
    '',
    '| Manager | Version | Median | p95 | Min | Max | Relative | Lockfiles | Sidecars |',
    '|---|---|---:|---:|---:|---:|---:|---:|---:|',
  ];
  for (const manager of summary.manager_order) {
    const result = summary.results[manager];
    lines.push(
      `| ${manager} | ${escapeCell(result.version)} | ${result.wall_ms_median} ms | ${result.wall_ms_p95} ms | ${result.wall_ms_min} ms | ${result.wall_ms_max} ms | ${result.relative_to_fastest}× | ${result.lockfile_count} | ${result.lockfile_sidecar_count} |`,
    );
  }
  lines.push(
    '',
    'Each measured cell is one root `install` command over an already materialized workspace. The fixture has no external dependencies or lifecycle scripts, so the result isolates process startup, workspace discovery, lockfile validation, and install dispatch without registry or download variance.',
    '',
    '## Commands',
    '',
  );
  for (const manager of summary.manager_order) {
    lines.push(`- ${manager}: \`${summary.results[manager].command}\``);
  }
  return lines.join('\n');
}

function resolveBinaries(parsed, selectedManagers) {
  const requested = {
    lpm: parsed.lpmBin ?? path.join(repoRoot, 'target/release/lpm-rs'),
    bun: parsed.bunBin ?? 'bun',
    pnpm: parsed.pnpmBin ?? 'pnpm',
    npm: parsed.npmBin ?? 'npm',
  };
  const resolved = {};
  for (const manager of selectedManagers) {
    resolved[manager] = resolveExecutable(requested[manager]);
    if (!resolved[manager]) {
      const flag = manager === 'lpm' ? '--lpm-bin' : `--${manager}-bin`;
      throw new Error(
        `${manager} binary is unavailable: ${requested[manager]}. Install it, pass ${flag} PATH, or omit ${manager} from --managers.`,
      );
    }
  }
  return resolved;
}

function resolveExecutable(raw) {
  if (path.isAbsolute(raw) || raw.startsWith('.') || raw.includes('/') || raw.includes('\\')) {
    const candidate = path.resolve(repoRoot, raw);
    return executable(candidate) ? candidate : '';
  }
  return commandPath(raw);
}

function commandPath(command) {
  const searchPath = String(process.env.PATH || '');
  const extensions =
    process.platform === 'win32'
      ? String(process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';')
      : [''];
  for (const directory of searchPath.split(path.delimiter)) {
    if (!directory) continue;
    for (const extension of extensions) {
      const candidate = path.join(directory, `${command}${extension}`);
      if (executable(candidate)) return candidate;
    }
  }
  return '';
}

function executable(candidate) {
  try {
    fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function failureDetail(spec, result) {
  return `${displayCommand(spec)} failed: ${failureResult(result)}`;
}

function failureResult(result) {
  if (result.error) return result.error.message;
  const stderr = String(result.stderr || '').trim();
  const stdout = String(result.stdout || '').trim();
  return tail(stderr || stdout || `exit status ${result.status}`, 4000);
}

function displayCommand(spec) {
  return [spec.binary, ...spec.args].map(shellWord).join(' ');
}

function shellWord(value) {
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(value)
    ? value
    : `'${value.replaceAll("'", "'\\''")}'`;
}

function parseArgs(argv) {
  const parsed = {};
  const booleanFlags = new Map([
    ['--help', 'help'],
    ['-h', 'help'],
    ['--self-test', 'selfTest'],
    ['--keep-projects', 'keepProjects'],
  ]);
  const valueFlags = new Map([
    ['--members', 'members'],
    ['--samples', 'samples'],
    ['-n', 'samples'],
    ['--warmups', 'warmups'],
    ['--managers', 'managers'],
    ['--lpm-bin', 'lpmBin'],
    ['--bun-bin', 'bunBin'],
    ['--pnpm-bin', 'pnpmBin'],
    ['--npm-bin', 'npmBin'],
    ['--timeout-ms', 'timeoutMs'],
    ['--output', 'output'],
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (booleanFlags.has(token)) {
      parsed[booleanFlags.get(token)] = true;
      continue;
    }
    if (!valueFlags.has(token)) throw new Error(`unknown argument: ${token}`);
    const value = argv[index + 1];
    if (!value) throw new Error(`${token} requires a value`);
    parsed[valueFlags.get(token)] = value;
    index += 1;
  }
  return parsed;
}

function parseManagers(raw) {
  const selected = raw
    .split(',')
    .map((manager) => manager.trim())
    .filter(Boolean);
  if (selected.length === 0) throw new Error('--managers must not be empty');
  const seen = new Set();
  for (const manager of selected) {
    if (!['lpm', 'bun', 'pnpm', 'npm'].includes(manager)) {
      throw new Error(`unsupported manager: ${manager}`);
    }
    if (seen.has(manager)) throw new Error(`duplicate manager: ${manager}`);
    seen.add(manager);
  }
  return selected;
}

function positiveInt(raw, fallback, flag) {
  if (raw == null) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return value;
}

function nonNegativeInt(raw, fallback, flag) {
  if (raw == null) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${flag} must be a non-negative integer`);
  }
  return value;
}

function rotated(values, offset) {
  if (values.length <= 1) return [...values];
  const shift = offset % values.length;
  return values.slice(shift).concat(values.slice(0, shift));
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

function round(value) {
  return Math.round(value * 100) / 100;
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function defaultOutputDir() {
  const timestamp = new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15);
  return path.join(
    os.tmpdir(),
    `lpm-recursive-workspace-benchmark-${timestamp}-${process.pid}`,
  );
}

function removeTree(target) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      fs.rmSync(target, { recursive: true, force: true });
      return;
    } catch (error) {
      if (attempt === 7) throw error;
      Atomics.wait(
        new Int32Array(new SharedArrayBuffer(4)),
        0,
        0,
        100 * (attempt + 1),
      );
    }
  }
}

function tail(value, maxChars) {
  return value.length > maxChars ? value.slice(value.length - maxChars) : value;
}

function escapeCell(value) {
  return String(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function runSelfTests() {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-recursive-workspace-self-test-'));
  try {
    createFixture(fixtureRoot, 3, true);
    const rootPackage = JSON.parse(fs.readFileSync(path.join(fixtureRoot, 'package.json'), 'utf8'));
    const finalMember = JSON.parse(
      fs.readFileSync(path.join(fixtureRoot, 'packages/m002/package.json'), 'utf8'),
    );
    assert.deepEqual(rootPackage.workspaces, ['packages/*']);
    assert.equal(finalMember.name, '@bench/m002');
    assert.match(
      fs.readFileSync(path.join(fixtureRoot, 'pnpm-workspace.yaml'), 'utf8'),
      /packages\/\*/,
    );
    const packageJsonOnlyRoot = path.join(fixtureRoot, 'package-json-only');
    createFixture(packageJsonOnlyRoot, 1, false);
    assert.equal(fs.existsSync(path.join(packageJsonOnlyRoot, 'pnpm-workspace.yaml')), false);

    const fakeBinaries = {
      lpm: '/tools/lpm',
      bun: '/tools/bun',
      pnpm: '/tools/pnpm',
      npm: '/tools/npm',
    };
    assert.deepEqual(makeManagerSpec('lpm', fakeBinaries.lpm).args.slice(0, 2), [
      'install',
      '--no-security-summary',
    ]);
    assert.deepEqual(makeManagerSpec('pnpm', fakeBinaries.pnpm).args.slice(-2), [
      '--reporter',
      'append-only',
    ]);
    assert.deepEqual(rotated(['lpm', 'bun', 'pnpm', 'npm'], 2), [
      'pnpm',
      'npm',
      'lpm',
      'bun',
    ]);
    assert.deepEqual(parseManagers('lpm,npm'), ['lpm', 'npm']);
    assert.equal(positiveInt('240', 1, '--members'), 240);
    assert.equal(percentile([1, 2, 3, 4], 0.5), 2);
    assert.deepEqual(parseArgs(['--members', '10', '--keep-projects']), {
      members: '10',
      keepProjects: true,
    });
    assert.throws(() => parseManagers('lpm,lpm'), /duplicate manager/);
    assert.throws(() => positiveInt('2.5', 1, '--samples'), /positive integer/);
  } finally {
    removeTree(fixtureRoot);
  }
  console.log('recursive-workspace-install-benchmark self-test passed');
}

function printHelp() {
  console.log(`Usage: node bench/scripts/recursive-workspace-install-benchmark.mjs [options]

Compare up-to-date root workspace installs across lpm, Bun, pnpm, and npm.
Each manager receives an isolated fixture, HOME, cache, and store. The harness
seeds each fixture once, warms it, then records samples in rotating round-robin
order. The default fixture has 240 independent members and requires no network.

Options:
      --members N          Workspace members (default: 240)
  -n, --samples N          Measured runs per manager (default: 20)
      --warmups N          Warmup rounds per manager (default: 3)
      --managers LIST      lpm,bun,pnpm,npm (default: all four)
      --lpm-bin PATH       lpm binary (default: target/release/lpm-rs)
      --bun-bin PATH       Bun binary (default: bun from PATH)
      --pnpm-bin PATH      pnpm binary (default: pnpm from PATH)
      --npm-bin PATH       npm binary (default: npm from PATH)
      --timeout-ms N       Per-command timeout (default: 60000)
      --output DIR         Artifact directory (default: /tmp/lpm-recursive-workspace-*)
      --keep-projects      Keep isolated fixtures and print their path
      --self-test          Validate fixture, commands, parsing, and statistics
  -h, --help               Show this help

Examples:
  cargo build --release --locked -p lpm-cli --bin lpm-rs
  node bench/scripts/recursive-workspace-install-benchmark.mjs --self-test
  node bench/scripts/recursive-workspace-install-benchmark.mjs \\
    --members 240 --samples 20 --managers lpm,bun,pnpm,npm
`);
}
