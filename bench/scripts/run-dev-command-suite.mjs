#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

export const MANAGERS = ['lpm', 'bun', 'pnpm', 'npm', 'aube', 'nub', 'deno', 'vlt', 'upm', 'yarn', 'vite'];
export const ROWS = ['echo', 'node', 'esbuild', 'tsx', 'lint', 'fmt'];
export const DEPS = { esbuild: '0.28.2', tsx: '4.23.15', oxlint: '1.79.0', '@biomejs/biome': '2.5.9', react: 'file:./react-0.0.0.tgz' };
const SCRIPT = fileURLToPath(import.meta.url);
const write = (p, value) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, value); };
const json = (p, value) => write(p, `${JSON.stringify(value, null, 2)}\n`);
const hash = value => createHash('sha256').update(value).digest('hex');
const strip = text => text.replace(/\x1b\[[0-9;]*m/g, '');

export function stats(values) {
  if (!values.length || values.some(x => !Number.isFinite(x) || x < 0)) throw new Error('Invalid samples');
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return { n: sorted.length, median: sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2,
    min: sorted[0], max: sorted.at(-1), p95: sorted[Math.ceil(sorted.length * 0.95) - 1] };
}

export function rotate(items, round) {
  const offset = round % items.length;
  const rotated = [...items.slice(offset), ...items.slice(0, offset)];
  return round % 2 ? rotated.reverse() : rotated;
}

export function environment(root, bins) {
  const home = path.join(root, 'home');
  fs.mkdirSync(root, { recursive: true });
  const tmpLink = path.join(root, 'tmp');
  // macOS Unix-domain socket paths must fit TSX's IPC suffix as well as TMPDIR.
  if (fs.lstatSync(tmpLink, { throwIfNoEntry: false })?.isSymbolicLink() && !fs.existsSync(tmpLink)) fs.unlinkSync(tmpLink);
  if (!fs.existsSync(tmpLink)) fs.symlinkSync(fs.mkdtempSync('/tmp/lpm-dev-'), tmpLink);
  const tmp = fs.realpathSync(tmpLink);
  const env = {
    PATH: [...new Set([path.dirname(process.execPath), ...Object.values(bins).map(p => path.dirname(p)), '/usr/bin', '/bin', '/usr/sbin', '/sbin'])].join(path.delimiter),
    HOME: home, USERPROFILE: home, TMPDIR: tmp, TMP: tmp, TEMP: tmp,
    LANG: 'en_US.UTF-8', NO_COLOR: '1', TERM: 'dumb',
    XDG_CACHE_HOME: path.join(home, '.cache'), XDG_CONFIG_HOME: path.join(home, '.config'), XDG_DATA_HOME: path.join(home, '.local/share'),
    LPM_HOME: path.join(home, '.lpm'), LPM_NO_UPDATE_CHECK: '1',
    BUN_INSTALL_CACHE_DIR: path.join(home, '.bun/install/cache'),
    PNPM_HOME: path.join(home, '.pnpm'), npm_config_userconfig: path.join(home, '.npmrc'), npm_config_cache: path.join(home, '.npm'),
    npm_config_update_notifier: 'false', npm_config_audit: 'false', npm_config_fund: 'false',
    AUBE_CACHE_DIR: path.join(home, '.cache/aube'), AUBE_STORE_DIR: path.join(home, '.local/share/aube/store'), AUBE_NO_UPDATE_CHECK: '1',
    DENO_DIR: path.join(home, '.cache/deno'), DENO_NO_UPDATE_CHECK: '1', DENO_NO_PROMPT: '1',
    YARN_GLOBAL_FOLDER: path.join(home, '.yarn'), YARN_ENABLE_IMMUTABLE_INSTALLS: 'false',
  };
  for (const dir of [home, tmp, env.XDG_CACHE_HOME, env.XDG_CONFIG_HOME, env.XDG_DATA_HOME]) fs.mkdirSync(dir, { recursive: true });
  return env;
}

export function fixture(project, manager) {
  const dependencies = { ...DEPS };
  if (manager === 'vite') {
    delete dependencies.oxlint;
    delete dependencies['@biomejs/biome'];
    dependencies['vite-plus'] = '1.0.0';
  }
  json(path.join(project, 'package.json'), { name: 'dev-command-bench', private: true, version: '0.0.0', type: 'module',
    scripts: { noop: 'echo hi', 'node-noop': 'node -e "process.stdout.write(\'node-noop\\n\')"', 'esbuild-version': './node_modules/.bin/esbuild --version' },
    dependencies });
  json(path.join(project, 'tsconfig.json'), { compilerOptions: { target: 'ES2022', moduleResolution: 'bundler', jsx: 'react-jsx', jsxImportSource: 'react' } });
  json(path.join(project, 'react-fixture/package.json'), { name: 'react', version: '0.0.0', type: 'module',
    exports: { './jsx-runtime': './jsx-runtime.js', './jsx-dev-runtime': './jsx-runtime.js' } });
  write(path.join(project, 'react-fixture/jsx-runtime.js'), 'export const Fragment = "Fragment";\nexport function jsx(type, props, key) { return { type, props: props || {}, key: key ?? null }; }\nexport const jsxs = jsx;\nexport const jsxDEV = jsx;\n');
  let entry = '';
  for (let i = 0; i < 10; i++) {
    write(path.join(project, `scripts/module-${i}.tsx`), `export function view${i}(): JSX.Element {\n  return <span data-index="${i}">module-${i}</span>;\n}\n`);
    entry += `import { view${i} } from "./module-${i}.tsx";\n`;
  }
  entry += `const nodes: JSX.Element[] = [${Array.from({ length: 10 }, (_, i) => `view${i}()`).join(', ')}];\n`;
  entry += 'if (nodes.length !== 10 || nodes.some((n, i) => n.type !== "span" || n.props.children !== `module-${i}`)) throw new Error("Invalid JSX result");\nconsole.log(nodes.length);\n';
  write(path.join(project, 'scripts/entry.tsx'), entry);
  for (let i = 0; i < 20; i++) write(path.join(project, `src/file-${String(i).padStart(2, '0')}.js`),
    'export function status() {\n  return { status: "ok", time: Date.now() };\n}\n');
  if (manager === 'deno') json(path.join(project, 'deno.json'), { nodeModulesDir: 'manual', compilerOptions: { jsx: 'react-jsx', jsxImportSource: 'react' } });
  if (manager === 'pnpm') write(path.join(project, 'pnpm-workspace.yaml'), 'allowBuilds:\n  esbuild: true\n');
  if (manager === 'vlt') json(path.join(project, 'vlt.json'), { config: { registry: 'https://registry.npmjs.org/', registries: { npm: 'https://registry.npmjs.org/' }, 'default-registry-alias': 'npm' } });
}

export function command(manager, row) {
  if (!MANAGERS.includes(manager) || !ROWS.includes(row)) throw new Error('Unknown manager or scenario');
  const run = name => manager === 'deno' ? ['task', name] : manager === 'vite' ? ['run', '--no-cache', name] : ['run', name];
  const exec = (bin, ...args) => manager === 'npm' ? ['exec', '--no', '--', bin, ...args]
    : manager === 'bun' ? ['run', bin, ...args] : manager === 'yarn' ? ['run', '-B', bin, ...args]
      : ['aube', 'vlt'].includes(manager) ? ['exec', '--', bin, ...args] : ['exec', bin, ...args];
  if (row === 'echo') return run('noop');
  if (row === 'node') return run('node-noop');
  if (row === 'esbuild') return manager === 'deno' ? run('esbuild-version') : exec('esbuild', '--version');
  if (row === 'tsx') return ['lpm', 'bun', 'nub'].includes(manager) ? ['scripts/entry.tsx']
    : manager === 'deno' ? ['run', '--allow-env', 'scripts/entry.tsx'] : exec('tsx', 'scripts/entry.tsx');
  if (row === 'lint') return ['lpm', 'deno', 'vite'].includes(manager) ? ['lint', 'src/'] : exec('oxlint', 'src/');
  return manager === 'lpm' ? ['fmt', '--check', 'src/'] : manager === 'deno' ? ['fmt', '--check', 'src/']
    : manager === 'vite' ? ['fmt', 'src/', '--check'] : exec('biome', 'format', 'src/');
}

export function outputValid(row, result) {
  if (result.code !== 0 || result.timed_out || result.error) return false;
  const expected = { echo: 'hi', node: 'node-noop', esbuild: DEPS.esbuild, tsx: '10' }[row];
  return !expected || strip(result.stdout).split(/\r?\n/).some(line => line.trim() === expected);
}

export function execute(program, args, { cwd, env, timeout = 30_000 } = {}) {
  return new Promise(resolve => {
    let stdout = '', stderr = '', timedOut = false, error = null;
    const start = process.hrtime.bigint();
    const child = spawn(program, args, { cwd, env, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    const kill = () => { try { process.platform === 'win32' ? child.kill('SIGKILL') : process.kill(-child.pid, 'SIGKILL'); } catch {} };
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeout);
    const interrupt = () => { error = 'Benchmark interrupted'; kill(); };
    process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
    for (const [stream, name] of [[child.stdout, 'stdout'], [child.stderr, 'stderr']]) stream.on('data', chunk => {
      if (name === 'stdout') stdout += chunk; else stderr += chunk;
      if (stdout.length + stderr.length > 8 * 1024 * 1024) { error = 'Output limit exceeded'; kill(); }
    });
    child.on('error', e => { error = e.message; });
    child.on('close', (code, signal) => {
      clearTimeout(timer); process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt);
      resolve({ code, signal, timed_out: timedOut, error, wall_ms: Number(process.hrtime.bigint() - start) / 1e6, stdout, stderr });
    });
  });
}

export function sourceHashes(project) {
  const result = {};
  for (const dir of ['src', 'scripts', 'react-fixture']) for (const file of fs.readdirSync(path.join(project, dir)).sort()) {
    result[`${dir}/${file}`] = hash(fs.readFileSync(path.join(project, dir, file)));
  }
  for (const file of ['package.json', 'tsconfig.json', 'deno.json', 'vlt.json', 'pnpm-workspace.yaml']) {
    if (fs.existsSync(path.join(project, file))) result[file] = hash(fs.readFileSync(path.join(project, file)));
  }
  return result;
}

async function logged(root, name, bin, args, options) {
  const result = await execute(bin, args, options);
  json(path.join(root, 'logs', `${name}.json`), { program: bin, args, ...result });
  if (result.error === 'Benchmark interrupted') throw new Error(result.error);
  return result;
}

export async function prepare(out, bins, managers) {
  fs.mkdirSync(out, { recursive: false });
  const plan = { schema: 1, created_at: new Date().toISOString(), platform: `${os.platform()} ${os.release()} ${os.arch()}`, cpu: os.cpus()[0]?.model,
    memory_bytes: os.totalmem(), node: process.version, node_binary: process.execPath, harness_sha256: hash(fs.readFileSync(SCRIPT)), bins, managers, dependencies: DEPS, projects: {} };
  json(path.join(out, 'plan.json'), plan);
  fs.copyFileSync(SCRIPT, path.join(out, 'run-dev-command-suite.mjs'));
  for (const manager of managers) {
    console.log(`Prepare ${manager}`);
    const root = path.join(out, 'work', manager), project = path.join(root, 'project');
    fixture(project, manager);
    const env = environment(root, bins), options = { cwd: project, env };
    const version = await logged(out, `${manager}-version`, bins[manager], ['--version'], options);
    const state = { version: version.code === 0 ? strip(version.stdout + version.stderr).trim() : 'CLI version flag unsupported', binary_sha256: hash(fs.readFileSync(fs.realpathSync(bins[manager]))), cases: {} };
    if (version.code !== 0) {
      let location = path.dirname(fs.realpathSync(bins[manager]));
      while (location !== path.dirname(location)) {
        if (fs.existsSync(path.join(location, 'package.json'))) {
          const pkg = JSON.parse(fs.readFileSync(path.join(location, 'package.json'), 'utf8'));
          state.package_version = { name: pkg.name, version: pkg.version }; break;
        }
        location = path.dirname(location);
      }
    }
    plan.projects[manager] = state;
    const packed = await logged(out, `${manager}-fixture-pack`, bins.npm, ['pack', './react-fixture', '--ignore-scripts'], options);
    if (packed.code !== 0) throw new Error(`Cannot pack React fixture for ${manager}`);
    const setupBin = ['vite', 'deno'].includes(manager) ? bins.npm : bins[manager];
    const setupArgs = ['install'];
    state.setup = { program: setupBin, args: setupArgs };
    const installed = await logged(out, `${manager}-install`, setupBin, setupArgs, { ...options, timeout: 180_000 });
    state.install_ok = installed.code === 0 && !installed.timed_out && !installed.error;
    if (!state.install_ok) { state.failure = 'Dependency setup failed. See install log.'; json(path.join(out, 'plan.json'), plan); continue; }
    const postinstall = path.join(project, 'node_modules/esbuild/install.js');
    if (fs.existsSync(postinstall)) {
      const built = await logged(out, `${manager}-esbuild-setup`, process.execPath, [postinstall], options);
      if (built.code !== 0) throw new Error(`Pinned esbuild postinstall failed for ${manager}`);
    }
    const formatArgs = manager === 'lpm' ? ['fmt', 'src/'] : manager === 'deno' ? ['fmt', 'src/']
      : manager === 'vite' ? ['fmt', 'src/'] : command(manager, 'fmt').concat('--write');
    await logged(out, `${manager}-format-setup`, bins[manager], formatArgs, { ...options, timeout: 180_000 });
    for (const row of ROWS) {
      const args = command(manager, row);
      const before = sourceHashes(project);
      const result = await logged(out, `${manager}-${row}-preflight`, bins[manager], args, { ...options, timeout: 180_000 });
      const after = sourceHashes(project);
      const stateCase = { args, ok: outputValid(row, result) && JSON.stringify(before) === JSON.stringify(after) };
      state.cases[row] = stateCase;
      if (stateCase.ok && ['lint', 'fmt'].includes(row)) {
        const probe = path.join(project, 'src/benchmark-canary.js');
        write(probe, row === 'lint' ? 'export const invalid = ;\n' : 'export const value={ok:true};\n');
        try {
          const failure = await logged(out, `${manager}-${row}-canary`, bins[manager], args, options);
          stateCase.canary_detected = failure.code !== 0 && failure.code !== null && !failure.error && !failure.timed_out && (failure.stdout + failure.stderr).includes('benchmark-canary');
          stateCase.ok &&= stateCase.canary_detected;
        } finally { fs.unlinkSync(probe); }
      }
      console.log(`  ${row}: ${stateCase.ok ? 'ready' : 'failed preflight'}`);
    }
    state.source_hashes = sourceHashes(project);
    const snapshot = path.join(out, 'fixtures', manager);
    for (const file of [...Object.keys(state.source_hashes), 'react-0.0.0.tgz']) {
      const target = path.join(snapshot, file);
      fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync(path.join(project, file), target);
    }
    state.tool_versions = {};
    for (const row of ['esbuild', 'tsx', 'lint', 'fmt']) {
      const args = row === 'esbuild' ? command(manager, row)
        : row === 'tsx' && ['lpm', 'bun', 'nub', 'deno'].includes(manager) ? ['--version']
          : row === 'fmt' && manager === 'deno' ? ['--version']
            : row === 'fmt' && manager === 'lpm' ? ['plugin', 'list']
              : command(manager, row).map(arg => ['src/', 'scripts/entry.tsx'].includes(arg) ? '--version' : arg).filter(arg => arg !== '--check' && arg !== 'format');
      const result = await logged(out, `${manager}-${row}-tool-version`, bins[manager], args, options);
      state.tool_versions[row] = { args, code: result.code, output: strip(result.stdout + result.stderr).trim() };
    }
    const localBin = path.join(project, 'node_modules/.bin/esbuild');
    if (fs.existsSync(localBin)) {
      const target = fs.realpathSync(localBin), bytes = fs.readFileSync(target);
      state.esbuild_launcher = { path: target, sha256: hash(bytes), header_hex: bytes.subarray(0, 16).toString('hex') };
    }
    state.lockfiles = {};
    for (const name of fs.readdirSync(project).filter(n => /lock|pnp|yarnrc/.test(n))) {
      const p = path.join(project, name);
      if (fs.statSync(p).isFile()) { state.lockfiles[name] = hash(fs.readFileSync(p)); fs.copyFileSync(p, path.join(out, `${manager}-${name}`)); }
    }
    json(path.join(out, 'plan.json'), plan);
  }
  return plan;
}

export async function measure(out, rounds, warmups) {
  const plan = JSON.parse(fs.readFileSync(path.join(out, 'plan.json'), 'utf8'));
  const run = fs.mkdtempSync(path.join(out, 'run-'));
  const results = [];
  const entries = plan.managers.flatMap(manager => ROWS.filter(row => plan.projects[manager].cases[row]?.ok).map(row => ({ manager, row })));
  if (!entries.length) throw new Error('No verified cases');
  for (const manager of plan.managers.filter(m => plan.projects[m].source_hashes)) {
    if (JSON.stringify(sourceHashes(path.join(out, 'work', manager, 'project'))) !== JSON.stringify(plan.projects[manager].source_hashes)) throw new Error(`Fixture changed: ${manager}`);
    if (hash(fs.readFileSync(fs.realpathSync(plan.bins[manager]))) !== plan.projects[manager].binary_sha256) throw new Error(`Binary changed: ${manager}`);
  }
  const visit = async (entry, phase, iteration) => {
    const { manager, row } = entry, root = path.join(out, 'work', manager), project = path.join(root, 'project');
    const args = plan.projects[manager].cases[row].args;
    const result = await logged(run, `${phase}-${iteration}-${manager}-${row}`, plan.bins[manager], args, { cwd: project, env: environment(root, plan.bins) });
    const ok = outputValid(row, result) && JSON.stringify(sourceHashes(project)) === JSON.stringify(plan.projects[manager].source_hashes);
    results.push({ manager, row, phase, iteration, wall_ms: result.wall_ms, ok, code: result.code });
    fs.appendFileSync(path.join(run, 'samples.jsonl'), `${JSON.stringify(results.at(-1))}\n`);
    if (!ok) throw new Error(`${manager}/${row} failed ${phase}; partial results preserved at ${run}`);
  };
  for (let i = 0; i < warmups; i++) for (const row of ROWS) for (const entry of rotate(entries.filter(e => e.row === row), i)) await visit(entry, 'warmup', i + 1);
  for (let i = 0; i < rounds; i++) {
    for (const row of rotate(ROWS, i)) for (const entry of rotate(entries.filter(e => e.row === row), i)) await visit(entry, 'sample', i + 1);
    console.log(`Round ${i + 1}/${rounds} complete`);
  }
  const summary = entries.map(({ manager, row }) => ({ manager, row, ...stats(results.filter(r => r.manager === manager && r.row === row && r.phase === 'sample' && r.ok).map(r => r.wall_ms)) }));
  const rss = [];
  if (process.platform === 'darwin') for (const { manager, row } of entries) {
    const root = path.join(out, 'work', manager);
    const result = await logged(run, `rss-${manager}-${row}`, '/usr/bin/time', ['-l', plan.bins[manager], ...plan.projects[manager].cases[row].args], { cwd: path.join(root, 'project'), env: environment(root, plan.bins) });
    rss.push({ manager, row, ok: outputValid(row, result), max_rss_bytes: Number(result.stderr.match(/(\d+)\s+maximum resident set size/)?.[1]) || null });
  }
  json(path.join(run, 'results.json'), { rounds, warmups, completed_at: new Date().toISOString(), plan, summary, results, rss, rss_method: 'One separate /usr/bin/time -l diagnostic per case on macOS. Maximum process RSS, not simultaneous process-tree memory.' });
  const table = ['| Manager | Echo | Node | esbuild | TSX | Lint | Format check |', '|---|---:|---:|---:|---:|---:|---:|'];
  for (const manager of plan.managers) table.push(`| ${manager} | ${ROWS.map(row => summary.find(s => s.manager === manager && s.row === row)?.median.toFixed(2) ?? 'N/A').join(' | ')} |`);
  write(path.join(run, 'SUMMARY.md'), `# Dev-command benchmark\n\nMedian wall time in milliseconds. ${rounds} samples after ${warmups} warmups.\n\n${table.join('\n')}\n\nExact commands, versions, failures, and source hashes are in results.json and ../plan.json.\n`);
  console.log(table.join('\n')); console.log(`Results: ${run}`);
  return run;
}

async function main() {
  const { values } = parseArgs({ options: { bins: { type: 'string' }, out: { type: 'string' }, managers: { type: 'string', default: MANAGERS.join(',') },
    prepare: { type: 'boolean' }, run: { type: 'boolean' }, rounds: { type: 'string', default: '10' }, warmups: { type: 'string', default: '2' }, help: { type: 'boolean' } } });
  if (values.help) { console.log('node bench/scripts/run-dev-command-suite.mjs --bins /absolute/bins.json --out /new/result-directory [--prepare | --run] [--managers lpm,bun,...] [--rounds 10] [--warmups 2]\nWithout --prepare or --run, prepares and measures. --run uses a previously prepared directory. Setup requires network. All caches remain in the results directory.'); return; }
  if (!values.out || !path.isAbsolute(values.out)) throw new Error('--out must be absolute');
  const rounds = Number(values.rounds), warmups = Number(values.warmups);
  if (!Number.isSafeInteger(rounds) || rounds < 1 || !Number.isSafeInteger(warmups) || warmups < 0) throw new Error('Invalid round or warmup count');
  if (values.prepare && values.run) throw new Error('Choose --prepare or --run');
  if (!values.run) {
    if (!values.bins) throw new Error('--bins is required for setup');
    const bins = JSON.parse(fs.readFileSync(values.bins, 'utf8')), managers = values.managers.split(',');
    if (new Set(managers).size !== managers.length || managers.some(m => !MANAGERS.includes(m))) throw new Error('Invalid manager selection');
    for (const m of new Set([...managers, 'npm'])) {
      if (typeof bins[m] !== 'string' || !path.isAbsolute(bins[m])) throw new Error(`Missing absolute binary for ${m}`);
      fs.accessSync(bins[m], fs.constants.X_OK);
    }
    await prepare(values.out, bins, managers);
  }
  if (!values.prepare) await measure(values.out, rounds, warmups);
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT) main().catch(error => { console.error(error.message); process.exitCode = 1; });
