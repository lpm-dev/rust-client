import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
const repoRoot=process.cwd();
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const outputDir=config.output;
assert(!fs.existsSync(outputDir),'output must be new');
fs.mkdirSync(outputDir,{recursive:true});
const artifactDir=path.join(outputDir,'artifacts');
const workspaceDir=path.join(outputDir,'work');
const timeoutMs=120000;
const samples=config.samples;
const fixtureDir=path.resolve(config.fixture??'bench/audit-fixtures/t3-install');
const fixturePackageJson=fs.readFileSync(path.join(fixtureDir,'package.json'));
const SCENARIOS=config.states.map(id=>({id,title:id}));
const variants=config.variants;
let lpmBin=variants.find(v=>v.manager==='lpm').binary;
let activeExtraEnv={};
const seeds=new Map();
function select(v){lpmBin=v.binary??lpmBin;activeExtraEnv=v.env??{};}
function reset(manager,scenario,root){
 if(scenario==='ci-cold-cache'){
  removeInstallState(root);clearAllDependencyState(manager,root);
 }else if(scenario==='fresh-checkout-warm-cache'||scenario==='ci-warm-cache'){
  removeInstallState(root);
  if(scenario==='fresh-checkout-warm-cache')removeLockfiles(manager,projectDir(root));
 }else if(scenario==='installed-cache-gone')clearDependencyCache(manager,root);
 else assert.equal(scenario,'up-to-date');
}
writeJson(path.join(outputDir,'plan.json'),{...config,fixture_sha256:sha256(fixturePackageJson),harness_sha256:sha256(fs.readFileSync(process.argv[1])),bun_sha256:sha256(fs.readFileSync(config.bunBinary)),bun_version:spawnSync(config.bunBinary,["--version"],{encoding:"utf8"}).stdout.trim(),node:process.version,platform:process.platform,variants:variants.map(v=>({...v,sha256:v.binary?sha256(fs.readFileSync(v.binary)):undefined})),method:(config.sharedLpmRoot?'Shared physical LPM root per state; separate Bun root. ':'Separate variant roots. ')+(config.balancedOrders?'All forward/reverse rotations balance pair direction. ':'Forward rotations. ')+'Manifest created once per physical root; each variant seeded and warmed twice; reset state outside measurement; rotating variant/scenario order; every scored install retained; no timing instrumentation on scored installs; inventories and lockfiles retained; no repeated seed downloads.'});
for(const scenario of SCENARIOS)for(const v of variants){
 select(v);
 const root=path.join(workspaceDir,`${scenario.id}-${config.sharedLpmRoot && v.manager==='lpm' ? 'lpm-shared' : v.id}`);
 if (!fs.existsSync(root)) createFreshRoot(root);
 seedInPlace(v.manager,scenario.id,root);
 for(let gate=0;gate<2;gate++){
  reset(v.manager,scenario.id,root);
  const r=runInstall({manager:v.manager,root,output:path.join(artifactDir,'gates',scenario.id,v.id,String(gate)),measured:false});
  assert(r.ok&&verifyInstalledProject(root).ok,`warm gate ${scenario.id} ${v.id}`);
  if (v.expectCompactNoop) assert(r.compact_noop, `compact warm gate ${scenario.id} ${v.id}`);
 }
 seeds.set(`${scenario.id}:${v.id}`,root);
 console.log('seeded',scenario.id,v.id);
}
function orderedVariants(items,sample){
 const order=rotate(items,(config.balancedOrders ? Math.floor((sample-1)/2) : sample-1)%items.length);
 return config.balancedOrders && sample%2===0 ? order.reverse() : order;
}
const rows=[];
for(let sample=1;sample<=samples;sample++)for(const scenario of rotate(SCENARIOS,(sample-1)%SCENARIOS.length)){
 const order=orderedVariants(variants,sample);
 for(const v of order){
  select(v);const root=seeds.get(`${scenario.id}:${v.id}`);
  reset(v.manager,scenario.id,root);const setup=captureState(v.manager,root);assertScenarioState(v.manager,scenario.id,setup);
  const output=path.join(artifactDir,scenario.id,v.id,String(sample));
  const result=runInstall({manager:v.manager,root,output,measured:true});
  const verification=verifyInstalledProject(root);
  retainInstalledInventory(root,output);
  const row={sample,scenario:scenario.id,manager:v.manager,variant:v.id,pair_order:order.map(v=>v.id).join('-'),setup,verification,...result};
  rows.push(row);writeJson(path.join(output,'metrics.json'),row);
  assert(result.ok&&verification.ok,`scored failure ${scenario.id} ${v.id} ${sample}`);
  if (v.expectCompactNoop) assert(result.compact_noop, `compact scored response ${scenario.id} ${v.id} ${sample}`);
 }
 if(sample%10===0)console.log('round',sample,scenario.id);
 writeJson(path.join(outputDir,'rows.partial.json'),rows);
}
for(const scenario of SCENARIOS)for(const v of variants){
 select(v);const root=seeds.get(`${scenario.id}:${v.id}`);

 if(v.manager==='lpm')for(let n=0;n<(config.diagnostics??3);n++){
  reset(v.manager,scenario.id,root);const output=path.join(artifactDir,'timing',scenario.id,v.id,String(n));
  const result=runInstall({manager:v.manager,root,output,measured:false,timing:true});assert(result.ok,'diagnostic install failed');
 }
}
writeJson(path.join(outputDir,'rows.json'),rows);
fs.rmSync(path.join(outputDir,'rows.partial.json'));
if(!config.keepWork)fs.rmSync(workspaceDir,{recursive:true,force:true});
console.log('completed',outputDir);
function seedInPlace(manager, scenario, root) {
  const attempts = 3;
  let lastResult;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    lastResult = runInstall({
      manager,
      root,
      output: path.join(root, `preparation-${attempt}`),
      measured: false,
    });
    if (lastResult.ok && verifyInstalledProject(root).ok) {
      assert.equal(lockfilePresent(manager, projectDir(root)), true, `${manager} seed lockfile`);
      return;
    }
    if (attempt < attempts) {
      fs.rmSync(root, { recursive: true, force: true });
      createFreshRoot(root);
    }
  }
  throw new Error(`${manager} ${scenario} preparation failed: ${lastResult?.stderr_tail}`);
}

function createFreshRoot(root) {
  fs.mkdirSync(projectDir(root), { recursive: true });
  fs.mkdirSync(homeDir(root), { recursive: true });
  fs.mkdirSync(lpmHomeDir(root), { recursive: true });
  fs.writeFileSync(path.join(projectDir(root), 'package.json'), fixturePackageJson);
}

function removeInstallState(root) {
  fs.rmSync(path.join(projectDir(root), 'node_modules'), { recursive: true, force: true });
  fs.rmSync(path.join(projectDir(root), '.lpm'), { recursive: true, force: true });
}

function removeLockfiles(manager, project) {
  const names = manager === 'lpm' ? ['lpm.lock', 'lpm.lockb'] : ['bun.lock', 'bun.lockb'];
  for (const name of names) {
    fs.rmSync(path.join(project, name), { force: true });
  }
}

function clearDependencyCache(manager, root) {
  if (manager === 'lpm') {
    fs.rmSync(path.join(lpmHomeDir(root), 'cache'), { recursive: true, force: true });
    return;
  }
  fs.rmSync(path.join(homeDir(root), '.bun', 'install', 'cache'), {
    recursive: true,
    force: true,
  });
}

function clearAllDependencyState(manager, root) {
  clearDependencyCache(manager, root);
  if (manager === 'lpm') {
    fs.rmSync(path.join(lpmHomeDir(root), 'store'), { recursive: true, force: true });
  }
}

function captureState(manager, root) {
  const nodeModules = fs.existsSync(path.join(projectDir(root), 'node_modules'));
  return {
    lockfile: lockfilePresent(manager, projectDir(root)),
    node_modules: nodeModules,
    project_lpm: fs.existsSync(path.join(projectDir(root), '.lpm')),
    cache: dependencyCachePresent(manager, root),
    package_store: manager === 'lpm' ? hasEntries(path.join(lpmHomeDir(root), 'store')) : undefined,
    installed_resolves: nodeModules ? verifyInstalledProject(root).ok : false,
  };
}

function assertScenarioState(manager, scenario, state) {
  const expected = {
    'first-install': { lockfile: false, node_modules: false, cache: false },
    'fresh-checkout-warm-cache': { lockfile: false, node_modules: false, cache: true },
    'ci-cold-cache': { lockfile: true, node_modules: false, cache: false },
    'ci-warm-cache': { lockfile: true, node_modules: false, cache: true },
    'installed-cache-gone': { lockfile: true, node_modules: true, cache: false },
    'up-to-date': { lockfile: true, node_modules: true, cache: true },
  }[scenario];
  assert.deepEqual(
    { lockfile: state.lockfile, node_modules: state.node_modules, cache: state.cache },
    expected,
    `${manager} ${scenario} setup`,
  );
  assert.equal(
    state.installed_resolves,
    expected.node_modules,
    `${manager} ${scenario} installed graph validity`,
  );
  if (manager === 'lpm') {
    const storeExpected = !['first-install', 'ci-cold-cache'].includes(scenario);
    assert.equal(state.package_store, storeExpected, `lpm ${scenario} package store setup`);
  }
}

function dependencyCachePresent(manager, root) {
  if (manager === 'lpm') {
    return hasEntries(path.join(lpmHomeDir(root), 'cache'));
  }
  return hasEntries(path.join(homeDir(root), '.bun', 'install', 'cache'));
}

function hasEntries(target) {
  try {
    return fs.readdirSync(target).length > 0;
  } catch {
    return false;
  }
}

function lockfilePresent(manager, project) {
  const names = manager === 'lpm' ? ['lpm.lock', 'lpm.lockb'] : ['bun.lock', 'bun.lockb'];
  return names.some((name) => fs.existsSync(path.join(project, name)));
}

function runInstall({ manager, root, output, measured, timing = false }) {
  fs.mkdirSync(output, { recursive: true });
  const command = installCommand(manager, timing);
  const env = managerEnv(manager, root, timing);
  const timePath = path.join(output, 'time.txt');
  const timed = measured ? timedCommand(command, timePath) : { command, enabled: false };
  const actual = timed.command;
  const started = process.hrtime.bigint();
  const result = spawnSync(actual[0], actual.slice(1), {
    cwd: projectDir(root),
    env,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout: timeoutMs,
  });
  const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
  fs.writeFileSync(path.join(output, 'stdout.log'), result.stdout ?? '');
  fs.writeFileSync(path.join(output, 'stderr.log'), result.stderr ?? '');
  if (result.error) {
    fs.writeFileSync(path.join(output, 'spawn-error.txt'), `${result.error.stack ?? result.error}\n`);
  }
  const timeOutput = timed.enabled && fs.existsSync(timePath) ? fs.readFileSync(timePath, 'utf8') : '';
  const parsed = manager === 'lpm' ? parseJson(result.stdout) : null;
  if (parsed) {
    writeJson(path.join(output, 'stdout.json'), parsed);
  }
  return {
    ok: result.status === 0 && !result.error && (manager !== 'lpm' || parsed !== null),
    exit_code: result.status ?? 1,
    signal: result.signal,
    spawn_error: result.error ? String(result.error) : undefined,
    wall_ms: wallMs,
    max_rss_bytes: timed.enabled ? parseMaxRssBytes(timeOutput, process.platform) : undefined,
    stdout_tail: tail(result.stdout ?? ''),
    stderr_tail: tail(result.stderr ?? ''),
    compact_noop: parsed?.up_to_date === true && !Object.hasOwn(parsed, 'counts'),
    up_to_date: parsed?.up_to_date === true,
    duration_ms: numberAt(parsed, ['duration_ms']),
    package_count: numberAt(parsed, ['count']),
    downloaded: numberAt(parsed, ['downloaded']),
    cached: numberAt(parsed, ['cached']),
    linked: numberAt(parsed, ['linked']),
    resolve_ms: numberAt(parsed, ['timing', 'resolve_ms']),
    fetch_ms: numberAt(parsed, ['timing', 'fetch_ms']),
    link_ms: numberAt(parsed, ['timing', 'link_ms']),
    link_reuse_check_sum_ms: numberAt(parsed, [
      'timing',
      'detail',
      'link',
      'v2_one',
      'reuse_check_sum_ms',
    ]),
    link_touch_sum_ns: numberAt(parsed, [
      'timing',
      'detail',
      'link',
      'v2_one',
      'touch_sum_ns',
    ]),
    ...streamingPipelineMetrics(parsed),
  };
}

function installCommand(manager, timing) {
  if (manager === 'lpm') {
    const command = [
      lpmBin,
      '--json',
      'install',
      ...(config.bareInstall ? [] : ['--no-security-summary', '--no-skills', '--no-editor-setup']),
    ];
    if (timing) {
      command.push('--timing');
    }
    return command;
  }
  return [config.bunBinary ?? 'bun', 'install', '--ignore-scripts'];
}

function managerEnv(manager, root, timing = false) {
  const keep = [
    'PATH',
    'SHELL',
    'LANG',
    'LC_ALL',
    'TMPDIR',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'NODE_EXTRA_CA_CERTS',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'ALL_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'all_proxy',
    'no_proxy',
    'LPM_REGISTRY_URL',
    'LPM_NPM_FANOUT',
  ];
  const env = {};
  for (const key of keep) {
    if (process.env[key] !== undefined) {
      env[key] = process.env[key];
    }
  }
  env.HOME = homeDir(root);
  env.USERPROFILE = homeDir(root);
  env.XDG_CACHE_HOME = path.join(homeDir(root), '.cache');
  env.XDG_CONFIG_HOME = path.join(homeDir(root), '.config');
  env.XDG_DATA_HOME = path.join(homeDir(root), '.local', 'share');
  if (!config.bareInstall) env.CI = '1';
  env.LPM_NO_UPDATE_CHECK = '1';
  env.LPM_FORCE_FILE_AUTH = '1';
  env.LPM_DISABLE_HOST_CLI_AUTH = '1';
  env.LPM_SECURITY_POLICY_PATH = path.join(homeDir(root), '.lpm/security-policy.toml');
  env.NO_COLOR = '1';
  env.BUN_INSTALL = path.join(homeDir(root), '.bun');
  env.BUN_INSTALL_CACHE_DIR = path.join(homeDir(root), '.bun', 'install', 'cache');
  if (manager === 'lpm') {
    env.LPM_HOME = lpmHomeDir(root);
    env.LPM_STORE_VERSION = 'v2';
    if (timing) {
      env.LPM_TIMING_DETAIL = 'trace';
    }
  }
  return {...env,...activeExtraEnv};
}

function verifyInstalledProject(root) {
  const result = spawnSync(process.execPath, ['-e', `require.resolve(${JSON.stringify(config.verifyModule??"next/package.json")})`], {
    cwd: projectDir(root),
    env: { ...process.env, NODE_PATH: path.join(projectDir(root), 'node_modules') },
    encoding: 'utf8',
    timeout: 30_000,
  });
  return {
    ok: result.status === 0,
    exit_code: result.status ?? 1,
    stderr_tail: tail(result.stderr ?? ''),
  };
}


function retainInstalledInventory(root, output) {
  const project = projectDir(root);
  for (const name of ['lpm.lock', 'lpm.lockb', 'bun.lock', 'bun.lockb']) {
    const source = path.join(project, name);
    if (fs.existsSync(source)) fs.copyFileSync(source, path.join(output, name));
  }
  const projectReal = fs.realpathSync(project);
  const pending = [path.join(project, 'node_modules')];
  const seen = new Set();
  const installed = new Set();
  const seenNodeModules = new Set();
  while (pending.length) {
    const nm = pending.pop();
    if (!fs.existsSync(nm)) continue;
    const realNm = fs.realpathSync(nm);
    if (seenNodeModules.has(realNm)) continue;
    seenNodeModules.add(realNm);
    const roots = fs.readdirSync(nm).filter(x => !x.startsWith('.')).flatMap(name => {
      const p = path.join(nm, name);
      return name.startsWith('@') && fs.statSync(p).isDirectory()
        ? fs.readdirSync(p).map(child => path.join(p, child)) : [p];
    });
    for (const pkg of roots) {
      const real = fs.realpathSync(pkg);
      if (real === projectReal || seen.has(real)) continue;
      seen.add(real);
      const manifest = path.join(real, 'package.json');
      if (!fs.existsSync(manifest)) continue;
      const data = JSON.parse(fs.readFileSync(manifest));
      if (data.name && data.version) installed.add(`${data.name}@${data.version}`);
      pending.push(path.join(real, 'node_modules'));
      const parent = path.dirname(real);
      const parentNm = path.basename(parent) === 'node_modules' ? parent : path.dirname(parent);
      if (path.basename(parentNm) === 'node_modules') pending.push(parentNm);
    }
  }
  writeJson(path.join(output, 'selected-packages.json'), [...installed].sort());
}

function timedCommand(command, outputPath) {
  if (!fs.existsSync('/usr/bin/time')) {
    return { command, enabled: false };
  }
  if (process.platform === 'darwin') {
    return { command: ['/usr/bin/time', '-l', '-o', outputPath, ...command], enabled: true };
  }
  if (process.platform === 'linux') {
    return { command: ['/usr/bin/time', '-v', '-o', outputPath, ...command], enabled: true };
  }
  return { command, enabled: false };
}

function parseMaxRssBytes(output, platform) {
  if (platform === 'darwin') {
    const match = output.match(/^\s*(\d+)\s+maximum resident set size\s*$/im);
    return match ? Number(match[1]) : undefined;
  }
  if (platform === 'linux') {
    const match = output.match(/^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$/im);
    return match ? Number(match[1]) * 1024 : undefined;
  }
  return undefined;
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function numberAt(value, keys) {
  let current = value;
  for (const key of keys) {
    current = current?.[key];
  }
  return Number.isFinite(current) ? current : undefined;
}

function streamedTask(value) {
  const fetchTasks = value?.timing?.detail?.trace?.slow_packages?.fetch_tasks;
  if (Array.isArray(fetchTasks?.by_pipeline) && fetchTasks.by_pipeline.length > 0) {
    return fetchTasks.by_pipeline[0];
  }
  return Array.isArray(fetchTasks?.by_total)
    ? fetchTasks.by_total.find((row) => Number(row?.pipeline_wall_ms) > 0)
    : undefined;
}

function streamedPackage(value) {
  return streamedTask(value)?.package;
}

function streamingPipelineMetrics(value) {
  const task = streamedTask(value);
  return {
    pipeline_wall_sum_ms: numberAt(value, [
      'timing',
      'fetch_breakdown',
      'pipeline_wall',
      'sum_ms',
    ]),
    pipeline_wall_task_count: numberAt(value, [
      'timing',
      'fetch_breakdown',
      'pipeline_wall',
      'task_count',
    ]),
    pipeline_wall_max_ms: numberAt(value, [
      'timing',
      'fetch_breakdown',
      'pipeline_wall',
      'max_ms',
    ]),
    stream_body_wall_ms: numberAt(task, ['stream_body_wall_ms']),
    streaming_weight_requested: numberAt(task, ['streaming_weight_requested']),
    streaming_weight_acquired: numberAt(task, ['streaming_weight_acquired']),
    streaming_extract_permit_wait_ms: numberAt(task, ['extract_permit_wait_ms']),
    supplemental_permit_hold_ms: numberAt(task, ['supplemental_permit_hold_ms']),
    supplemental_permit_lease_expired:
      task?.supplemental_permit_lease_expired === true
        ? 1
        : task?.supplemental_permit_lease_expired === false
          ? 0
          : undefined,
    declared_unpacked_bytes: numberAt(task, ['declared_unpacked_bytes']),
    actual_unpacked_bytes: numberAt(task, ['unpacked_bytes']),
    actual_to_declared_unpacked_ratio: ratio(
      numberAt(task, ['unpacked_bytes']),
      numberAt(task, ['declared_unpacked_bytes']),
    ),
    streamed_package: task?.package,
  };
}

function rotate(values, offset) {
  return [...values.slice(offset), ...values.slice(0, offset)];
}

function projectDir(root) {
  return path.join(root, 'project');
}

function homeDir(root) {
  return path.join(root, 'home');
}

function lpmHomeDir(root) {
  return path.join(root, 'lpm-home');
}

function tail(value) {
  return value.trim().split('\n').slice(-20).join('\n');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeJson(target, value) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
}

