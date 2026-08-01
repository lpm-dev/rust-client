#!/usr/bin/env node

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stripVTControlCharacters } from 'node:util';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const configPath = path.join(repoRoot, 'bench/ecosystem-verifier/projects.json');
const workspaceLifecyclePhases = new Set([
  'pnpm:devPreinstall',
  'preinstall',
  'install',
  'postinstall',
  'preprepare',
  'prepare',
  'postprepare',
]);
const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}
if (args.selfTest) {
  runSelfTests();
  process.exit(0);
}

const projects = selectProjects(loadProjects(configPath), args.projects ?? 'vite,vue,n8n');
const timeoutMs = positiveInt(args.timeoutMs, 30 * 60_000, '--timeout-ms');
const determinismRuns = boundedInt(args.determinismRuns, 1, 1, 3, '--determinism-runs');
const keepWorkspaces = Boolean(args.keepWorkspaces);
const materializeReference = Boolean(args.materializeReference);
const lpmBin = requiredBinary(args.lpmBin ?? path.join(repoRoot, 'target/release/lpm-rs'));
const verifierBin = requiredBinary(
  args.verifierBin ?? path.join(repoRoot, 'target/release/lpm-ecosystem-verifier'),
);
const outputDir = prepareOutputDirectory(args.output ?? defaultOutputDir());
const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-ecosystem-correction-'));
const results = [];

writeJson(path.join(outputDir, 'plan.json'), {
  schema_version: 1,
  purpose: 'ecosystem_correction_verification',
  graph_parity_policy: {
    release_age: 'one_day_strict_for_both_managers',
    lifecycle_scripts: 'removed_from_temporary_workspace_manifests_for_both_managers',
    engine_constraints: 'warning_only_for_both_managers',
    note: 'pnpm receives minimumReleaseAge=1440. LPM keeps its production 24-hour duration and uses strict transitive scope from its isolated config. Both managers retain their warning-only engine behavior for graph comparison; LPM receives --no-engine-strict because its production default is stricter than pnpm. Repository-specific exclusion syntax is reported, not bypassed. Removed lifecycle phases are recorded per project. Patch-bearing projects may permit only their pinned expected_unused_patches during the fresh pnpm solve; the observed set must match exactly and is recorded per project.',
  },
  projects,
  determinism_runs: determinismRuns,
  materialize_pnpm_reference: materializeReference,
  timeout_ms: timeoutMs,
  output_dir: outputDir,
  work_root: keepWorkspaces ? workRoot : null,
  binaries: {
    lpm: lpmBin,
    verifier: verifierBin,
  },
  versions: {
    node: process.version,
    git: commandVersion('git', ['--version'], repoRoot),
    corepack: commandVersion('corepack', ['--version'], repoRoot),
    lpm: commandVersion(lpmBin, ['--version'], repoRoot),
    verifier: commandVersion(verifierBin, ['--version'], repoRoot),
  },
});

try {
  for (const project of projects) {
    const result = runProject(project);
    results.push(result);
    writeJson(path.join(outputDir, 'summary.json'), summarize(results));
    fs.writeFileSync(path.join(outputDir, 'summary.md'), `${renderSummary(results)}\n`);
  }
} finally {
  if (keepWorkspaces) {
    console.log(`Kept verification workspaces: ${workRoot}`);
  } else {
    removeTree(workRoot, os.tmpdir());
  }
}

const summary = summarize(results);
writeJson(path.join(outputDir, 'summary.json'), summary);
fs.writeFileSync(path.join(outputDir, 'summary.md'), `${renderSummary(results)}\n`);
console.log('');
console.log(renderSummary(results));
console.log(`Artifacts: ${outputDir}`);
if (summary.nonpassing > 0) process.exitCode = 1;

function runProject(project) {
  const projectOutput = path.join(outputDir, project.id);
  const projectWork = path.join(workRoot, project.id);
  const sourceDir = path.join(projectWork, 'source');
  const pnpmDir = path.join(projectWork, 'pnpm');
  const lpmDir = path.join(projectWork, 'lpm-auto');
  fs.mkdirSync(projectOutput, { recursive: true });
  fs.mkdirSync(projectWork, { recursive: true });
  console.log(`[${project.id}] cloning ${project.commit}`);

  const result = {
    id: project.id,
    repository: project.repository,
    commit: project.commit,
    status: 'failed',
    stages: {},
  };
  try {
    clonePinned(project, sourceDir, projectOutput);
    result.input_normalization = {
      removed_workspace_lifecycle_scripts: disableWorkspaceLifecycleScripts(sourceDir),
    };
    copySource(sourceDir, pnpmDir);
    copySource(sourceDir, lpmDir);
    result.input_normalization.pnpm_lockfile = moveOriginalPnpmLock(pnpmDir, projectOutput);

    const pnpmEnv = isolatedEnvironment(path.join(projectWork, 'pnpm-state'));
    result.pnpm_version = commandVersion('corepack', ['pnpm', '--version'], pnpmDir, pnpmEnv);
    const pnpmPolicy = readEffectivePnpmPolicy(pnpmDir, pnpmEnv);
    const importerInventoryPath = path.join(projectOutput, 'lpm-importers.json');
    const importerPaths = discoverLpmImporterPaths(lpmDir, importerInventoryPath);
    result.policy_normalization = applyEquivalentLpmPolicy(lpmDir, pnpmPolicy, importerPaths);
    result.policy_normalization.correction_verification =
      applyPinnedLpmVerificationPolicy(project, lpmDir);
    result.reference_compatibility = applyPinnedReferenceCompatibility(
      project,
      result.policy_normalization,
    );
    const compatibilityPath = path.join(projectOutput, 'comparison-policy.json');
    writeJson(compatibilityPath, comparisonPolicy(result.policy_normalization));
    const lpmStateRoot = path.join(projectWork, 'lpm-state');
    const lpmEnv = lpmCorrectionEnvironment(lpmStateRoot, result.policy_normalization);

    const permittedUnusedPatches = expectedUnusedPatches(project);
    const pnpmArgs = pnpmInstallArgs(project, materializeReference);
    const pnpmInstall = runLogged({
      label: `${project.id}:pnpm-install`,
      command: 'corepack',
      commandArgs: pnpmArgs,
      cwd: pnpmDir,
      env: pnpmEnv,
      timeoutMs,
      outputBase: path.join(projectOutput, 'pnpm-install'),
      allowFailure: true,
    });
    result.stages.pnpm_install = stageResult(pnpmInstall);
    if (pnpmInstall.error || pnpmInstall.status !== 0) {
      const policyBlock = classifyPnpmInstallPolicyBlock(pnpmInstall);
      if (policyBlock == null) {
        throw loggedCommandFailure(`${project.id}:pnpm-install`, pnpmInstall);
      }
      result.status = 'policy_block';
      result.policy_block = policyBlock;
      console.log(
        `[${project.id}] policy block: ${policyBlock.package_identity} triggered pnpm ${policyBlock.code}`,
      );
      return finishProject(result, projectOutput, projectWork);
    }
    const observedUnusedPatches = parsePnpmUnusedPatches(
      `${pnpmInstall.stdout ?? ''}\n${pnpmInstall.stderr ?? ''}`,
    );
    result.reference_fresh_solve = {
      unused_patch_policy:
        permittedUnusedPatches.length > 0 ? 'pinned_expected_set' : 'fail_on_any_unused_patch',
      permitted_unused_patches: permittedUnusedPatches,
      observed_unused_patches: observedUnusedPatches,
    };
    if (!stringArraysEqual(permittedUnusedPatches, observedUnusedPatches)) {
      throw new Error(
        `pnpm unused patches differed from the pinned fresh-solve policy: expected ${JSON.stringify(permittedUnusedPatches)}, observed ${JSON.stringify(observedUnusedPatches)}`,
      );
    }
    preserveNamedFiles(
      pnpmDir,
      ['pnpm-lock.yaml'],
      path.join(projectOutput, 'reference-lockfiles'),
    );

    const lpmArgs = baseLpmArgs();
    const lpmInstall = runLogged({
      label: `${project.id}:lpm-install`,
      command: lpmBin,
      commandArgs: lpmArgs,
      cwd: lpmDir,
      env: lpmEnv,
      timeoutMs,
      outputBase: path.join(projectOutput, 'lpm-install'),
      allowFailure: true,
    });
    result.stages.lpm_install = stageResult(lpmInstall);
    if (lpmInstall.error || lpmInstall.status !== 0) {
      throw loggedCommandFailure(`${project.id}:lpm-install`, lpmInstall);
    }
    const lpmReport = parseJsonOutput(lpmInstall.stdout, 'lpm install');
    writeJson(path.join(projectOutput, 'lpm-install.parsed.json'), lpmReport);
    const workerRequests =
      lpmReport?.timing?.process?.metadata_fetch?.routes?.lpm_worker ?? null;
    result.public_package_worker_requests = workerRequests;
    if (workerRequests != null && workerRequests !== 0) {
      throw new Error(`public-package correction run observed ${workerRequests} LPM worker metadata requests`);
    }
    const initialLocks = hashNamedFiles(lpmDir, ['lpm.lock', 'lpm.lockb']);
    if (initialLocks.size === 0) throw new Error('LPM install created no lockfiles');
    preserveNamedFiles(
      lpmDir,
      ['lpm.lock', 'lpm.lockb'],
      path.join(projectOutput, 'initial-lockfiles'),
    );
    result.initial_lockfiles = [...initialLocks.entries()].map(([file, sha256]) => ({
      file,
      sha256,
    }));

    normalizeGraph('pnpm', pnpmDir, path.join(projectOutput, 'pnpm.graph.json'));
    normalizeGraph('lpm', lpmDir, path.join(projectOutput, 'lpm.graph.json'));
    compareGraphs(projectOutput, compatibilityPath);
    const comparison = readJson(path.join(projectOutput, 'comparison.json'));
    result.comparison = comparison.summary;
    result.comparison_passed = comparison.passed;
    result.peer_amplification = comparison.peer_amplification;

    const pnpmGraph = readJson(path.join(projectOutput, 'pnpm.graph.json'));
    const lpmGraph = readJson(path.join(projectOutput, 'lpm.graph.json'));
    const pnpmLayout = materializeReference
      ? verifyDirectLayout(pnpmDir, pnpmGraph)
      : { skipped: true, reason: 'reference_materialization_not_requested' };
    const lpmLayout = verifyDirectLayout(lpmDir, lpmGraph);
    writeJson(path.join(projectOutput, 'layout-verification.json'), {
      pnpm: pnpmLayout,
      lpm: lpmLayout,
    });
    result.layout = {
      pnpm_failures: pnpmLayout.failures?.length ?? null,
      lpm_failures: lpmLayout.failures.length,
    };
    if (lpmLayout.failures.length > 0) {
      throw new Error(`LPM direct layout verification found ${lpmLayout.failures.length} failures`);
    }
    if (!keepWorkspaces) removeTree(pnpmDir, workRoot);

    const replay = runReplayGates(project, lpmDir, lpmEnv, projectOutput, initialLocks);
    result.replay = replay;
    if (!keepWorkspaces) removeNamedDirectories(lpmDir, 'node_modules', workRoot);

    const determinism = runDeterminismGates(
      project,
      sourceDir,
      lpmDir,
      projectWork,
      lpmEnv,
      lpmStateRoot,
      projectOutput,
      initialLocks,
      result.policy_normalization,
    );
    result.determinism = determinism;

    result.status =
      comparison.passed && replay.passed && determinism.passed ? 'passed' : 'discrepancies';
    console.log(
      `[${project.id}] ${result.status}: graph errors=${comparison.summary.errors}, lpm layout failures=${lpmLayout.failures.length}`,
    );
  } catch (error) {
    result.error = error.stack || String(error);
    fs.writeFileSync(path.join(projectOutput, 'failure.log'), `${result.error}\n`);
    console.error(`[${project.id}] failed: ${error.message}`);
  }
  return finishProject(result, projectOutput, projectWork);
}

function finishProject(result, projectOutput, projectWork) {
  writeJson(path.join(projectOutput, 'result.json'), result);
  if (!keepWorkspaces) removeTree(projectWork, workRoot);
  return result;
}

function runReplayGates(project, workspace, env, projectOutput, expectedLocks) {
  const gates = [];
  for (const gate of [
    { name: 'up-to-date', args: baseLpmArgs() },
    { name: 'frozen', args: [...baseLpmArgs(), '--frozen-lockfile'] },
  ]) {
    const run = runLogged({
      label: `${project.id}:lpm-${gate.name}`,
      command: lpmBin,
      commandArgs: gate.args,
      cwd: workspace,
      env,
      timeoutMs,
      outputBase: path.join(projectOutput, `lpm-${gate.name}`),
    });
    const locksMatch = lockMapsEqual(expectedLocks, hashNamedFiles(workspace, ['lpm.lock', 'lpm.lockb']));
    gates.push({ name: gate.name, ...stageResult(run), locks_match: locksMatch });
  }

  removeNamedDirectories(workspace, 'node_modules', workRoot);
  const offline = runLogged({
    label: `${project.id}:lpm-offline-rebuild`,
    command: lpmBin,
    commandArgs: [...baseLpmArgs(), '--offline', '--frozen-lockfile'],
    cwd: workspace,
    env,
    timeoutMs,
    outputBase: path.join(projectOutput, 'lpm-offline-rebuild'),
  });
  const offlineGraphPath = path.join(projectOutput, 'lpm-offline.graph.json');
  normalizeGraph('lpm', workspace, offlineGraphPath);
  const offlineLayout = verifyDirectLayout(workspace, readJson(offlineGraphPath));
  const offlineLocksMatch = lockMapsEqual(
    expectedLocks,
    hashNamedFiles(workspace, ['lpm.lock', 'lpm.lockb']),
  );
  gates.push({
    name: 'offline-rebuild',
    ...stageResult(offline),
    locks_match: offlineLocksMatch,
    layout_failures: offlineLayout.failures.length,
  });
  const passed = gates.every(
    (gate) => gate.exit_code === 0 && gate.locks_match && (gate.layout_failures ?? 0) === 0,
  );
  const result = { passed, gates };
  writeJson(path.join(projectOutput, 'replay-gates.json'), result);
  return result;
}

function runDeterminismGates(
  project,
  sourceDir,
  initialWorkspace,
  projectWork,
  baseEnv,
  baseStateRoot,
  projectOutput,
  expectedLocks,
  policyNormalization,
) {
  const executionPlan = determinismExecutionPlan(determinismRuns);
  const cacheWarmWorkspace = path.join(projectWork, 'lpm-determinism-cache-warm');
  copySource(sourceDir, cacheWarmWorkspace);
  applyEquivalentLpmPolicy(
    cacheWarmWorkspace,
    policyNormalization.source,
    policyNormalization.applied_importers,
  );
  applyPinnedLpmVerificationPolicy(project, cacheWarmWorkspace);
  removeNamedFiles(cacheWarmWorkspace, ['lpm.lock', 'lpm.lockb'], workRoot);
  removeNamedDirectories(cacheWarmWorkspace, 'node_modules', workRoot);
  const cacheWarmRun = runLogged({
    label: `${project.id}:determinism-cache-warm`,
    command: lpmBin,
    commandArgs: baseLpmArgs(),
    cwd: cacheWarmWorkspace,
    env: baseEnv,
    timeoutMs,
    outputBase: path.join(projectOutput, 'lpm-determinism-cache-warm'),
  });
  const cacheWarmLocks = hashNamedFiles(cacheWarmWorkspace, ['lpm.lock', 'lpm.lockb']);
  const cacheWarmLockDifferences = lockMapDifferences(expectedLocks, cacheWarmLocks);
  if (cacheWarmLockDifferences.length > 0) {
    preserveNamedFiles(
      cacheWarmWorkspace,
      ['lpm.lock', 'lpm.lockb'],
      path.join(projectOutput, 'determinism-lockfiles', 'metadata-cache-warm'),
    );
  }
  const metadataCacheWarmth = {
    passed: cacheWarmRun.status === 0 && cacheWarmLockDifferences.length === 0,
    run: {
      concurrency: 'auto',
      cache_state: 'metadata-cache-warm',
      ...stageResult(cacheWarmRun),
      locks_match_initial: cacheWarmLockDifferences.length === 0,
      lock_count: cacheWarmLocks.size,
      lock_differences: cacheWarmLockDifferences,
    },
  };
  cleanupCompletedDeterminismRun(
    cacheWarmWorkspace,
    null,
    workRoot,
    keepWorkspaces,
  );
  cleanupCompletedDeterminismRun(
    initialWorkspace,
    baseStateRoot,
    workRoot,
    keepWorkspaces,
  );

  const freshSchedulingRuns = [
    {
      run: 1,
      concurrency: 'auto',
      cache_state: 'fresh',
      locks_match_initial: true,
      lock_count: expectedLocks.size,
    },
  ];
  for (let index = 1; index < executionPlan.length; index += 1) {
    const concurrency = executionPlan[index].concurrency;
    const workspace = path.join(projectWork, `lpm-determinism-${concurrency}`);
    const stateRoot = path.join(projectWork, `lpm-determinism-${concurrency}-state`);
    copySource(sourceDir, workspace);
    applyEquivalentLpmPolicy(
      workspace,
      policyNormalization.source,
      policyNormalization.applied_importers,
    );
    applyPinnedLpmVerificationPolicy(project, workspace);
    removeNamedFiles(workspace, ['lpm.lock', 'lpm.lockb'], workRoot);
    removeNamedDirectories(workspace, 'node_modules', workRoot);
    const env = lpmCorrectionEnvironment(stateRoot, policyNormalization);
    const run = runLogged({
      label: `${project.id}:determinism-${concurrency}`,
      command: lpmBin,
      commandArgs: baseLpmArgs(),
      cwd: workspace,
      env: { ...env, LPM_WORKSPACE_CONCURRENCY: concurrency },
      timeoutMs,
      outputBase: path.join(projectOutput, `lpm-determinism-${concurrency}`),
    });
    const locks = hashNamedFiles(workspace, ['lpm.lock', 'lpm.lockb']);
    const lockDifferences = lockMapDifferences(expectedLocks, locks);
    if (lockDifferences.length > 0) {
      preserveNamedFiles(
        workspace,
        ['lpm.lock', 'lpm.lockb'],
        path.join(projectOutput, 'determinism-lockfiles', `fresh-${index + 1}`),
      );
    }
    freshSchedulingRuns.push({
      run: index + 1,
      concurrency,
      cache_state: 'fresh',
      ...stageResult(run),
      locks_match_initial: lockDifferences.length === 0,
      lock_count: locks.size,
      lock_differences: lockDifferences,
    });
    cleanupCompletedDeterminismRun(
      workspace,
      stateRoot,
      workRoot,
      keepWorkspaces,
    );
  }
  const freshScheduling = {
    requested_runs: determinismRuns,
    passed: freshSchedulingRuns.every(
      (run) => run.locks_match_initial && (run.exit_code ?? 0) === 0,
    ),
    runs: freshSchedulingRuns,
  };
  const result = {
    passed: freshScheduling.passed && metadataCacheWarmth.passed,
    fresh_scheduling: freshScheduling,
    metadata_cache_warmth: metadataCacheWarmth,
  };
  writeJson(path.join(projectOutput, 'determinism-gates.json'), result);
  return result;
}

function determinismExecutionPlan(runCount) {
  return [
    { kind: 'metadata-cache-warm', concurrency: 'auto' },
    ...['1', '3'].slice(0, runCount - 1).map((concurrency) => ({
      kind: 'fresh',
      concurrency,
    })),
  ];
}

function normalizeGraph(manager, workspace, output) {
  runCommand(
    verifierBin,
    [manager === 'pnpm' ? 'normalize-pnpm' : 'normalize-lpm', '--workspace', workspace, '--output', output],
    { cwd: repoRoot, timeoutMs },
  );
}

function compareGraphs(projectOutput, compatibility) {
  runCommand(
    verifierBin,
    [
      'compare',
      '--reference',
      path.join(projectOutput, 'pnpm.graph.json'),
      '--candidate',
      path.join(projectOutput, 'lpm.graph.json'),
      '--compatibility',
      compatibility,
      '--json',
      path.join(projectOutput, 'comparison.json'),
      '--markdown',
      path.join(projectOutput, 'comparison.md'),
    ],
    { cwd: repoRoot, timeoutMs },
  );
}

function verifyDirectLayout(workspace, graph) {
  const failures = [];
  let checked = 0;
  let optionalMissing = 0;
  let peersSkipped = 0;
  let workspaceProjectionsPending = 0;
  for (const importer of Object.values(graph.importers ?? {})) {
    const importerDir = importer.path === '.' ? workspace : path.join(workspace, importer.path);
    for (const edge of importer.direct_dependencies ?? []) {
      if (edge.kind === 'peer') {
        peersSkipped += 1;
        continue;
      }
      const packageDir = path.join(importerDir, 'node_modules', ...edge.local_name.split('/'));
      if (!fs.existsSync(packageDir)) {
        if (pendingWorkspaceProjectionMatches(workspace, packageDir, edge.target)) {
          checked += 1;
          workspaceProjectionsPending += 1;
          continue;
        }
        if (edge.kind === 'optional') {
          optionalMissing += 1;
          continue;
        }
        failures.push({
          importer: importer.path,
          dependency: edge.local_name,
          code: 'direct_entry_missing',
          expected: edge.target,
        });
        continue;
      }
      checked += 1;
      let manifest;
      try {
        manifest = readJson(path.join(fs.realpathSync(packageDir), 'package.json'));
      } catch (error) {
        failures.push({
          importer: importer.path,
          dependency: edge.local_name,
          code: 'installed_manifest_unreadable',
          message: error.message,
        });
        continue;
      }
      if (edge.target.name && manifest.name !== edge.target.name) {
        failures.push({
          importer: importer.path,
          dependency: edge.local_name,
          code: 'installed_name_mismatch',
          expected: edge.target.name,
          actual: manifest.name ?? null,
        });
      }
      if (
        edge.target.version &&
        !installedVersionMatches(edge.target.version, manifest.version)
      ) {
        failures.push({
          importer: importer.path,
          dependency: edge.local_name,
          code: 'installed_version_mismatch',
          expected: edge.target.version,
          actual: manifest.version ?? null,
        });
      }
    }
  }
  return {
    checked,
    optional_missing: optionalMissing,
    peers_skipped: peersSkipped,
    workspace_projections_pending: workspaceProjectionsPending,
    failures,
  };
}

function installedVersionMatches(expected, actual) {
  if (actual === expected) return true;
  if (typeof expected !== 'string' || typeof actual !== 'string') return false;
  const exactSemver = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
  return exactSemver.test(expected) && actual === `v${expected}`;
}

function pendingWorkspaceProjectionMatches(workspace, packageDir, target) {
  if (target?.kind !== 'workspace' || typeof target.path !== 'string') return false;
  const expectedTarget = path.resolve(workspace, target.path);
  if (fs.existsSync(expectedTarget)) return false;
  try {
    const linkTarget = fs.readlinkSync(packageDir);
    return path.resolve(path.dirname(packageDir), linkTarget) === expectedTarget;
  } catch {
    return false;
  }
}

function baseLpmArgs() {
  return [
    '--json',
    'install',
    '--recursive',
    '--timing',
    '--no-security-summary',
    '--no-skills',
    '--no-editor-setup',
    '--no-audit-after-install',
    '--no-engine-strict',
  ];
}

function clonePinned(project, destination, outputDirForProject) {
  runLogged({
    label: `${project.id}:git-init`,
    command: 'git',
    commandArgs: ['init', '--quiet', destination],
    cwd: workRoot,
    env: process.env,
    timeoutMs,
    outputBase: path.join(outputDirForProject, 'git-init'),
  });
  runCommand('git', ['remote', 'add', 'origin', project.repository], {
    cwd: destination,
    timeoutMs,
  });
  runLogged({
    label: `${project.id}:git-fetch`,
    command: 'git',
    commandArgs: ['fetch', '--quiet', '--depth', '1', 'origin', project.commit],
    cwd: destination,
    env: process.env,
    timeoutMs,
    outputBase: path.join(outputDirForProject, 'git-fetch'),
  });
  runCommand('git', ['-c', 'advice.detachedHead=false', 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], {
    cwd: destination,
    timeoutMs,
  });
  const actual = commandVersion('git', ['rev-parse', 'HEAD'], destination);
  if (actual !== project.commit) throw new Error(`checkout mismatch: expected ${project.commit}, got ${actual}`);
}

function copySource(source, destination) {
  if (process.platform === 'darwin') {
    runCommand('cp', ['-cR', source, destination], { cwd: path.dirname(destination), timeoutMs });
    const copiedGit = path.join(destination, '.git');
    if (fs.existsSync(copiedGit)) removeTree(copiedGit, workRoot);
    return;
  }
  fs.cpSync(source, destination, {
    recursive: true,
    filter: (entry) => {
      const relative = path.relative(source, entry);
      const first = relative.split(path.sep)[0];
      return !['.git', 'node_modules', 'target'].includes(first);
    },
  });
}

function disableWorkspaceLifecycleScripts(workspace) {
  const manifests = [];
  walkWorkspace(workspace, (entry, type) => {
    if (type.isFile() && path.basename(entry) === 'package.json') manifests.push(entry);
  });
  manifests.sort();

  const removed = [];
  for (const manifestPath of manifests) {
    const raw = fs.readFileSync(manifestPath, 'utf8');
    const hasBom = raw.charCodeAt(0) === 0xfeff;
    let manifest;
    try {
      manifest = JSON.parse(hasBom ? raw.slice(1) : raw);
    } catch (error) {
      if (manifestPath === path.join(workspace, 'package.json')) {
        throw new Error(`failed to parse workspace root package.json: ${error.message}`);
      }
      continue;
    }
    if (
      manifest?.scripts == null ||
      typeof manifest.scripts !== 'object' ||
      Array.isArray(manifest.scripts)
    ) {
      continue;
    }

    const phases = [];
    for (const phase of workspaceLifecyclePhases) {
      if (Object.hasOwn(manifest.scripts, phase)) {
        delete manifest.scripts[phase];
        phases.push(phase);
      }
    }
    if (phases.length === 0) continue;

    const prefix = hasBom ? '\uFEFF' : '';
    fs.writeFileSync(manifestPath, `${prefix}${JSON.stringify(manifest, null, 2)}\n`);
    removed.push({ path: slash(path.relative(workspace, manifestPath)), phases });
  }
  return removed;
}

function moveOriginalPnpmLock(workspace, projectOutput) {
  const lockfile = path.join(workspace, 'pnpm-lock.yaml');
  if (!fs.existsSync(lockfile)) return { mode: 'fresh_solve', original_present: false };
  const snapshot = path.join(projectOutput, 'pnpm-lock.original.yaml');
  fs.copyFileSync(lockfile, snapshot);
  fs.renameSync(lockfile, path.join(workspace, 'pnpm-lock.original.yaml'));
  return {
    mode: 'fresh_solve',
    original_present: true,
    artifact: path.basename(snapshot),
  };
}

function expectedUnusedPatches(project) {
  return sortedUnique(project.fresh_solve?.expected_unused_patches ?? []);
}

function pnpmInstallArgs(project, materialize) {
  const commandArgs = [
    'pnpm',
    'install',
    '--force',
    '--ignore-scripts',
    '--reporter',
    'append-only',
    '--config.minimum-release-age=1440',
    '--config.minimum-release-age-strict=true',
    '--config.engine-strict=false',
  ];
  if (expectedUnusedPatches(project).length > 0) {
    commandArgs.push('--config.allow-unused-patches=true');
  }
  if (!materialize) commandArgs.push('--lockfile-only');
  return commandArgs;
}

function parsePnpmUnusedPatches(output) {
  const plain = stripVTControlCharacters(output);
  const unused = [];
  const pattern = /The following patches were not used:\s*([^\r\n]+)/g;
  for (const match of plain.matchAll(pattern)) {
    unused.push(
      ...match[1]
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
    );
  }
  return sortedUnique(unused);
}

function stringArraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function runLogged({
  label,
  command,
  commandArgs,
  cwd,
  env,
  timeoutMs: timeout,
  outputBase,
  allowFailure = false,
}) {
  const started = process.hrtime.bigint();
  const result = spawnSync(command, commandArgs, {
    cwd,
    env,
    encoding: 'utf8',
    timeout,
    maxBuffer: 256 * 1024 * 1024,
    windowsHide: true,
  });
  const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
  fs.writeFileSync(`${outputBase}.stdout`, result.stdout ?? '');
  fs.writeFileSync(`${outputBase}.stderr`, result.stderr ?? '');
  writeJson(`${outputBase}.command.json`, {
    label,
    command,
    args: commandArgs,
    cwd,
    wall_ms: round(wallMs),
    exit_code: result.status,
    signal: result.signal,
    error: result.error?.message ?? null,
  });
  if (!allowFailure && (result.error || result.status !== 0)) {
    throw loggedCommandFailure(label, result);
  }
  return { ...result, wallMs };
}

function loggedCommandFailure(label, result) {
  return new Error(
    `${label} failed (exit=${result.status}, signal=${result.signal}): ${commandFailureDetail(result)}`,
  );
}

function commandFailureDetail(result) {
  if (result.error?.message) return result.error.message;
  const streams = [
    ['stdout', result.stdout],
    ['stderr', result.stderr],
  ]
    .filter(([, content]) => content?.trim())
    .map(([label, content]) => `${label}:\n${content.trim().slice(-4000)}`);
  return streams.join('\n') || 'unknown error';
}

function runCommand(command, commandArgs, options) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: 'utf8',
    timeout: options.timeoutMs,
    maxBuffer: 256 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${command} ${commandArgs.join(' ')} failed: ${result.error?.message ?? result.stderr?.slice(-4000) ?? `exit ${result.status}`}`,
    );
  }
  return result;
}

function stageResult(run) {
  return {
    exit_code: run.status,
    wall_ms: round(run.wallMs),
    stdout_bytes: Buffer.byteLength(run.stdout ?? ''),
    stderr_bytes: Buffer.byteLength(run.stderr ?? ''),
  };
}

function isolatedEnvironment(stateRoot) {
  const env = {};
  for (const key of [
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
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'ALL_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'all_proxy',
    'no_proxy',
    'SystemRoot',
    'WINDIR',
    'COMSPEC',
    'PATHEXT',
  ]) {
    if (process.env[key] != null) env[key] = process.env[key];
  }
  const home = path.join(stateRoot, 'home');
  fs.mkdirSync(home, { recursive: true });
  return {
    ...env,
    HOME: home,
    USERPROFILE: home,
    XDG_CACHE_HOME: path.join(home, '.cache'),
    XDG_CONFIG_HOME: path.join(home, '.config'),
    XDG_DATA_HOME: path.join(home, '.local/share'),
    NPM_CONFIG_USERCONFIG: path.join(home, '.npmrc'),
    npm_config_userconfig: path.join(home, '.npmrc'),
    NPM_CONFIG_CACHE: path.join(home, '.npm'),
    npm_config_cache: path.join(home, '.npm'),
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    COREPACK_HOME: path.join(home, '.cache/corepack'),
    COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
    PNPM_HOME: path.join(home, '.pnpm-home'),
    NO_UPDATE_NOTIFIER: '1',
    LPM_NO_UPDATE_CHECK: '1',
    CI: '1',
  };
}

function readEffectivePnpmPolicy(workspace, env) {
  const read = (key) => {
    const output = runCommand('corepack', ['pnpm', 'config', 'get', key, '--json'], {
      cwd: workspace,
      env,
      timeoutMs: 120_000,
    }).stdout.trim();
    if (output === '' || output === 'undefined') return null;
    return JSON.parse(output);
  };
  const configPolicy = {
    auto_install_peers: read('autoInstallPeers'),
    minimum_release_age_exclude: read('minimumReleaseAgeExclude'),
    overrides: read('overrides'),
    package_extensions: read('packageExtensions'),
    patched_dependencies: read('patchedDependencies'),
    peer_dependency_rules: read('peerDependencyRules'),
    trust_policy: read('trustPolicy'),
  };
  const manifestPath = path.join(workspace, 'package.json');
  const manifest = readJson(manifestPath);
  const manifestPnpm =
    manifest.pnpm && typeof manifest.pnpm === 'object' && !Array.isArray(manifest.pnpm)
      ? manifest.pnpm
      : {};
  return mergePnpmPolicy(configPolicy, manifestPnpm);
}

function mergePnpmPolicy(configPolicy, manifestPnpm) {
  return {
    auto_install_peers: configPolicy.auto_install_peers ?? manifestPnpm.autoInstallPeers ?? null,
    minimum_release_age_exclude:
      configPolicy.minimum_release_age_exclude ?? manifestPnpm.minimumReleaseAgeExclude ?? null,
    overrides: mergePolicyObjects(manifestPnpm.overrides, configPolicy.overrides),
    package_extensions: mergePolicyObjects(
      manifestPnpm.packageExtensions,
      configPolicy.package_extensions,
    ),
    patched_dependencies: mergePolicyObjects(
      manifestPnpm.patchedDependencies,
      configPolicy.patched_dependencies,
    ),
    peer_dependency_rules: mergePolicyObjects(
      manifestPnpm.peerDependencyRules,
      configPolicy.peer_dependency_rules,
    ),
    trust_policy: configPolicy.trust_policy ?? manifestPnpm.trustPolicy ?? null,
  };
}

function mergePolicyObjects(manifestValue, configValue) {
  const manifestObject =
    manifestValue && typeof manifestValue === 'object' && !Array.isArray(manifestValue)
      ? manifestValue
      : null;
  const configObject =
    configValue && typeof configValue === 'object' && !Array.isArray(configValue)
      ? configValue
      : null;
  if (manifestObject == null && configObject == null) return null;
  return { ...(manifestObject ?? {}), ...(configObject ?? {}) };
}

function discoverLpmImporterPaths(workspace, output) {
  runCommand(
    verifierBin,
    ['discover-importers', '--workspace', workspace, '--output', output],
    { cwd: repoRoot, timeoutMs },
  );
  const inventory = readJson(output);
  assert.equal(inventory.schema_version, 1, 'unsupported importer inventory schema');
  assert(Array.isArray(inventory.importer_paths), 'importer inventory must contain an array');
  return normalizeImporterPaths(workspace, inventory.importer_paths);
}

function normalizeImporterPaths(workspace, importerPaths) {
  assert(Array.isArray(importerPaths) && importerPaths.length > 0, 'no recursive importers found');
  const normalized = normalizeImporterPathsForValidation(importerPaths);
  for (const importerPath of normalized) {
    const manifestPath = path.join(workspace, importerPath, 'package.json');
    assertInside(workspace, manifestPath);
    assert(fs.statSync(manifestPath).isFile(), `recursive importer has no package.json: ${importerPath}`);
  }
  return normalized;
}

function applyEquivalentLpmPolicy(workspace, pnpmPolicy, importerPaths) {
  const translated = {};
  const unsupported = {};

  if (typeof pnpmPolicy.auto_install_peers === 'boolean') {
    translated.auto_install_peers = pnpmPolicy.auto_install_peers;
  }

  const supportedExcludes = [];
  const unsupportedExcludes = [];
  for (const entry of arrayOfStrings(pnpmPolicy.minimum_release_age_exclude)) {
    (isSupportedReleaseAgeExclude(entry) ? supportedExcludes : unsupportedExcludes).push(entry);
  }
  if (supportedExcludes.length > 0) {
    translated.minimum_release_age_exclude = sortedUnique(supportedExcludes);
  }
  if (unsupportedExcludes.length > 0) {
    unsupported.minimum_release_age_exclude = unsupportedExcludes;
  }

  const pnpmOverrides = stringMap(pnpmPolicy.overrides);
  const translatedOverrides = {};
  const unsupportedOverrides = {};
  for (const [selector, target] of Object.entries(pnpmOverrides)) {
    if (isLpmOverrideTarget(target)) translatedOverrides[selector] = target;
    else unsupportedOverrides[selector] = target;
  }
  if (Object.keys(translatedOverrides).length > 0) {
    translated.overrides = translatedOverrides;
  }
  if (Object.keys(unsupportedOverrides).length > 0) {
    unsupported.overrides = unsupportedOverrides;
  }

  const peerRules = normalizePeerDependencyRules(pnpmPolicy.peer_dependency_rules);
  if (peerRules != null) {
    translated.peer_dependency_rules = peerRules;
  }

  const patches = stringMap(pnpmPolicy.patched_dependencies);
  if (Object.keys(patches).length > 0) unsupported.patched_dependencies = patches;
  if (
    pnpmPolicy.package_extensions &&
    typeof pnpmPolicy.package_extensions === 'object' &&
    !Array.isArray(pnpmPolicy.package_extensions) &&
    Object.keys(pnpmPolicy.package_extensions).length > 0
  ) {
    unsupported.package_extensions = pnpmPolicy.package_extensions;
  }
  if (pnpmPolicy.trust_policy === 'no-downgrade') {
    translated.trust_policy = 'no-downgrade';
  } else if (pnpmPolicy.trust_policy != null && pnpmPolicy.trust_policy !== 'off') {
    unsupported.trust_policy = pnpmPolicy.trust_policy;
  }

  const appliedImporters = normalizeImporterPaths(workspace, importerPaths);
  for (const importerPath of appliedImporters) {
    applyTranslatedPolicyToImporter(workspace, importerPath, translated);
  }
  return {
    source: pnpmPolicy,
    translated,
    unsupported,
    applied_importers: appliedImporters,
  };
}

function applyPinnedLpmVerificationPolicy(project, workspace) {
  const entries = project.correction_verification?.typosquat_allow ?? [];
  if (entries.length === 0) return { typosquat_allow: [] };

  const importers = normalizeImporterPaths(
    workspace,
    sortedUnique(entries.map((entry) => entry.importer)),
  );
  for (const importer of importers) {
    const policyPath = path.join(workspace, importer, 'lpm.toml');
    assertInside(workspace, policyPath);
    const existing = fs.existsSync(policyPath) ? fs.readFileSync(policyPath, 'utf8') : '';
    const blocks = entries
      .filter((entry) => entry.importer === importer)
      .map(
        (entry) =>
          `[[policy.typosquat.allow]]\npackage = ${JSON.stringify(entry.package)}\nsimilar-to = ${JSON.stringify(entry.similar_to)}\nreason = ${JSON.stringify(entry.reason)}`,
      );
    const separator = existing === '' || existing.endsWith('\n') ? '' : '\n';
    fs.writeFileSync(policyPath, `${existing}${separator}${blocks.join('\n\n')}\n`);
  }

  return { typosquat_allow: structuredClone(entries) };
}

function applyPinnedReferenceCompatibility(project, policyNormalization) {
  const database = project.reference_compatibility?.pnpm_compatibility_database;
  if (database == null) return null;
  const extensions = structuredClone(database.package_extensions);
  policyNormalization.unsupported.pnpm_compatibility_database_extensions = extensions;
  return {
    pnpm_compatibility_database: {
      package: database.package,
      git_commit: database.git_commit,
      package_extensions: extensions,
    },
  };
}

function comparisonPolicy(policyNormalization) {
  const policy = structuredClone(policyNormalization.unsupported);
  const referencePeerOverrides = stringMap(policyNormalization.source.overrides);
  if (Object.keys(referencePeerOverrides).length > 0) {
    policy.reference_peer_overrides = referencePeerOverrides;
  }
  return policy;
}

function applyTranslatedPolicyToImporter(workspace, importerPath, translated) {
  const manifestPath = path.join(workspace, importerPath, 'package.json');
  const raw = fs.readFileSync(manifestPath, 'utf8');
  const hasBom = raw.charCodeAt(0) === 0xfeff;
  const manifest = JSON.parse(hasBom ? raw.slice(1) : raw);
  const existingLpm =
    manifest.lpm && typeof manifest.lpm === 'object' && !Array.isArray(manifest.lpm)
      ? manifest.lpm
      : {};
  const lpm = { ...existingLpm };

  if (typeof translated.auto_install_peers === 'boolean') {
    lpm.autoInstallPeers = translated.auto_install_peers;
  }
  if (translated.minimum_release_age_exclude?.length > 0) {
    lpm.minimumReleaseAgeExclude = sortedUnique([
      ...arrayOfStrings(lpm.minimumReleaseAgeExclude),
      ...translated.minimum_release_age_exclude,
    ]);
  }
  if (translated.overrides != null) {
    lpm.overrides = { ...stringMap(lpm.overrides), ...translated.overrides };
  }
  if (translated.peer_dependency_rules != null) {
    lpm.peerDependencyRules = translated.peer_dependency_rules;
  }

  manifest.lpm = lpm;
  const prefix = hasBom ? '\uFEFF' : '';
  fs.writeFileSync(manifestPath, `${prefix}${JSON.stringify(manifest, null, 2)}\n`);
}

function configureLpmCorrectionState(lpmHome, policyNormalization) {
  fs.mkdirSync(lpmHome, { recursive: true });
  const lines = ['minimum-release-age-secs = 86400', 'release-age-policy = "strict"'];
  if (policyNormalization.translated.minimum_release_age_exclude?.length > 0) {
    const values = policyNormalization.translated.minimum_release_age_exclude.map((entry) =>
      JSON.stringify(entry),
    );
    lines.push(`minimum-release-age-exclude = [${values.join(', ')}]`);
  }
  if (typeof policyNormalization.translated.auto_install_peers === 'boolean') {
    lines.push(`auto-install-peers = ${policyNormalization.translated.auto_install_peers}`);
  }
  if (policyNormalization.translated.trust_policy === 'no-downgrade') {
    lines.push('trust-policy = "no-downgrade"');
  }
  fs.writeFileSync(path.join(lpmHome, 'config.toml'), `${lines.join('\n')}\n`);
}

function lpmCorrectionEnvironment(stateRoot, policyNormalization) {
  const lpmHome = path.join(stateRoot, 'lpm-home');
  configureLpmCorrectionState(lpmHome, policyNormalization);
  return {
    ...isolatedEnvironment(stateRoot),
    LPM_HOME: lpmHome,
    LPM_STORE_VERSION: 'v2',
    LPM_TIMING_DETAIL: 'trace',
    LPM_NPM_ROUTE: 'direct',
  };
}

function arrayOfStrings(value) {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === 'string') : [];
}

function stringMap(value) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => typeof entry === 'string'),
  );
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function isExactNpmPackageName(value) {
  return /^(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)$/i.test(
    value,
  );
}

function isSupportedReleaseAgeExclude(value) {
  if (/^@[a-z0-9][a-z0-9._~-]*\/\*$/i.test(value)) return true;
  const versionSeparator = value.startsWith('@') ? value.lastIndexOf('@') : value.indexOf('@');
  if (versionSeparator > 0) {
    const packageName = value.slice(0, versionSeparator);
    const version = value.slice(versionSeparator + 1);
    return (
      isExactNpmPackageName(packageName) &&
      /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(version)
    );
  }
  return isExactNpmPackageName(value);
}

function isLpmOverrideTarget(value) {
  return (
    typeof value === 'string' &&
    /^[v~^<>=*0-9]/.test(value) &&
    !value.includes(':') &&
    !value.includes('$')
  );
}

function normalizePeerDependencyRules(value) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) return null;
  const rules = {};
  const ignoreMissing = arrayOfStrings(value.ignoreMissing);
  const allowAny = arrayOfStrings(value.allowAny);
  const allowedVersions = stringMap(value.allowedVersions);
  if (ignoreMissing.length > 0) rules.ignoreMissing = ignoreMissing;
  if (allowAny.length > 0) rules.allowAny = allowAny;
  if (Object.keys(allowedVersions).length > 0) rules.allowedVersions = allowedVersions;
  return Object.keys(rules).length > 0 ? rules : null;
}

function hashNamedFiles(root, names) {
  const files = discoverNamedFiles(root, new Set(names));
  return new Map(
    files.map((file) => [
      slash(path.relative(root, file)),
      crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
    ]),
  );
}

function lockMapsEqual(left, right) {
  return lockMapDifferences(left, right).length === 0;
}

function lockMapDifferences(expected, actual) {
  const paths = [...new Set([...expected.keys(), ...actual.keys()])].sort();
  return paths
    .filter((relative) => expected.get(relative) !== actual.get(relative))
    .map((relative) => ({
      path: relative,
      expected_sha256: expected.get(relative) ?? null,
      actual_sha256: actual.get(relative) ?? null,
    }));
}

function preserveNamedFiles(root, names, destination) {
  const files = discoverNamedFiles(root, new Set(names));
  for (const file of files) {
    const relative = path.relative(root, file);
    const output = path.join(destination, relative);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.copyFileSync(file, output);
  }
}

function discoverNamedFiles(root, names) {
  const found = [];
  walkWorkspace(root, (entry, type) => {
    if (type.isFile() && names.has(path.basename(entry))) found.push(entry);
  });
  return found.sort();
}

function removeNamedFiles(root, names, guardRoot) {
  for (const file of discoverNamedFiles(root, new Set(names))) {
    assertInside(guardRoot, file);
    fs.rmSync(file, { force: true });
  }
}

function removeNamedDirectories(root, name, guardRoot) {
  const directories = [];
  walkWorkspace(root, (entry, type) => {
    if (type.isDirectory() && path.basename(entry) === name) directories.push(entry);
  });
  directories.sort((left, right) => right.length - left.length);
  for (const directory of directories) removeTree(directory, guardRoot);
}

function walkWorkspace(root, visit) {
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      visit(full, entry);
      if (
        entry.isDirectory() &&
        !entry.isSymbolicLink() &&
        !['.git', '.lpm', '.next', '.nuxt', '.output', '.turbo', 'coverage', 'dist', 'node_modules', 'target'].includes(entry.name)
      ) {
        pending.push(full);
      }
    }
  }
}

function removeTree(target, guardRoot) {
  assertInside(guardRoot, target);
  fs.rmSync(target, { recursive: true, force: true });
}

function cleanupCompletedDeterminismRun(
  workspace,
  stateRoot,
  guardRoot,
  preserveWorkspaces,
) {
  if (preserveWorkspaces) return;
  removeTree(workspace, guardRoot);
  if (stateRoot != null) removeTree(stateRoot, guardRoot);
}

function assertInside(root, target) {
  const relative = path.relative(path.resolve(root), path.resolve(target));
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`refusing destructive operation outside a child of ${root}: ${target}`);
  }
}

function loadProjects(file) {
  const projects = readJson(file);
  assert(Array.isArray(projects) && projects.length > 0, 'projects config must be a non-empty array');
  const ids = new Set();
  for (const project of projects) validateProject(project, ids);
  return projects;
}

function validateProject(project, ids = new Set()) {
  assert.match(project.id ?? '', /^[a-z0-9][a-z0-9-]*$/, 'invalid project id');
  assert(!ids.has(project.id), `duplicate project id: ${project.id}`);
  ids.add(project.id);
  assert.match(
    project.repository ?? '',
    /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/,
    `invalid GitHub repository for ${project.id}`,
  );
  assert.match(project.commit ?? '', /^[0-9a-f]{40}$/, `invalid commit for ${project.id}`);
  if (project.fresh_solve != null) {
    assert(
      typeof project.fresh_solve === 'object' && !Array.isArray(project.fresh_solve),
      `fresh_solve must be an object for ${project.id}`,
    );
    assert.deepEqual(
      Object.keys(project.fresh_solve).sort(),
      ['expected_unused_patches'],
      `fresh_solve has unsupported fields for ${project.id}`,
    );
    const patches = project.fresh_solve.expected_unused_patches;
    assert(Array.isArray(patches), `expected_unused_patches must be an array for ${project.id}`);
    assert(
      patches.every((patch) => typeof patch === 'string' && patch.trim() === patch && patch !== ''),
      `expected_unused_patches must contain non-empty trimmed strings for ${project.id}`,
    );
    assert.equal(
      new Set(patches).size,
      patches.length,
      `expected_unused_patches must not contain duplicates for ${project.id}`,
    );
  }
  if (project.reference_compatibility != null) {
    assertPlainObject(
      project.reference_compatibility,
      `reference_compatibility must be an object for ${project.id}`,
    );
    assert.deepEqual(
      Object.keys(project.reference_compatibility),
      ['pnpm_compatibility_database'],
      `reference_compatibility has unsupported fields for ${project.id}`,
    );
    const database = project.reference_compatibility.pnpm_compatibility_database;
    assertPlainObject(
      database,
      `pnpm_compatibility_database must be an object for ${project.id}`,
    );
    assert.deepEqual(
      Object.keys(database).sort(),
      ['git_commit', 'package', 'package_extensions'],
      `pnpm_compatibility_database has unsupported fields for ${project.id}`,
    );
    assert.match(
      database.package ?? '',
      /^@yarnpkg\/extensions@[^\s]+$/,
      `invalid pnpm compatibility database package for ${project.id}`,
    );
    assert.match(
      database.git_commit ?? '',
      /^[0-9a-f]{40}$/,
      `invalid pnpm compatibility database commit for ${project.id}`,
    );
    validatePackageExtensions(database.package_extensions, project.id);
  }
  if (project.correction_verification != null) {
    assertPlainObject(
      project.correction_verification,
      `correction_verification must be an object for ${project.id}`,
    );
    assert.deepEqual(
      Object.keys(project.correction_verification),
      ['typosquat_allow'],
      `correction_verification has unsupported fields for ${project.id}`,
    );
    const entries = project.correction_verification.typosquat_allow;
    assert(
      Array.isArray(entries) && entries.length > 0,
      `typosquat_allow must be a non-empty array for ${project.id}`,
    );
    const identities = new Set();
    for (const entry of entries) {
      assertPlainObject(entry, `typosquat_allow entries must be objects for ${project.id}`);
      assert.deepEqual(
        Object.keys(entry).sort(),
        ['importer', 'package', 'reason', 'similar_to'],
        `typosquat_allow entry has unsupported fields for ${project.id}`,
      );
      assert(
        normalizeImporterPathsForValidation([entry.importer]).length === 1,
        `invalid typosquat_allow importer for ${project.id}`,
      );
      for (const field of ['package', 'similar_to', 'reason']) {
        assert(
          typeof entry[field] === 'string' &&
            entry[field] !== '' &&
            entry[field].trim() === entry[field] &&
            !/\p{Cc}/u.test(entry[field]),
          `invalid typosquat_allow ${field} for ${project.id}`,
        );
      }
      const identity = `${entry.importer}\0${entry.package}\0${entry.similar_to}`;
      assert(!identities.has(identity), `duplicate typosquat_allow entry for ${project.id}`);
      identities.add(identity);
    }
  }
}

function normalizeImporterPathsForValidation(importerPaths) {
  assert(Array.isArray(importerPaths), 'importer paths must be an array');
  const normalized = sortedUnique(importerPaths.map((entry) => slash(entry)));
  for (const importerPath of normalized) {
    assert(
      importerPath === '.' ||
        (typeof importerPath === 'string' &&
          importerPath !== '' &&
          !path.isAbsolute(importerPath) &&
          importerPath !== '..' &&
          !importerPath.startsWith('../') &&
          !importerPath.includes('/../')),
      `invalid recursive importer path: ${importerPath}`,
    );
  }
  return normalized;
}

function assertPlainObject(value, message) {
  assert(value != null && typeof value === 'object' && !Array.isArray(value), message);
}

function validatePackageExtensions(extensions, projectId) {
  assertPlainObject(extensions, `package_extensions must be an object for ${projectId}`);
  assert(Object.keys(extensions).length > 0, `package_extensions must not be empty for ${projectId}`);
  const supportedFields = new Set([
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'peerDependenciesMeta',
  ]);
  for (const [selector, extension] of Object.entries(extensions)) {
    assert(
      selector !== '' && selector.trim() === selector,
      `package extension selectors must be non-empty and trimmed for ${projectId}`,
    );
    assertPlainObject(extension, `package extension ${selector} must be an object for ${projectId}`);
    const fields = Object.keys(extension);
    assert(fields.length > 0, `package extension ${selector} must not be empty for ${projectId}`);
    assert(
      fields.every((field) => supportedFields.has(field)),
      `package extension ${selector} has unsupported fields for ${projectId}`,
    );
    for (const field of fields) {
      assertPlainObject(
        extension[field],
        `package extension ${selector}.${field} must be an object for ${projectId}`,
      );
      if (field !== 'peerDependenciesMeta') {
        assert(
          Object.entries(extension[field]).every(
            ([name, range]) => name !== '' && typeof range === 'string' && range !== '',
          ),
          `package extension ${selector}.${field} must map names to ranges for ${projectId}`,
        );
      }
    }
  }
}

function selectProjects(projects, raw) {
  const requested = raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  assert(requested.length > 0, '--projects must select at least one project');
  const byId = new Map(projects.map((project) => [project.id, project]));
  return requested.map((id) => {
    const project = byId.get(id);
    if (!project) throw new Error(`unknown project ${id}; choices: ${[...byId.keys()].join(',')}`);
    return project;
  });
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === '--help') parsed.help = true;
    else if (value === '--self-test') parsed.selfTest = true;
    else if (value === '--keep-workspaces') parsed.keepWorkspaces = true;
    else if (value === '--materialize-reference') parsed.materializeReference = true;
    else if (value === '--projects') parsed.projects = requiredArg(values, ++index, value);
    else if (value === '--output') parsed.output = requiredArg(values, ++index, value);
    else if (value === '--lpm-bin') parsed.lpmBin = requiredArg(values, ++index, value);
    else if (value === '--verifier-bin') parsed.verifierBin = requiredArg(values, ++index, value);
    else if (value === '--timeout-ms') parsed.timeoutMs = requiredArg(values, ++index, value);
    else if (value === '--determinism-runs')
      parsed.determinismRuns = requiredArg(values, ++index, value);
    else throw new Error(`unknown argument: ${value}`);
  }
  return parsed;
}

function requiredArg(values, index, flag) {
  if (index >= values.length || values[index].startsWith('--')) {
    throw new Error(`${flag} requires a value`);
  }
  return values[index];
}

function positiveInt(raw, fallback, flag) {
  const value = raw == null ? fallback : Number(raw);
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${flag} must be a positive integer`);
  return value;
}

function boundedInt(raw, fallback, minimum, maximum, flag) {
  const value = raw == null ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${flag} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function requiredBinary(value) {
  const resolved = path.resolve(value);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    throw new Error(`binary does not exist: ${resolved}`);
  }
  return resolved;
}

function prepareOutputDirectory(value) {
  const resolved = path.resolve(value);
  if (fs.existsSync(resolved) && fs.readdirSync(resolved).length > 0) {
    throw new Error(`output directory must be absent or empty: ${resolved}`);
  }
  fs.mkdirSync(resolved, { recursive: true });
  return resolved;
}

function commandVersion(command, commandArgs, cwd, env = process.env) {
  return runCommand(command, commandArgs, { cwd, env, timeoutMs: 120_000 }).stdout.trim();
}

function parseJsonOutput(output, label) {
  try {
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`${label} did not emit valid JSON: ${error.message}`);
  }
}

function classifyPnpmInstallPolicyBlock(run) {
  if (run.status === 0 || run.error) return null;
  const output = stripVTControlCharacters(`${run.stdout ?? ''}\n${run.stderr ?? ''}`);
  const trustDowngrade = output.match(
    /\[ERR_PNPM_TRUST_DOWNGRADE\]\s+(High-risk trust downgrade for "([^"]+)"[^\r\n]*)/,
  );
  if (trustDowngrade != null) {
    const identity = splitNpmPackageIdentity(trustDowngrade[2]);
    if (identity == null) return null;
    return {
      code: 'trust_downgrade',
      manager: 'pnpm',
      phase: 'reference_fresh_solve',
      package: identity.package,
      version: identity.version,
      package_identity: trustDowngrade[2],
      message: trustDowngrade[1],
    };
  }

  const missingReleaseTime = output.match(
    /\[ERR_PNPM_MISSING_TIME\]\s+(The metadata of ([^\s"]+) is missing the "time" field)/,
  );
  if (missingReleaseTime == null) return null;
  return {
    code: 'missing_release_time',
    manager: 'pnpm',
    phase: 'reference_fresh_solve',
    package: missingReleaseTime[2],
    package_identity: missingReleaseTime[2],
    message: missingReleaseTime[1],
  };
}

function splitNpmPackageIdentity(identity) {
  const separator = identity.lastIndexOf('@');
  if (separator <= 0 || separator === identity.length - 1) return null;
  return {
    package: identity.slice(0, separator),
    version: identity.slice(separator + 1),
  };
}

function readJson(file) {
  const content = fs.readFileSync(file, 'utf8');
  return JSON.parse(content.charCodeAt(0) === 0xfeff ? content.slice(1) : content);
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function stageSummary(result) {
  return result?.stages?.lpm_install?.wall_ms ?? null;
}

function summarize(results) {
  return {
    schema_version: 1,
    total: results.length,
    passed: results.filter((result) => result.status === 'passed').length,
    discrepancies: results.filter((result) => result.status === 'discrepancies').length,
    capability_gaps: results.filter((result) => result.status === 'capability_gap').length,
    policy_blocks: results.filter((result) => result.status === 'policy_block').length,
    failed: results.filter((result) => result.status === 'failed').length,
    nonpassing: results.filter((result) => result.status !== 'passed').length,
    projects: results,
  };
}

function renderSummary(results) {
  const lines = [
    '# Ecosystem correction pilot',
    '',
    'Both managers use a strict one-day minimum release age, including transitive packages. Lifecycle phases are removed from both temporary workspace copies and recorded in each project result.',
    '',
    '| Project | Status | pnpm install | LPM install | Graph errors | LPM layout failures | Replay | Determinism | Non-graph blocker |',
    '|---|---|---:|---:|---:|---:|---|---|---|',
  ];
  for (const result of results) {
    lines.push(
      `| ${result.id} | ${result.status} | ${formatMs(result.stages?.pnpm_install?.wall_ms)} | ${formatMs(stageSummary(result))} | ${result.comparison?.errors ?? '—'} | ${result.layout?.lpm_failures ?? '—'} | ${formatPass(result.replay?.passed)} | ${formatPass(result.determinism?.passed)} | ${formatNonGraphBlocker(result)} |`,
    );
  }
  return lines.join('\n');
}

function formatNonGraphBlocker(result) {
  if (result.capability_gap != null) {
    return `${result.capability_gap.code} (${result.capability_gap.package})`;
  }
  if (result.policy_block != null) {
    return `${result.policy_block.code} (${result.policy_block.package_identity})`;
  }
  return '—';
}

function formatMs(value) {
  return value == null ? '—' : `${Math.round(value).toLocaleString('en-US')} ms`;
}

function formatPass(value) {
  return value == null ? '—' : value ? 'pass' : 'fail';
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

function slash(value) {
  return value.split(path.sep).join('/');
}

function defaultOutputDir() {
  return path.join(os.tmpdir(), `lpm-ecosystem-correction-${new Date().toISOString().replaceAll(/[:.]/g, '-')}`);
}

function runSelfTests() {
  const parsed = parseArgs([
    '--projects',
    'vite,vue',
    '--determinism-runs',
    '3',
    '--keep-workspaces',
    '--materialize-reference',
  ]);
  assert.equal(parsed.projects, 'vite,vue');
  assert.equal(parsed.determinismRuns, '3');
  assert.deepEqual(
    mergePnpmPolicy(
      {
        auto_install_peers: null,
        minimum_release_age_exclude: null,
        overrides: null,
        package_extensions: null,
        patched_dependencies: null,
        peer_dependency_rules: null,
        trust_policy: null,
      },
      {
        autoInstallPeers: true,
        overrides: { postcss: '8.5.10' },
        patchedDependencies: { fixture: 'patches/fixture.patch' },
      },
    ),
    {
      auto_install_peers: true,
      minimum_release_age_exclude: null,
      overrides: { postcss: '8.5.10' },
      package_extensions: null,
      patched_dependencies: { fixture: 'patches/fixture.patch' },
      peer_dependency_rules: null,
      trust_policy: null,
    },
  );
  assert.deepEqual(
    comparisonPolicy({
      source: { overrides: { postcss: '8.5.10', vite: 'catalog:' } },
      unsupported: { overrides: { vite: 'catalog:' } },
    }),
    {
      overrides: { vite: 'catalog:' },
      reference_peer_overrides: { postcss: '8.5.10', vite: 'catalog:' },
    },
  );
  assert.equal(installedVersionMatches('1.28.1', 'v1.28.1'), true);
  assert.equal(installedVersionMatches('1.28.1', 'v1.28.2'), false);
  assert.equal(parsed.keepWorkspaces, true);
  assert.equal(parsed.materializeReference, true);
  assert.deepEqual(determinismExecutionPlan(3), [
    { kind: 'metadata-cache-warm', concurrency: 'auto' },
    { kind: 'fresh', concurrency: '1' },
    { kind: 'fresh', concurrency: '3' },
  ]);

  const fixtureProjects = [
    {
      id: 'vite',
      repository: 'https://github.com/vitejs/vite.git',
      commit: 'e6b6b167afa0a80548829d1f24a0712f9194389a',
    },
    {
      id: 'vue',
      repository: 'https://github.com/vuejs/core.git',
      commit: 'b5f8518379b77c3b62a7a9d2b52f6c76cda09bd5',
    },
  ];
  const selected = selectProjects(fixtureProjects, 'vue,vite');
  assert.deepEqual(selected.map((project) => project.id), ['vue', 'vite']);
  const patchBearingProject = {
    ...fixtureProjects[0],
    fresh_solve: {
      expected_unused_patches: [
        'vue-tsc@2.2.8',
        '@types/express-serve-static-core@5.0.6',
      ],
    },
  };
  validateProject(patchBearingProject);
  assert.deepEqual(expectedUnusedPatches(patchBearingProject), [
    '@types/express-serve-static-core@5.0.6',
    'vue-tsc@2.2.8',
  ]);
  assert.deepEqual(
    parsePnpmUnusedPatches(
      '\u001b[33mWARN\u001b[39m The following patches were not used: vue-tsc@2.2.8, @types/express-serve-static-core@5.0.6',
    ),
    ['@types/express-serve-static-core@5.0.6', 'vue-tsc@2.2.8'],
  );
  assert.deepEqual(parsePnpmUnusedPatches('Lockfile is up to date'), []);
  assert(pnpmInstallArgs(fixtureProjects[0], false).includes('--config.engine-strict=false'));
  assert(
    pnpmInstallArgs(fixtureProjects[0], false).includes(
      '--config.minimum-release-age-strict=true',
    ),
  );
  assert.throws(() =>
    validateProject({
      ...fixtureProjects[0],
      fresh_solve: { expected_unused_patches: ['vue-tsc@2.2.8', 'vue-tsc@2.2.8'] },
    }),
  );
  const compatibilityProject = {
    ...fixtureProjects[0],
    reference_compatibility: {
      pnpm_compatibility_database: {
        package: '@yarnpkg/extensions@2.0.6',
        git_commit: 'a9edb7777f04ba16f51503ef6775325b353b67cc',
        package_extensions: {
          'notistack@^3.0.0': { dependencies: { csstype: '^3.0.10' } },
        },
      },
    },
  };
  validateProject(compatibilityProject);
  assert.throws(() =>
    validateProject({
      ...compatibilityProject,
      reference_compatibility: {
        pnpm_compatibility_database: {
          ...compatibilityProject.reference_compatibility.pnpm_compatibility_database,
          git_commit: 'main',
        },
      },
    }),
  );
  assert(baseLpmArgs().includes('--no-engine-strict'));
  assert.throws(() => validateProject({ id: '../escape', repository: 'x', commit: 'x' }));
  assert.throws(() => boundedInt('4', 1, 1, 3, '--determinism-runs'));
  const failureDetail = commandFailureDetail({
    stdout: '{"success":false,"error":"manifest rejected"}',
    stderr: 'warning emitted before failure',
  });
  assert.match(failureDetail, /manifest rejected/);
  assert.match(failureDetail, /warning emitted before failure/);
  assert.deepEqual(
    classifyPnpmInstallPolicyBlock({
      status: 1,
      stdout:
        '[ERR_PNPM_TRUST_DOWNGRADE] High-risk trust downgrade for "@netlify/serverless-functions-api@2.16.0" (possible package takeover)\n\nTrust checks are based solely on publish date.',
      stderr: '',
    }),
    {
      code: 'trust_downgrade',
      manager: 'pnpm',
      phase: 'reference_fresh_solve',
      package: '@netlify/serverless-functions-api',
      version: '2.16.0',
      package_identity: '@netlify/serverless-functions-api@2.16.0',
      message:
        'High-risk trust downgrade for "@netlify/serverless-functions-api@2.16.0" (possible package takeover)',
    },
  );
  assert.deepEqual(
    classifyPnpmInstallPolicyBlock({
      status: 1,
      stdout:
        '[ERR_PNPM_MISSING_TIME] The metadata of typescript is missing the "time" field\n\nThis error happened while installing a direct dependency',
      stderr: '',
    }),
    {
      code: 'missing_release_time',
      manager: 'pnpm',
      phase: 'reference_fresh_solve',
      package: 'typescript',
      package_identity: 'typescript',
      message: 'The metadata of typescript is missing the "time" field',
    },
  );
  assert.equal(
    classifyPnpmInstallPolicyBlock({
      status: 1,
      stdout: '[ERR_PNPM_FETCH_500] registry unavailable',
      stderr: '',
    }),
    null,
  );
  assert.deepEqual(
    summarize([
      { status: 'passed' },
      { status: 'discrepancies' },
      { status: 'capability_gap' },
      { status: 'policy_block' },
      { status: 'failed' },
    ]),
    {
      schema_version: 1,
      total: 5,
      passed: 1,
      discrepancies: 1,
      capability_gaps: 1,
      policy_blocks: 1,
      failed: 1,
      nonpassing: 4,
      projects: [
        { status: 'passed' },
        { status: 'discrepancies' },
        { status: 'capability_gap' },
        { status: 'policy_block' },
        { status: 'failed' },
      ],
    },
  );

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-correction-self-test-'));
  try {
    const workspace = path.join(directory, 'workspace');
    writeJson(path.join(workspace, 'package.json'), {
      name: 'root',
      scripts: { preinstall: 'only-allow pnpm', test: 'vitest' },
    });
    writeJson(path.join(workspace, 'packages/member/package.json'), {
      name: 'member',
      scripts: { prepare: 'build', lint: 'eslint .' },
    });
    writeJson(path.join(workspace, 'fixtures/not-a-member/package.json'), {
      name: 'not-a-member',
    });
    const normalizedScripts = disableWorkspaceLifecycleScripts(workspace);
    assert.deepEqual(normalizedScripts, [
      { path: 'package.json', phases: ['preinstall'] },
      { path: 'packages/member/package.json', phases: ['prepare'] },
    ]);
    assert.deepEqual(readJson(path.join(workspace, 'package.json')).scripts, { test: 'vitest' });
    assert.deepEqual(readJson(path.join(workspace, 'packages/member/package.json')).scripts, {
      lint: 'eslint .',
    });
    const policyNormalization = applyEquivalentLpmPolicy(
      workspace,
      {
        auto_install_peers: false,
        minimum_release_age_exclude: [
          'rolldown',
          'rolldown@1.2.1',
          '@rolldown/*',
          '@rolldown/binding-*',
        ],
        overrides: { rolldown: '~1.2.1', debug: 'npm:obug@^1.0.2' },
        package_extensions: { fixture: { dependencies: { extra: '1.0.0' } } },
        patched_dependencies: { 'fixture@1.0.0': 'patches/fixture.patch' },
        peer_dependency_rules: { allowedVersions: { vite: '*' } },
        trust_policy: 'no-downgrade',
      },
      ['.', 'packages/member'],
    );
    assert.deepEqual(policyNormalization.translated, {
      auto_install_peers: false,
      minimum_release_age_exclude: ['@rolldown/*', 'rolldown', 'rolldown@1.2.1'],
      overrides: { rolldown: '~1.2.1' },
      peer_dependency_rules: { allowedVersions: { vite: '*' } },
      trust_policy: 'no-downgrade',
    });
    assert.deepEqual(policyNormalization.unsupported.minimum_release_age_exclude, [
      '@rolldown/binding-*',
    ]);
    assert.deepEqual(policyNormalization.unsupported.overrides, {
      debug: 'npm:obug@^1.0.2',
    });
    const correctionProject = {
      ...fixtureProjects[0],
      correction_verification: {
        typosquat_allow: [
          {
            importer: 'packages/member',
            package: 'mysql2',
            similar_to: 'mysql',
            reason: 'Pinned self-test dependency',
          },
        ],
      },
    };
    validateProject(correctionProject);
    assert.deepEqual(applyPinnedLpmVerificationPolicy(correctionProject, workspace), {
      typosquat_allow: correctionProject.correction_verification.typosquat_allow,
    });
    assert.match(
      fs.readFileSync(path.join(workspace, 'packages/member/lpm.toml'), 'utf8'),
      /package = "mysql2"\nsimilar-to = "mysql"\nreason = "Pinned self-test dependency"/,
    );
    const referenceCompatibility = applyPinnedReferenceCompatibility(
      compatibilityProject,
      policyNormalization,
    );
    assert.deepEqual(referenceCompatibility, compatibilityProject.reference_compatibility);
    assert.deepEqual(policyNormalization.unsupported.pnpm_compatibility_database_extensions, {
      'notistack@^3.0.0': { dependencies: { csstype: '^3.0.10' } },
    });
    const normalizedManifest = readJson(path.join(workspace, 'package.json'));
    assert.equal(normalizedManifest.lpm.autoInstallPeers, false);
    assert.deepEqual(normalizedManifest.lpm.overrides, { rolldown: '~1.2.1' });
    const normalizedMemberManifest = readJson(
      path.join(workspace, 'packages/member/package.json'),
    );
    assert.equal(normalizedMemberManifest.lpm.autoInstallPeers, false);
    assert.deepEqual(normalizedMemberManifest.lpm.minimumReleaseAgeExclude, [
      '@rolldown/*',
      'rolldown',
      'rolldown@1.2.1',
    ]);
    assert.deepEqual(normalizedMemberManifest.lpm.overrides, { rolldown: '~1.2.1' });
    assert.deepEqual(normalizedMemberManifest.lpm.peerDependencyRules, {
      allowedVersions: { vite: '*' },
    });
    assert.equal(readJson(path.join(workspace, 'fixtures/not-a-member/package.json')).lpm, undefined);
    assert.deepEqual(policyNormalization.applied_importers, ['.', 'packages/member']);
    const lpmState = path.join(directory, 'lpm-state');
    const lpmEnv = lpmCorrectionEnvironment(lpmState, policyNormalization);
    assert.equal(
      fs.readFileSync(path.join(lpmEnv.LPM_HOME, 'config.toml'), 'utf8'),
      'minimum-release-age-secs = 86400\nrelease-age-policy = "strict"\nminimum-release-age-exclude = ["@rolldown/*", "rolldown", "rolldown@1.2.1"]\nauto-install-peers = false\ntrust-policy = "no-downgrade"\n',
    );
    assert.equal(lpmEnv.HOME, path.join(lpmState, 'home'));
    assert.equal(lpmEnv.LPM_NPM_ROUTE, 'direct');
    fs.writeFileSync(
      path.join(workspace, 'bom.json'),
      '\uFEFF{"name":"bom-package","version":"1.0.0"}',
    );
    assert.equal(readJson(path.join(workspace, 'bom.json')).name, 'bom-package');
    const packageDir = path.join(workspace, 'node_modules/example');
    fs.mkdirSync(packageDir, { recursive: true });
    writeJson(path.join(packageDir, 'package.json'), { name: 'example', version: '1.2.3' });
    const layout = verifyDirectLayout(workspace, {
      importers: {
        '.': {
          path: '.',
          direct_dependencies: [
            {
              kind: 'production',
              local_name: 'example',
              target: { name: 'example', version: '1.2.3' },
            },
          ],
        },
      },
    });
    assert.equal(layout.checked, 1);
    assert.deepEqual(layout.failures, []);

    if (process.platform !== 'win32') {
      const pendingLink = path.join(workspace, 'node_modules/@fixture/pending');
      fs.mkdirSync(path.dirname(pendingLink), { recursive: true });
      fs.symlinkSync('../../packages/pending/build', pendingLink, 'dir');
      const pendingLayout = verifyDirectLayout(workspace, {
        importers: {
          '.': {
            path: '.',
            direct_dependencies: [
              {
                kind: 'production',
                local_name: '@fixture/pending',
                target: {
                  kind: 'workspace',
                  name: '@fixture/pending',
                  version: null,
                  path: 'packages/pending/build',
                },
              },
            ],
          },
        },
      });
      assert.equal(pendingLayout.checked, 1);
      assert.equal(pendingLayout.workspace_projections_pending, 1);
      assert.deepEqual(pendingLayout.failures, []);
    }

    writeJson(path.join(workspace, 'lpm.lock'), { stable: true });
    const first = hashNamedFiles(workspace, ['lpm.lock']);
    const second = hashNamedFiles(workspace, ['lpm.lock']);
    assert.equal(lockMapsEqual(first, second), true);
    fs.writeFileSync(path.join(workspace, 'lpm.lock'), '{"stable":false}\n');
    const changed = hashNamedFiles(workspace, ['lpm.lock']);
    assert.deepEqual(lockMapDifferences(first, changed).map((difference) => difference.path), [
      'lpm.lock',
    ]);
    const preserved = path.join(directory, 'preserved');
    preserveNamedFiles(workspace, ['lpm.lock'], preserved);
    assert.equal(
      fs.readFileSync(path.join(preserved, 'lpm.lock'), 'utf8'),
      '{"stable":false}\n',
    );
    const nestedModules = path.join(workspace, 'packages/member/node_modules/example');
    fs.mkdirSync(nestedModules, { recursive: true });
    removeNamedDirectories(workspace, 'node_modules', directory);
    assert.equal(fs.existsSync(path.join(workspace, 'packages/member/node_modules')), false);
    assert.equal(fs.existsSync(path.join(workspace, 'packages/member/package.json')), true);

    const completedWorkspace = path.join(directory, 'completed-determinism-workspace');
    const completedState = path.join(directory, 'completed-determinism-state');
    writeJson(path.join(completedWorkspace, 'lpm.lock'), { stable: true });
    writeJson(path.join(completedState, 'home/state.json'), { cached: true });
    cleanupCompletedDeterminismRun(completedWorkspace, completedState, directory, false);
    assert.equal(fs.existsSync(completedWorkspace), false);
    assert.equal(fs.existsSync(completedState), false);
  } finally {
    removeTree(directory, os.tmpdir());
  }
  console.log('run-ecosystem-correction self-test passed');
}

function printHelp() {
  console.log(`Usage: node bench/scripts/run-ecosystem-correction.mjs [options]

Options:
  --projects <ids>          Comma-separated project ids (default: vite,vue,n8n)
  --output <dir>            Empty artifact directory (default: unique /tmp directory)
  --lpm-bin <path>          Source-built LPM binary
  --verifier-bin <path>     Source-built canonical graph verifier
  --timeout-ms <ms>         Per-command timeout (default: 1800000)
  --determinism-runs <1-3>  Fresh-state scheduling runs; cache-warm parity always runs
  --materialize-reference   Also build pnpm node_modules and verify its direct layout
  --keep-workspaces         Preserve temporary source/install workspaces
  --self-test               Validate harness logic without network access
  --help                    Show this help
`);
}
