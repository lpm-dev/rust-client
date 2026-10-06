#!/usr/bin/env python3
"""Export a pinned universal macOS engine from immutable source inputs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(256 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def source_hashes(root):
    inputs = [root / 'Cargo.toml', root / 'Cargo.lock', root / 'scripts/export-env-engine.py']
    inputs += [path for path in [root / '.cargo/config.toml', root / 'rust-toolchain.toml'] if path.is_file()]
    for crate in ['lpm-env', 'lpm-env-source', 'lpm-env-ffi']:
        inputs += sorted(path for path in (root / 'crates' / crate).rglob('*') if path.is_file())
    return {str(path.relative_to(root)): file_hash(path) for path in inputs}


def export(root, target_dir, output):
    target_dir = target_dir.resolve() / 'env-engine-export'
    target_dir.mkdir(parents=True, exist_ok=True)
    with (target_dir / 'export.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return export_locked(root, target_dir, output)


def export_locked(root, target_dir, output):
    target_dir = target_dir.resolve()
    output = output.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and any(path.name not in {'LPMEnv.xcframework', 'provenance.json'} for path in output.iterdir()):
        raise RuntimeError('Output contains files outside the engine bundle')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    recorded_sources = source_hashes(root)
    for relative, digest in recorded_sources.items():
        try:
            committed = subprocess.check_output(['git', 'show', revision + ':' + relative], cwd=root, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as error:
            raise RuntimeError('Engine inputs do not match the recorded revision: ' + relative) from error
        if hashlib.sha256(committed).hexdigest() != digest:
            raise RuntimeError('Engine inputs do not match the recorded revision: ' + relative)
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).split(b'\0')
    targets = ['aarch64-apple-darwin', 'x86_64-apple-darwin']
    with tempfile.TemporaryDirectory(prefix='lpm-env-source-') as temporary, tempfile.TemporaryDirectory(prefix='.lpm-env-export-', dir=output.parent) as publication:
        frozen = Path(temporary).resolve()
        for raw in paths:
            if not raw:
                continue
            relative = Path(os.fsdecode(raw))
            source = root / relative
            if not source.is_file():
                continue
            destination = frozen / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        sources = source_hashes(frozen)
        if source_hashes(root) != sources:
            raise RuntimeError('Engine sources changed during capture')
        env = {key: value for key, value in os.environ.items() if key in {
            'PATH', 'HOME', 'TMPDIR', 'CARGO_HOME', 'RUSTUP_HOME', 'DEVELOPER_DIR', 'SDKROOT',
        }}
        cargo_home = Path(env.get('CARGO_HOME', str(Path.home() / '.cargo'))).resolve()
        flags = ['--remap-path-prefix=' + str(frozen) + '=/lpm-rust-client', '--remap-path-prefix=' + str(cargo_home) + '=/lpm-cargo']
        env.update(CARGO_TARGET_DIR=str(target_dir), CARGO_INCREMENTAL='0', ZERO_AR_DATE='1', CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
        for target in targets:
            if shutil.disk_usage(target_dir).free < 10 * 1024**3:
                raise RuntimeError('At least 10 GiB free is required on the Cargo target volume')
            subprocess.run(['cargo', '+1.94.0', 'build', '--locked', '--release', '-p', 'lpm-env-ffi', '--target', target], cwd=frozen, env=env, check=True)
        staging = Path(publication) / 'bundle'
        staging.mkdir()
        library = Path(publication) / 'libLPMEnv.a'
        artifact = staging / 'LPMEnv.xcframework'
        subprocess.run(['lipo', '-create', *[str(target_dir / target / 'release/liblpm_env_ffi.a') for target in targets], '-output', str(library)], env=env, check=True)
        sysroot = subprocess.check_output(['rustc', '+1.94.0', '--print', 'sysroot'], env=env, text=True).strip()
        version = subprocess.check_output(['rustc', '+1.94.0', '-vV'], env=env, text=True)
        host = next(line.removeprefix('host: ') for line in version.splitlines() if line.startswith('host: '))
        objcopy = Path(sysroot) / 'lib/rustlib' / host / 'bin/llvm-objcopy'
        subprocess.run([str(objcopy), '--strip-debug', '--enable-deterministic-archives', '--remove-section=__LLVM,__bitcode', '--remove-section=__LLVM,__cmdline', str(library)], env=env, check=True)
        subprocess.run(['xcodebuild', '-create-xcframework', '-library', str(library), '-headers', str(frozen / 'crates/lpm-env-ffi/include'), '-output', str(artifact)], env=env, check=True)
        files = {str(path.relative_to(staging)): file_hash(path) for path in artifact.rglob('*') if path.is_file()}
        provenance = dict(abiVersion=1, toolchain='1.94.0', targets=targets, repository='https://github.com/lpm-dev/rust-client', revision=revision, sources=sources, artifacts=files)
        (staging / 'provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n')
        if source_hashes(root) != sources or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip() != revision:
            raise RuntimeError('Engine sources changed during export')
        backup = Path(publication) / 'previous'
        if output.exists():
            os.replace(output, backup)
        try:
            os.replace(staging, output)
        except BaseException:
            if backup.exists():
                os.replace(backup, output)
            raise
    print('Exported ' + str(output / 'LPMEnv.xcframework'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    export(Path(__file__).resolve().parents[1], args.target_dir, args.output)


if __name__ == '__main__':
    main()
