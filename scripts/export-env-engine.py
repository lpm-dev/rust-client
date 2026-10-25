#!/usr/bin/env python3
"""Export a pinned universal macOS engine from immutable source inputs."""
import argparse
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

NOTICES = 'THIRD_PARTY_NOTICES.html'
# The companion storage contract both clients test against, shipped with the
# engine so the app reads the fixtures of the revision it links.
FIXTURES = Path('crates/lpm-vault/tests/fixtures/companion')
BUNDLED_FIXTURES = Path('fixtures/companion')
LICENSE_FILE_PREFIXES = ('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE', 'UNLICENSE')


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(256 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def engine_crates(root):
    """The workspace crates the engine builds from, relative to root: lpm-env-ffi and every path dependency it reaches, build and target-specific ones included."""
    shared = tomllib.loads((root / 'Cargo.toml').read_text()).get('workspace', {}).get('dependencies', {})
    found = set()
    pending = [Path('crates/lpm-env-ffi')]
    while pending:
        crate = pending.pop()
        if crate in found:
            continue
        found.add(crate)
        manifest = tomllib.loads((root / crate / 'Cargo.toml').read_text())
        for table in [manifest, *manifest.get('target', {}).values()]:
            for kind in ['dependencies', 'build-dependencies']:
                for name, spec in table.get(kind, {}).items():
                    base = crate
                    if isinstance(spec, dict) and spec.get('workspace'):
                        spec, base = shared.get(name), Path()
                    if isinstance(spec, dict) and 'path' in spec:
                        path = Path(os.path.normpath(base / spec['path']))
                        if path.is_absolute() or path.parts[:1] == ('..',):
                            raise RuntimeError('Engine dependency outside the repository: ' + name)
                        pending.append(path)
    return sorted(found)


def fixture_paths(root):
    directory = root / FIXTURES
    return sorted(path for path in directory.glob('*.json') if path.is_file()) if directory.is_dir() else []


def source_hashes(root):
    inputs = [root / 'Cargo.toml', root / 'Cargo.lock', root / 'scripts/export-env-engine.py']
    inputs += [path for path in [root / '.cargo/config.toml', root / 'rust-toolchain.toml'] if path.is_file()]
    for crate in engine_crates(root):
        inputs += sorted(path for path in (root / crate).rglob('*') if path.is_file())
    inputs += fixture_paths(root)
    return {str(path.relative_to(root)): file_hash(path) for path in inputs}


def header_abi_version(root):
    header = (root / 'crates/lpm-env-ffi/include/lpm_env.h').read_text()
    for line in header.splitlines():
        fields = line.split()
        if fields[:2] == ['#define', 'LPM_ENV_ABI_VERSION'] and len(fields) == 3 and fields[2].isdigit():
            return int(fields[2])
    raise RuntimeError('lpm_env.h does not define LPM_ENV_ABI_VERSION')


def linked_packages(metadata_by_target):
    """The registry packages linked into lpm-env-ffi for any of the targets: those its
    normal dependencies reach, without proc macros, which only run while compiling."""
    linked = {}
    for metadata in metadata_by_target:
        packages = {package['id']: package for package in metadata['packages']}
        nodes = {node['id']: node for node in metadata['resolve']['nodes']}
        pending = [next(package['id'] for package in metadata['packages'] if package['name'] == 'lpm-env-ffi' and package['source'] is None)]
        reached = set()
        while pending:
            node = pending.pop()
            if node in reached:
                continue
            reached.add(node)
            for dependency in nodes[node]['deps']:
                package = packages[dependency['pkg']]
                normal = any(kind['kind'] is None for kind in dependency['dep_kinds'])
                if normal and not any('proc-macro' in target['kind'] for target in package['targets']):
                    pending.append(dependency['pkg'])
        for node in reached:
            package = packages[node]
            if package['source'] is not None:
                linked[(package['name'], package['version'])] = package
    return [linked[key] for key in sorted(linked)]


def normalized(data):
    text = data.decode('utf-8', errors='replace').replace('\r\n', '\n').replace('\r', '\n')
    return '\n'.join(line.rstrip() for line in text.split('\n')).strip('\n')


def is_apache_license(text):
    return re.match(r'\s*Apache License\s+Version 2\.0', text) is not None


def license_texts(package, mit_text):
    """The license, copyright and notice files a package ships. A package that may
    be used under MIT alone leaves out its Apache License text when it ships an MIT
    one. One that ships none and offers MIT gets the MIT text in its authors' name;
    any other fails, to be reviewed."""
    directory = Path(package['manifest_path']).parent
    paths = {path for path in directory.iterdir() if path.is_file() and path.name.upper().startswith(LICENSE_FILE_PREFIXES)}
    if package.get('license_file'):
        paths.add(directory / package['license_file'])
    texts = [normalized(path.read_bytes()) for path in sorted(paths, key=lambda path: path.name)]
    expression = package.get('license') or ''
    terms = set(re.findall(r'[A-Za-z0-9.+-]+', expression)) - {'OR', 'AND', 'WITH'}
    mit_alone = 'MIT' in terms and 'AND' not in expression.split()
    if mit_alone and any('Permission is hereby granted' in text for text in texts):
        texts = [text for text in texts if not is_apache_license(text)]
    if texts:
        return texts
    if 'MIT' in terms:
        holders = ', '.join(package.get('authors') or []) or 'the ' + package['name'] + ' authors'
        return [normalized(mit_text.replace('<year> <copyright holders>', holders).encode())]
    raise RuntimeError(package['name'] + ' ' + package['version'] + ' ships no license text; review its license and add its notice')


def third_party_notices(packages, mit_text, data_notices, std_notice):
    """One HTML document of the notices for everything the engine links: each crate
    with the license texts it ships, each distinct text written once, the data
    files' notices, and the Rust standard library's own notices."""
    body = re.search(r'<body>(.*)</body>', std_notice, re.DOTALL | re.IGNORECASE)
    if body is None:
        raise RuntimeError('The Rust standard library notices have no body')
    numbers = {}
    items = []
    for package in packages:
        texts = [numbers.setdefault(text, len(numbers) + 1) for text in license_texts(package, mit_text)]
        name, version = html.escape(package['name']), html.escape(package['version'])
        items.append(
            '<li><b>' + name + '</b> ' + version + ', ' + html.escape(package.get('license') or 'see its texts')
            + ', source https://crates.io/crates/' + name + '/' + version
            + ', texts ' + ', '.join('<a href="#text-' + str(number) + '">' + str(number) + '</a>' for number in texts) + '</li>')
    parts = [
        '<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8">\n<title>Third-party notices for the LPM env engine</title>\n</head>\n<body>',
        '<h1>Third-party notices for the LPM env engine</h1>',
        '<h2>Rust crates</h2>',
        '<ul>\n' + '\n'.join(items) + '\n</ul>',
        '<h2>Crate license texts</h2>',
    ]
    for text, number in numbers.items():
        parts.append('<h3 id="text-' + str(number) + '">' + str(number) + '</h3>\n<pre>' + html.escape(text) + '</pre>')
    if data_notices:
        parts.append('<h2>Data</h2>')
        parts += ['<pre>' + html.escape(normalized(text)) + '</pre>' for text in data_notices]
    parts += ['<h2>The Rust standard library</h2>', body.group(1).strip(), '</body>\n</html>\n']
    return '\n'.join(parts)


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
    if output.exists() and any(path.name not in {'LPMEnv.xcframework', 'provenance.json', NOTICES, BUNDLED_FIXTURES.parts[0]} for path in output.iterdir()):
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
        abi_version = header_abi_version(frozen)
        env = {key: value for key, value in os.environ.items() if key in {
            'PATH', 'HOME', 'TMPDIR', 'CARGO_HOME', 'RUSTUP_HOME', 'DEVELOPER_DIR', 'SDKROOT',
        }}
        cargo_home = Path(env.get('CARGO_HOME', str(Path.home() / '.cargo')))
        if not cargo_home.is_absolute():
            cargo_home = frozen / cargo_home
        # Cargo names sources under its home as given, which a symlink, such as macOS's /tmp, keeps apart from the resolved path.
        homes = dict.fromkeys([str(cargo_home.resolve()), str(cargo_home)])
        flags = ['--remap-path-prefix=' + str(frozen) + '=/lpm-rust-client'] + ['--remap-path-prefix=' + home + '=/lpm-cargo' for home in homes]
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
        # Not offline: metadata resolves every workspace package, beyond what building lpm-env-ffi fetched.
        metadata = [json.loads(subprocess.check_output(['cargo', '+1.94.0', 'metadata', '--locked', '--format-version', '1', '--filter-platform', target], cwd=frozen, env=env)) for target in targets]
        licenses = Path(sysroot) / 'share/doc/rust'
        notices = third_party_notices(
            linked_packages(metadata),
            (licenses / 'licenses/MIT.txt').read_text(),
            [path.read_bytes() for path in sorted((frozen / 'crates/lpm-env-ffi/include').glob('*NOTICE*'))],
            (licenses / 'COPYRIGHT-library.html').read_text(),
        )
        (staging / NOTICES).write_text(notices)
        fixtures = {}
        for fixture in fixture_paths(frozen):
            bundled = staging / BUNDLED_FIXTURES / fixture.name
            bundled.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture, bundled)
            fixtures[str(BUNDLED_FIXTURES / fixture.name)] = file_hash(bundled)
        provenance = dict(abiVersion=abi_version, toolchain='1.94.0', targets=targets, repository='https://github.com/lpm-dev/rust-client', revision=revision, sources=sources, artifacts=files, notices=file_hash(staging / NOTICES), fixtures=fixtures)
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
