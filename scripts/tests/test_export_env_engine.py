import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('exporter', Path(__file__).resolve().parents[1] / 'export-env-engine.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


HEADER = '#ifndef LPM_ENV_H\n#define LPM_ENV_H\n#define LPM_ENV_ABI_VERSION 7\n#endif\n'
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
MIT_TEXT = 'MIT License\n\nCopyright (c) <year> <copyright holders>\n\nPermission is hereby granted, free of charge.\n'
STD_NOTICE = '<!DOCTYPE html>\n<html><head><title>std</title></head>\n<body>\n<h1>Copyright notices for The Rust Standard Library</h1>\n</body></html>\n'
APACHE = 'Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n'


def package(name, version='1.0.0', source=REGISTRY, license='MIT', directory=None, proc_macro=False, authors=(), license_file=None):
    return {
        'id': name + ' ' + version, 'name': name, 'version': version, 'source': source, 'license': license,
        'authors': list(authors), 'license_file': license_file,
        'manifest_path': str((directory or Path('/registry') / (name + '-' + version)) / 'Cargo.toml'),
        'targets': [{'kind': ['proc-macro' if proc_macro else 'lib']}],
    }


def metadata(packages, edges):
    """`cargo metadata` output for packages, with edges from a package's id to (dependency id, kind)."""
    return {'packages': packages, 'resolve': {'nodes': [
        {'id': entry['id'], 'deps': [{'pkg': dependency, 'dep_kinds': [{'kind': kind, 'target': None}]} for dependency, kind in edges.get(entry['id'], [])]}
        for entry in packages]}}


def fake_sysroot(directory):
    """A toolchain sysroot with the license files the notices read."""
    licenses = directory / 'share/doc/rust'
    (licenses / 'licenses').mkdir(parents=True)
    (licenses / 'licenses/MIT.txt').write_text(MIT_TEXT)
    (licenses / 'COPYRIGHT-library.html').write_text(STD_NOTICE)
    return directory


ENGINE_METADATA = json.dumps(metadata([package('lpm-env-ffi', source=None)], {}))
MANIFESTS = {
    'Cargo.toml': '[workspace.dependencies]\nlpm-env = { path = "crates/lpm-env" }\nlpm-env-source = { path = "crates/lpm-env-source" }\n',
    'crates/lpm-env/Cargo.toml': '[dependencies]\n',
    'crates/lpm-env-source/Cargo.toml': '[dependencies]\nlpm-env.workspace = true\n',
    'crates/lpm-env-ffi/Cargo.toml': '[dependencies]\nlpm-env-source.workspace = true\n',
}


def write_sources(root, marker='original'):
    """An engine source tree: manifests the exporter walks, sources holding marker, and the header."""
    for name, text in MANIFESTS.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for name in ['Cargo.lock', 'scripts/export-env-engine.py', 'crates/lpm-env/src/lib.rs', 'crates/lpm-env-source/src/lib.rs']:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(marker)
    header = root / 'crates/lpm-env-ffi/include/lpm_env.h'
    header.parent.mkdir(parents=True, exist_ok=True)
    header.write_text(HEADER if marker == 'original' else HEADER + marker)


class EngineExportTests(unittest.TestCase):
    def test_provenance_abi_version_comes_from_the_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / 'crates/lpm-env-ffi/include/lpm_env.h'
            header.parent.mkdir(parents=True)
            header.write_text(HEADER)
            self.assertEqual(exporter.header_abi_version(root), 7)
            for text in ['#define LPM_ENV_ABI_VERSION\n', '#define LPM_ENV_ABI_VERSION two\n', '#define LPM_ENV_INPUT_LIMIT 2\n']:
                header.write_text(text)
                with self.assertRaisesRegex(RuntimeError, 'LPM_ENV_ABI_VERSION'):
                    exporter.header_abi_version(root)

    def test_provenance_covers_every_workspace_crate_the_engine_builds_from(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_sources(root)
            manifests = {
                'Cargo.toml': MANIFESTS['Cargo.toml'] + 'common = { path = "crates/lpm-common", package = "lpm-common" }\nunused = { path = "crates/unused" }\nserde = "1"\n',
                'crates/lpm-env-ffi/Cargo.toml': '[dependencies]\nlpm-env-source.workspace = true\nserde.workspace = true\n[target.\'cfg(unix)\'.dependencies]\ncommon = { workspace = true, features = ["extra"] }\n',
                'crates/lpm-common/Cargo.toml': '[build-dependencies]\nhelper = { path = "../lpm-build-helper" }\n',
                'crates/lpm-build-helper/Cargo.toml': '[dependencies]\n',
                'crates/unused/Cargo.toml': '[dependencies]\n',
            }
            for name, text in manifests.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            (root / 'crates/lpm-build-helper/src').mkdir()
            (root / 'crates/lpm-build-helper/src/lib.rs').write_text('helper')

            self.assertEqual(exporter.engine_crates(root), [Path('crates') / name for name in ['lpm-build-helper', 'lpm-common', 'lpm-env', 'lpm-env-ffi', 'lpm-env-source']])
            self.assertIn('crates/lpm-build-helper/src/lib.rs', exporter.source_hashes(root))
            self.assertNotIn('crates/unused/Cargo.toml', exporter.source_hashes(root))

            (root / 'crates/lpm-build-helper/Cargo.toml').write_text('[dependencies]\noutside = { path = "../../../elsewhere" }\n')
            with self.assertRaisesRegex(RuntimeError, 'outside the repository: outside'):
                exporter.engine_crates(root)

    def test_archive_hashing_streams_without_reading_the_complete_file(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'library'
            data = b'0123456789abcdef' * 262144
            path.write_bytes(data)
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('whole file read')):
                self.assertEqual(exporter.file_hash(path), hashlib.sha256(data).hexdigest())

    def test_revision_admission_rejects_dirty_engine_inputs_and_allows_unrelated_edits(self):
        for state in ('modified', 'staged', 'untracked', 'unrelated'):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'source'
                write_sources(root)
                subprocess.run(['git', 'init', '-q', str(root)], check=True)
                subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
                subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
                changed = root / ('notes.txt' if state == 'unrelated' else 'crates/lpm-env/src/new.rs' if state == 'untracked' else 'crates/lpm-env/src/lib.rs')
                changed.write_text('changed')
                if state == 'staged': subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
                real_run = subprocess.run
                def reject_build(args, **kwargs):
                    if args[0] == 'git': return real_run(args, **kwargs)
                    if state == 'unrelated': raise RuntimeError('fixture build reached')
                    raise AssertionError('dirty export attempted a build')
                with patch.object(exporter.subprocess, 'run', side_effect=reject_build):
                    with self.assertRaisesRegex(RuntimeError, 'fixture build reached' if state == 'unrelated' else 'recorded revision'):
                        exporter.export(root, Path(temporary) / 'target', Path(temporary) / 'output')

    def scenario(self, failure):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            write_sources(root)
            output = Path(temporary) / 'engine'
            (output / 'LPMEnv.xcframework').mkdir(parents=True)
            (output / 'LPMEnv.xcframework/old').write_bytes(b'old bundle')
            (output / 'provenance.json').write_bytes(b'old provenance')
            paths = b'\0'.join(str(path.relative_to(root)).encode() for path in root.rglob('*') if path.is_file()) + b'\0'
            builds = []

            def command(args, **kwargs):
                if args[0] == 'cargo':
                    if failure == 'canonical':
                        self.assertEqual(kwargs['cwd'], kwargs['cwd'].resolve())
                    if failure == 'remap-spaces':
                        # macOS's temporary directory is reached through the /var symlink; Linux's isn't.
                        homes = dict.fromkeys([str(cargo_home.resolve()), str(cargo_home)])
                        self.assertEqual(kwargs['env']['CARGO_ENCODED_RUSTFLAGS'].split('\x1f'), [
                            '--remap-path-prefix=' + str(kwargs['cwd']) + '=/lpm-rust-client',
                            *['--remap-path-prefix=' + home + '=/lpm-cargo' for home in homes],
                        ])
                    if failure == 'cargo-home-alias':
                        self.assertEqual(kwargs['env']['CARGO_HOME'], str(cargo_home))
                        self.assertEqual(kwargs['env']['CARGO_ENCODED_RUSTFLAGS'].split('\x1f'), [
                            '--remap-path-prefix=' + str(kwargs['cwd']) + '=/lpm-rust-client',
                            '--remap-path-prefix=' + str(cargo_home.resolve()) + '=/lpm-cargo',
                            '--remap-path-prefix=' + str(cargo_home) + '=/lpm-cargo',
                        ])
                    builds.append(kwargs['cwd'])
                    self.assertNotEqual(kwargs['cwd'], root)
                    self.assertEqual((kwargs['cwd'] / 'crates/lpm-env/src/lib.rs').read_text(), 'original')
                    if failure == 'mutation' and len(builds) == 1:
                        (root / 'crates/lpm-env/src/lib.rs').write_text('changed')
                if args[0] == 'lipo':
                    if failure in {'packaging', 'canonical', 'remap-spaces', 'cargo-home-alias'}:
                        raise subprocess.CalledProcessError(1, args)
                    Path(args[-1]).write_bytes(b'library')
                if failure == 'environment' and args[0] in {'lipo', 'xcrun', 'xcodebuild'}:
                    self.assertEqual(kwargs['env']['ZERO_AR_DATE'], '1')
                if failure == 'pinned-strip' and (args[0] == 'xcrun' or args[0].endswith('llvm-objcopy')):
                    self.assertEqual(args[0], str(sysroot / 'lib/rustlib/aarch64-apple-darwin/bin/llvm-objcopy'))
                    self.assertIn('--remove-section=__LLVM,__bitcode', args)
                    self.assertIn('--remove-section=__LLVM,__cmdline', args)
                    self.assertIn('--enable-deterministic-archives', args)
                if args[0] == 'xcodebuild':
                    if failure in {'environment','pinned-strip'}:
                        raise subprocess.CalledProcessError(1, args)
                    artifact = Path(args[-1])
                    artifact.mkdir()
                    (artifact / 'library').write_bytes(b'new bundle')

            sysroot = fake_sysroot(Path(temporary) / 'pinned/rust-1.94')

            def read(args, **kwargs):
                if args[:2] == ['git', 'show']: return (root / args[2].split(':', 1)[1]).read_bytes()
                if args[0] == 'rustc':
                    return str(sysroot) + '\n' if '--print' in args else 'host: aarch64-apple-darwin\n'
                if args[0] == 'cargo': return ENGINE_METADATA
                return paths if args[1] == 'ls-files' else 'a' * 40 + '\n'

            import contextlib
            original_temporary_directory = tempfile.TemporaryDirectory
            real = Path(temporary) / 'frozen-real'
            real.mkdir()
            alias = Path(temporary) / 'frozen-alias'
            alias.symlink_to(real, target_is_directory=True)
            cargo_home = Path(temporary) / 'cargo home with spaces'
            if failure == 'cargo-home-alias':
                (Path(temporary) / 'cargo-real').mkdir()
                cargo_home = Path(temporary) / 'cargo-alias'
                cargo_home.symlink_to(Path(temporary) / 'cargo-real', target_is_directory=True)

            @contextlib.contextmanager
            def temporary_directory(**options):
                if failure == 'canonical' and options.get('prefix') == 'lpm-env-source-':
                    with original_temporary_directory(dir=real, **options) as name:
                        yield str(alias / Path(name).name)
                else:
                    with original_temporary_directory(**options) as name:
                        yield name

            with patch.dict(exporter.os.environ, {'CARGO_HOME': str(cargo_home)}), patch.object(exporter.tempfile, 'TemporaryDirectory', side_effect=temporary_directory), patch.object(exporter.subprocess, 'run', side_effect=command), patch.object(exporter.subprocess, 'check_output', side_effect=read):
                with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                    exporter.export(root, Path(temporary) / 'target', output)
            self.assertEqual((output / 'LPMEnv.xcframework/old').read_bytes(), b'old bundle')
            self.assertEqual((output / 'provenance.json').read_bytes(), b'old provenance')

    def test_notices_read_metadata_with_a_cargo_cache_holding_only_what_the_engine_build_fetched(self):
        """A clean runner's cache holds what building lpm-env-ffi fetched, while `cargo metadata`
        resolves every workspace package, which it can't fetch offline."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            write_sources(root)
            output = Path(temporary) / 'engine'
            paths = b'\0'.join(str(path.relative_to(root)).encode() for path in root.rglob('*') if path.is_file()) + b'\0'
            sysroot = fake_sysroot(Path(temporary) / 'sysroot')
            cache = set()

            def command(args, **kwargs):
                if args[0] == 'cargo':
                    cache.add('engine dependencies')
                    library = Path(kwargs['env']['CARGO_TARGET_DIR']) / args[-1] / 'release/liblpm_env_ffi.a'
                    library.parent.mkdir(parents=True, exist_ok=True)
                    library.write_bytes(b'library')
                elif args[0] == 'lipo':
                    Path(args[-1]).write_bytes(b'library')
                elif args[0] == 'xcodebuild':
                    artifact = Path(args[-1])
                    artifact.mkdir()
                    (artifact / 'library').write_bytes(b'bundle')

            def read(args, **kwargs):
                if args[:2] == ['git', 'show']: return (root / args[2].split(':', 1)[1]).read_bytes()
                if args[0] == 'rustc':
                    return str(sysroot) + '\n' if '--print' in args else 'host: aarch64-apple-darwin\n'
                if args[:3] == ['cargo', '+1.94.0', 'metadata']:
                    if 'workspace dependencies' not in cache:
                        if '--offline' in args:
                            raise subprocess.CalledProcessError(101, args, stderr=b'attempting to make an HTTP request, but --offline was specified')
                        cache.add('workspace dependencies')
                    return ENGINE_METADATA
                return paths if args[1] == 'ls-files' else 'a' * 40 + '\n'

            with patch.object(exporter.subprocess, 'run', side_effect=command), patch.object(exporter.subprocess, 'check_output', side_effect=read):
                exporter.export(root, Path(temporary) / 'target', output)
            self.assertIn('The Rust standard library', (output / exporter.NOTICES).read_text())

    def test_concurrent_source_changes_reject_publication(self):
        self.scenario('mutation')

    def test_packaging_failure_preserves_existing_bundle_and_provenance(self):
        self.scenario('packaging')

    def test_frozen_source_remapping_uses_the_canonical_directory(self):
        self.scenario('canonical')

    def test_packaging_receives_the_deterministic_build_environment(self):
        self.scenario('environment')

    def test_remapping_keeps_paths_with_spaces_in_single_compiler_arguments(self):
        self.scenario('remap-spaces')

    def test_remapping_covers_a_cargo_home_reached_through_a_symlink_as_cargo_names_it(self):
        self.scenario('cargo-home-alias')

    def test_archive_stripping_uses_the_pinned_rust_llvm_tools(self):
        self.scenario('pinned-strip')



class ThirdPartyNoticeTests(unittest.TestCase):
    def test_linked_packages_follow_normal_dependencies_on_every_target(self):
        ffi, env = package('lpm-env-ffi', source=None), package('lpm-env', source=None)
        serde, derive, syn = package('serde'), package('serde_derive', proc_macro=True), package('syn')
        cc, tempfile_crate, foundation = package('cc'), package('tempfile'), package('core-foundation')
        edges = {ffi['id']: [(env['id'], None), (derive['id'], None), (cc['id'], 'build'), (tempfile_crate['id'], 'dev')], env['id']: [(serde['id'], None)], derive['id']: [(syn['id'], None)]}
        arm = metadata([ffi, env, serde, derive, syn, cc, tempfile_crate], edges)
        intel = metadata([ffi, env, serde, derive, syn, cc, tempfile_crate, foundation], dict(edges, **{ffi['id']: edges[ffi['id']] + [(foundation['id'], None)]}))
        self.assertEqual([entry['name'] for entry in exporter.linked_packages([arm, intel])], ['core-foundation', 'serde'])

    def test_license_texts_are_every_notice_file_without_apache_when_mit_alone_applies(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'LICENSE-MIT').write_bytes(b'Copyright Alice\r\n\r\nPermission is hereby granted.  \r\n')
            (directory / 'LICENSE-APACHE').write_text(APACHE)
            (directory / 'NOTICE').write_text('Alice wrote this.\n')
            (directory / 'README.md').write_text('not a notice')
            (directory / 'terms.txt').write_text('declared terms')
            dual = package('dual', license='MIT OR Apache-2.0', directory=directory)
            self.assertEqual(exporter.license_texts(dual, MIT_TEXT), ['Copyright Alice\n\nPermission is hereby granted.', 'Alice wrote this.'])
            for license in ['Apache-2.0', '(MIT OR Apache-2.0) AND Unicode-3.0']:
                with self.subTest(license=license):
                    texts = exporter.license_texts(package('kept', license=license, directory=directory), MIT_TEXT)
                    self.assertIn(APACHE.strip(), texts)
            declared = package('declared', license=None, directory=directory, license_file='terms.txt')
            self.assertIn('declared terms', exporter.license_texts(declared, MIT_TEXT))
            (directory / 'LICENSE-MIT').unlink()
            self.assertIn(APACHE.strip(), exporter.license_texts(dual, MIT_TEXT), 'without an MIT text, the Apache one stays')

    def test_a_package_without_license_files_gets_the_mit_text_only_when_it_offers_mit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            named = package('named', license='MIT OR Apache-2.0', directory=directory, authors=['Alice <alice@example.invalid>'])
            self.assertEqual(exporter.license_texts(named, MIT_TEXT), ['MIT License\n\nCopyright (c) Alice <alice@example.invalid>\n\nPermission is hereby granted, free of charge.'])
            anonymous = package('anonymous', license='MIT', directory=directory)
            self.assertIn('Copyright (c) the anonymous authors', exporter.license_texts(anonymous, MIT_TEXT)[0])
            with self.assertRaisesRegex(RuntimeError, 'bsd-only 1.0.0 ships no license text'):
                exporter.license_texts(package('bsd-only', license='BSD-3-Clause', directory=directory), MIT_TEXT)

    def test_notices_list_every_crate_write_each_text_once_and_escape_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            shared, own = Path(temporary) / 'shared', Path(temporary) / 'own'
            for directory, text in [(shared, 'Permission is hereby granted <to all> & sundry.'), (own, 'Unicode terms')]:
                directory.mkdir()
                (directory / 'LICENSE').write_text(text)
            packages = [package('alpha', directory=shared), package('beta', directory=shared), package('gamma', license='Unicode-3.0', directory=own)]
            notices = exporter.third_party_notices(packages, MIT_TEXT, [b'# EFF wordlist\r\nCC BY 3.0 US\r\n'], STD_NOTICE)
            self.assertEqual(notices.count('Permission is hereby granted &lt;to all&gt; &amp; sundry.'), 1)
            self.assertIn('<b>alpha</b> 1.0.0, MIT, source https://crates.io/crates/alpha/1.0.0, texts <a href="#text-1">1</a>', notices)
            self.assertIn('<b>beta</b> 1.0.0, MIT, source https://crates.io/crates/beta/1.0.0, texts <a href="#text-1">1</a>', notices)
            self.assertIn('<b>gamma</b> 1.0.0, Unicode-3.0, source https://crates.io/crates/gamma/1.0.0, texts <a href="#text-2">2</a>', notices)
            self.assertIn('<h2>Data</h2>\n<pre># EFF wordlist\nCC BY 3.0 US</pre>', notices)
            self.assertIn('<h1>Copyright notices for The Rust Standard Library</h1>', notices)
            self.assertNotIn('<title>std</title>', notices)
            self.assertEqual(notices, exporter.third_party_notices(packages, MIT_TEXT, [b'# EFF wordlist\r\nCC BY 3.0 US\r\n'], STD_NOTICE))
            self.assertNotIn('<h2>Data</h2>', exporter.third_party_notices(packages, MIT_TEXT, [], STD_NOTICE))
            with self.assertRaisesRegex(RuntimeError, 'standard library notices'):
                exporter.third_party_notices(packages, MIT_TEXT, [], '<html>no body</html>')


class ConcurrentEngineExportTests(unittest.TestCase):
    def test_shared_target_exports_keep_both_slices_from_their_own_sources(self):
        import sys
        import time
        import shutil
        child = r'''
import importlib.util, pathlib, shutil, subprocess, sys, time
script, root, target, output, signal, sysroot = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('exporter', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
marker = (root / 'crates/lpm-env/src/lib.rs').read_text()
paths = b'\0'.join(str(path.relative_to(root)).encode() for path in root.rglob('*') if path.is_file()) + b'\0'
engine_metadata = '{"packages": [{"id": "ffi", "name": "lpm-env-ffi", "version": "1.0.0", "source": null, "targets": []}], "resolve": {"nodes": [{"id": "ffi", "deps": []}]}}'
module.subprocess.check_output = lambda args, **kwargs: (str(sysroot) + '\n' if '--print' in args else 'host: aarch64-apple-darwin\n') if args[0] == 'rustc' else engine_metadata if args[0] == 'cargo' else (root / args[2].split(':', 1)[1]).read_bytes() if args[1] == 'show' else paths if args[1] == 'ls-files' else 'a' * 40 + '\n'
def command(args, **kwargs):
    if args[0] == 'cargo':
        library = pathlib.Path(kwargs['env']['CARGO_TARGET_DIR']) / args[-1] / 'release/liblpm_env_ffi.a'
        library.parent.mkdir(parents=True, exist_ok=True)
        library.write_bytes(marker.encode())
        if marker == 'A' and args[-1] == 'aarch64-apple-darwin':
            signal.touch()
            time.sleep(1)
    elif args[0] == 'lipo':
        pathlib.Path(args[-1]).write_bytes(pathlib.Path(args[2]).read_bytes() + pathlib.Path(args[3]).read_bytes())
    elif args[0] == 'xcodebuild':
        artifact = pathlib.Path(args[-1])
        artifact.mkdir()
        shutil.copyfile(args[args.index('-library')+1], artifact / 'library')
module.subprocess.run = command
module.export(root, target, output)
'''
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            script = Path(exporter.__file__)
            sources = []
            for marker in ['A', 'B']:
                root = parent / marker
                write_sources(root, marker)
                sources.append(root)
            signal = parent / 'first-slice-built'
            target = parent / 'shared-target'
            sysroot = fake_sysroot(parent / 'sysroot')
            first = subprocess.Popen([sys.executable, '-B', '-c', child, str(script), str(sources[0]), str(target), str(parent/'out-A'), str(signal), str(sysroot)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 5
            while not signal.exists() and time.monotonic() < deadline and first.poll() is None:
                time.sleep(0.01)
            self.assertTrue(signal.exists())
            second = subprocess.Popen([sys.executable, '-B', '-c', child, str(script), str(sources[1]), str(target), str(parent/'out-B'), str(signal), str(sysroot)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for process in [first, second]:
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
            self.assertEqual((parent/'out-A/LPMEnv.xcframework/library').read_bytes(), b'AA')
            self.assertEqual((parent/'out-B/LPMEnv.xcframework/library').read_bytes(), b'BB')
            for name in ['out-A', 'out-B']:
                provenance = json.loads((parent / name / 'provenance.json').read_text())
                self.assertEqual(provenance['abiVersion'], 7)
                notices = parent / name / exporter.NOTICES
                self.assertEqual(provenance['notices'], exporter.file_hash(notices))
                self.assertIn('Copyright notices for The Rust Standard Library', notices.read_text())


if __name__ == '__main__':
    unittest.main()
