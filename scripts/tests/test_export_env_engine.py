import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('exporter', Path(__file__).resolve().parents[1] / 'export-env-engine.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class EngineExportTests(unittest.TestCase):
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
                root.mkdir()
                files = ['Cargo.toml', 'Cargo.lock', 'scripts/export-env-engine.py', 'crates/lpm-env/src/lib.rs']
                for name in files:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('original')
                subprocess.run(['git', 'init', '-q', str(root)], check=True)
                subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
                subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
                changed = root / ('notes.txt' if state == 'unrelated' else 'crates/lpm-env/src/new.rs' if state == 'untracked' else files[-1])
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
            root.mkdir()
            for name in ['Cargo.toml', 'Cargo.lock', 'scripts/export-env-engine.py', 'crates/lpm-env/src/lib.rs', 'crates/lpm-env-source/src/lib.rs', 'crates/lpm-env-ffi/include/lpm_env.h']:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original')
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
                        self.assertEqual(kwargs['env']['CARGO_ENCODED_RUSTFLAGS'].split('\x1f'), [
                            '--remap-path-prefix=' + str(kwargs['cwd']) + '=/lpm-rust-client',
                            '--remap-path-prefix=' + str(cargo_home.resolve()) + '=/lpm-cargo',
                        ])
                    builds.append(kwargs['cwd'])
                    self.assertNotEqual(kwargs['cwd'], root)
                    self.assertEqual((kwargs['cwd'] / 'crates/lpm-env/src/lib.rs').read_text(), 'original')
                    if failure == 'mutation' and len(builds) == 1:
                        (root / 'crates/lpm-env/src/lib.rs').write_text('changed')
                if args[0] == 'lipo':
                    if failure in {'packaging', 'canonical', 'remap-spaces'}:
                        raise subprocess.CalledProcessError(1, args)
                    Path(args[-1]).write_bytes(b'library')
                if failure == 'environment' and args[0] in {'lipo', 'xcrun', 'xcodebuild'}:
                    self.assertEqual(kwargs['env']['ZERO_AR_DATE'], '1')
                if failure == 'pinned-strip' and (args[0] == 'xcrun' or args[0].endswith('llvm-objcopy')):
                    self.assertEqual(args[0], '/pinned/rust-1.94/lib/rustlib/aarch64-apple-darwin/bin/llvm-objcopy')
                    self.assertIn('--remove-section=__LLVM,__bitcode', args)
                    self.assertIn('--remove-section=__LLVM,__cmdline', args)
                    self.assertIn('--enable-deterministic-archives', args)
                if args[0] == 'xcodebuild':
                    if failure in {'environment','pinned-strip'}:
                        raise subprocess.CalledProcessError(1, args)
                    artifact = Path(args[-1])
                    artifact.mkdir()
                    (artifact / 'library').write_bytes(b'new bundle')

            def read(args, **kwargs):
                if args[:2] == ['git', 'show']: return b'original'
                if args[0] == 'rustc':
                    return '/pinned/rust-1.94\n' if '--print' in args else 'host: aarch64-apple-darwin\n'
                return paths if args[1] == 'ls-files' else 'a' * 40 + '\n'

            import contextlib
            original_temporary_directory = tempfile.TemporaryDirectory
            real = Path(temporary) / 'frozen-real'
            real.mkdir()
            alias = Path(temporary) / 'frozen-alias'
            alias.symlink_to(real, target_is_directory=True)
            cargo_home = Path(temporary) / 'cargo home with spaces'

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

    def test_archive_stripping_uses_the_pinned_rust_llvm_tools(self):
        self.scenario('pinned-strip')



class ConcurrentEngineExportTests(unittest.TestCase):
    def test_shared_target_exports_keep_both_slices_from_their_own_sources(self):
        import sys
        import time
        import shutil
        child = r'''
import importlib.util, pathlib, shutil, subprocess, sys, time
script, root, target, output, signal = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('exporter', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
marker = (root / 'crates/lpm-env/src/lib.rs').read_text()
paths = b'\0'.join(str(path.relative_to(root)).encode() for path in root.rglob('*') if path.is_file()) + b'\0'
module.subprocess.check_output = lambda args, **kwargs: ('/pinned/rust-1.94\n' if '--print' in args else 'host: aarch64-apple-darwin\n') if args[0] == 'rustc' else marker.encode() if args[1] == 'show' else paths if args[1] == 'ls-files' else 'a' * 40 + '\n'
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
                for name in ['Cargo.toml', 'Cargo.lock', 'scripts/export-env-engine.py', 'crates/lpm-env/src/lib.rs', 'crates/lpm-env-source/src/lib.rs', 'crates/lpm-env-ffi/include/lpm_env.h']:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(marker)
                sources.append(root)
            signal = parent / 'first-slice-built'
            target = parent / 'shared-target'
            first = subprocess.Popen([sys.executable, '-B', '-c', child, str(script), str(sources[0]), str(target), str(parent/'out-A'), str(signal)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 5
            while not signal.exists() and time.monotonic() < deadline and first.poll() is None:
                time.sleep(0.01)
            self.assertTrue(signal.exists())
            second = subprocess.Popen([sys.executable, '-B', '-c', child, str(script), str(sources[1]), str(target), str(parent/'out-B'), str(signal)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for process in [first, second]:
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
            self.assertEqual((parent/'out-A/LPMEnv.xcframework/library').read_bytes(), b'AA')
            self.assertEqual((parent/'out-B/LPMEnv.xcframework/library').read_bytes(), b'BB')


if __name__ == '__main__':
    unittest.main()
