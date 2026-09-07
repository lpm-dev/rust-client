import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

BENCH = Path(__file__).resolve().parent


class AuditInstallDeadlineTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "the shell helper test uses /bin/true")
    def test_invalid_deadline_is_not_retried_by_the_shell_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; shift; lpm_audit_run_install_with_retries "$@"',
                    "audit-test",
                    str(BENCH / "audit-install-args.sh"),
                    "/bin/true",
                    str(root / "out"),
                    str(root / "err"),
                ],
                env=dict(
                    os.environ,
                    LPM_AUDIT_INSTALL_TIMEOUT_SECS="0",
                    LPM_AUDIT_INSTALL_RETRIES="2",
                ),
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("retrying", result.stderr)

    @unittest.skipIf(os.name == "nt", "SIGTERM delivery is POSIX-specific")
    def test_cancelling_the_runner_stops_the_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready = Path(temporary) / "ready"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(BENCH / "run-audit-install.py"),
                    sys.executable,
                    "-c",
                    "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)",
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=dict(os.environ, LPM_AUDIT_INSTALL_TIMEOUT_SECS="30"),
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "install child did not start")
                process.terminate()
                process.communicate(timeout=5)
                self.assertEqual(process.returncode, 128 + signal.SIGTERM)
            finally:
                if process.poll() is None:
                    process.kill()
                    if ready.exists():
                        try:
                            os.killpg(int(ready.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.communicate()

    @unittest.skipIf(
        os.name == "nt", "the binary and smoke stubs use POSIX executable scripts"
    )
    def test_fixture_timeout_writes_artifacts_and_skips_runtime_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bench = root / "bench"
            harness = bench / "audit-fixtures"
            fixture = harness / "stalled"
            fixture.mkdir(parents=True)
            for name in ["audit-install-args.sh", "run-audit-install.py"]:
                shutil.copyfile(BENCH / name, bench / name)
            for name in ["run-audit.sh", "classify_result.py"]:
                shutil.copyfile(BENCH / "audit-fixtures" / name, harness / name)
            (fixture / "package.json").write_text(
                '{"dependencies":{"missing":"1.0.0"}}'
            )
            unexpected_check = root / "unexpected-check"
            smoke = fixture / "smoke.sh"
            smoke.write_text('#!/bin/bash\ntouch "$AUDIT_UNEXPECTED_CHECK"\nexit 1\n')
            smoke.chmod(0o755)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            node = fake_bin / "node"
            shutil.copyfile(smoke, node)
            node.chmod(0o755)
            binary = fake_bin / "lpm"
            binary.write_text(
                "#!/bin/bash\necho partial-output\necho partial-error >&2\nsleep 30\n"
            )
            binary.chmod(0o755)
            result = subprocess.run(
                ["bash", str(harness / "run-audit.sh"), "stalled"],
                env=dict(
                    os.environ,
                    LPM_BIN=str(binary),
                    LPM_AUDIT_ALLOW_NEW="0",
                    LPM_HOME=str(root / "home"),
                    LPM_AUDIT_WORK_BASE=str(root / "work"),
                    LPM_AUDIT_INSTALL_TIMEOUT_SECS="1",
                    AUDIT_UNEXPECTED_CHECK=str(unexpected_check),
                    PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                ),
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            results = list((harness / "results").glob("*.json"))
            self.assertEqual(len(results), 2)
            for path in results:
                payload = json.loads(path.read_text())
                self.assertEqual(payload["install_exit"], 124)
                self.assertEqual(payload["classification"], "install-timeout")
                self.assertIsNone(payload["smoke_exit"])
                self.assertEqual(
                    path.with_suffix(".stdout.log").read_text(), "partial-output\n"
                )
                self.assertIn(
                    "partial-error", path.with_suffix(".stderr.log").read_text()
                )
            self.assertFalse(unexpected_check.exists())

    @unittest.skipIf(os.name == "nt", "these suites run on Linux CI")
    def test_shared_audit_suites_fail_when_both_modes_exceed_the_deadline(self):
        self.assert_shared_suite_failure("install deadline", broken=False)

    @unittest.skipIf(os.name == "nt", "these suites run on Linux CI")
    def test_shared_audit_suites_fail_when_the_fixture_harness_fails(self):
        self.assert_shared_suite_failure("harness failed", broken=True)

    def assert_shared_suite_failure(self, message, broken):
        for suite in ["realworld-audit", "top-npm-audit"]:
            with self.subTest(suite=suite), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                harness = root / "bench" / suite
                harness.mkdir(parents=True)
                shutil.copyfile(BENCH / suite / "run-all.sh", harness / "run-all.sh")
                fake_bin = root / "bin"
                fake_bin.mkdir()
                jq = fake_bin / "jq"
                jq.write_text("#!/bin/bash\necho stalled\n")
                jq.chmod(0o755)
                if suite == "top-npm-audit":
                    runner = root / "bench" / "audit-fixtures" / "run-audit.sh"
                    (runner.parent / "top-npm" / "stalled").mkdir(parents=True)
                    (harness / "generate.sh").write_text("#!/bin/bash\nexit 0\n")
                else:
                    runner = harness / "run-realworld.sh"
                    (harness / "projects.json").write_text(
                        '{"projects":[{"name":"stalled"}]}'
                    )
                runner.write_text(
                    "#!/bin/bash\n"
                    'mkdir -p "$(dirname "$0")/results"\n'
                    'name="${1//\\//-}"\n'
                    "for mode in isolated hoisted; do\n"
                    '  printf \'{"verdict":"FAIL","install_exit":124,"classification":"install-timeout"}\\n\' '
                    '> "$(dirname "$0")/results/$name-$mode-stub.json"\n'
                    "done\n"
                )
                if broken:
                    runner.write_text("#!/bin/bash\nexit 2\n")
                runner.chmod(0o755)
                result = subprocess.run(
                    ["bash", str(harness / "run-all.sh")],
                    env=dict(
                        os.environ,
                        PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                        LPM_AUDIT_WORK_BASE=str(root / "work"),
                        LPM_TOP_NPM_PARALLEL="1",
                    ),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stdout)

    @unittest.skipIf(os.name == "nt", "the suite stub uses a POSIX executable script")
    def test_suite_fails_when_the_fixture_harness_cannot_write_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "audit-fixtures"
            harness.mkdir()
            shutil.copyfile(
                BENCH / "audit-fixtures" / "run-all.sh", harness / "run-all.sh"
            )
            stub = harness / "run-audit.sh"
            stub.write_text("#!/bin/bash\necho fixture-harness-failed >&2\nexit 2\n")
            stub.chmod(0o755)
            result = subprocess.run(
                ["bash", str(harness / "run-all.sh")],
                env=dict(os.environ, LPM_AUDIT_WORK_BASE=str(root / "work")),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("harness failed", result.stdout)

    def test_deadline_terminates_descendants_that_outlive_the_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            port_file = Path(temporary) / "child-port"
            child = (
                "import os,signal,socket,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "server=socket.socket(); server.bind(('127.0.0.1',0)); server.listen(); "
                "open(sys.argv[1],'w').write(str(server.getsockname()[1])); time.sleep(30)"
            )
            parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); time.sleep(30)"
            environment = dict(os.environ, LPM_AUDIT_INSTALL_TIMEOUT_SECS="2")
            result = subprocess.run(
                [
                    sys.executable,
                    str(BENCH / "run-audit-install.py"),
                    sys.executable,
                    "-c",
                    parent,
                    child,
                    str(port_file),
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 124, result.stderr)
            port = int(port_file.read_text())
            deadline = time.monotonic() + 2
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        pass
                except OSError:
                    break
                if time.monotonic() >= deadline:
                    self.fail("a child process survived the install deadline")
                time.sleep(0.01)

    def test_runner_preserves_arguments_output_and_exit_status(self):
        result = subprocess.run(
            [
                sys.executable,
                str(BENCH / "run-audit-install.py"),
                sys.executable,
                "-c",
                "import sys; print(repr(sys.argv[1:])); print('detail', file=sys.stderr); sys.exit(17)",
                "a path with spaces",
                "quote'and\"double",
                "",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            env=dict(os.environ, LPM_AUDIT_INSTALL_TIMEOUT_SECS="000180"),
        )
        self.assertEqual(result.returncode, 17)
        self.assertEqual(
            result.stdout.strip(), repr(["a path with spaces", "quote'and\"double", ""])
        )
        self.assertEqual(result.stderr.strip(), "detail")

    def test_invalid_deadlines_fail_before_starting_the_install(self):
        for value in ["", "0", "-1", "1.5", "nan", "86401", "9" * 100]:
            with self.subTest(value=value):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(BENCH / "run-audit-install.py"),
                        sys.executable,
                        "-c",
                        "print('unexpected install')",
                    ],
                    env=dict(os.environ, LPM_AUDIT_INSTALL_TIMEOUT_SECS=value),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("LPM_AUDIT_INSTALL_TIMEOUT_SECS", result.stderr)

    @unittest.skipIf(os.name == "nt", "the suite stub uses a POSIX executable script")
    def test_suite_fails_when_both_modes_exceed_the_install_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "audit-fixtures"
            harness.mkdir()
            shutil.copyfile(
                BENCH / "audit-fixtures" / "run-all.sh", harness / "run-all.sh"
            )
            stub = harness / "run-audit.sh"
            stub.write_text(
                "#!/bin/bash\n"
                'mkdir -p "$(dirname "$0")/results"\n'
                'name="${1//\\//-}"\n'
                "for mode in isolated hoisted; do\n"
                '  printf \'{"verdict":"FAIL","install_exit":124,"classification":"install-timeout"}\\n\' '
                '> "$(dirname "$0")/results/$name-$mode-stub.json"\n'
                "done\n"
            )
            stub.chmod(0o755)
            environment = dict(os.environ, LPM_AUDIT_WORK_BASE=str(root / "work"))
            result = subprocess.run(
                ["bash", str(harness / "run-all.sh")],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("install deadline", result.stdout)

    @unittest.skipIf(os.name == "nt", "the shell stub uses a POSIX executable script")
    def test_stalled_install_stops_without_retry_and_preserves_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fake-lpm"
            attempts = root / "attempts"
            output = root / "install.json"
            errors = root / "install.log"
            binary.write_text(
                "#!/bin/bash\n"
                'echo attempt >> "$AUDIT_TEST_ATTEMPTS"\n'
                "echo partial-install-output\n"
                "echo partial-install-error >&2\n"
                "sleep 30\n"
            )
            binary.chmod(0o755)
            environment = dict(os.environ)
            environment.update(
                LPM_AUDIT_INSTALL_TIMEOUT_SECS="1",
                LPM_AUDIT_INSTALL_RETRIES="2",
                AUDIT_TEST_ATTEMPTS=str(attempts),
            )
            process = subprocess.Popen(
                [
                    "bash",
                    "-c",
                    'source "$1"; shift; lpm_audit_run_install_with_retries "$@"',
                    "audit-test",
                    str(BENCH / "audit-install-args.sh"),
                    str(binary),
                    str(output),
                    str(errors),
                    "--linker",
                    "hoisted",
                    "--json",
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                process.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                self.fail("the audit install exceeded its configured deadline")
            self.assertEqual(process.returncode, 124)
            self.assertEqual(attempts.read_text().splitlines(), ["attempt"])
            self.assertIn("partial-install-output", output.read_text())
            self.assertIn("partial-install-error", errors.read_text())
            self.assertIn("install exceeded 1s deadline", errors.read_text())


if __name__ == "__main__":
    unittest.main()
