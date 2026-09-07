#!/usr/bin/env python3

import os
import signal
import subprocess
import sys

DEFAULT_TIMEOUT_SECS = 180
MAX_TIMEOUT_SECS = 86400
TERMINATION_GRACE_SECS = 2


class InstallInterrupted(BaseException):
    def __init__(self, signum):
        self.signum = signum


def interrupt_install(signum, _frame):
    raise InstallInterrupted(signum)


def stop_process_tree(process):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            print(f"[audit] process-tree termination failed: {error}", file=sys.stderr)
        finally:
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait()
            return
        try:
            process.wait(timeout=TERMINATION_GRACE_SECS)
        except subprocess.TimeoutExpired:
            pass
        finally:
            # Descendants can outlive the group leader after SIGTERM.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    process.wait()


def main():
    raw_timeout = os.environ.get(
        "LPM_AUDIT_INSTALL_TIMEOUT_SECS", str(DEFAULT_TIMEOUT_SECS)
    )
    timeout_digits = raw_timeout.lstrip("0") or "0"
    if (
        not raw_timeout.isascii()
        or not raw_timeout.isdecimal()
        or len(timeout_digits) > 5
        or not 1 <= int(timeout_digits) <= MAX_TIMEOUT_SECS
    ):
        print(
            "[audit] LPM_AUDIT_INSTALL_TIMEOUT_SECS must be an integer from 1 to 86400",
            file=sys.stderr,
        )
        return 2
    if len(sys.argv) < 2:
        print("[audit] install command required", file=sys.stderr)
        return 2
    timeout = int(timeout_digits)
    try:
        process = subprocess.Popen(sys.argv[1:], start_new_session=os.name != "nt")
    except OSError as error:
        print(f"[audit] cannot start install: {error}", file=sys.stderr)
        return 127
    signal.signal(signal.SIGTERM, interrupt_install)
    signal.signal(signal.SIGINT, interrupt_install)
    try:
        result = process.wait(timeout=timeout)
        return result if result >= 0 else 128 - result
    except subprocess.TimeoutExpired:
        print(
            f"[audit] install exceeded {timeout}s deadline. Stopping process tree.",
            file=sys.stderr,
            flush=True,
        )
        stop_process_tree(process)
        return 124
    except InstallInterrupted as interrupted:
        stop_process_tree(process)
        return 128 + interrupted.signum


if __name__ == "__main__":
    sys.exit(main())
