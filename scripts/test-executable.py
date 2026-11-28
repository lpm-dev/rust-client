"""Print the test executable Cargo built for a crate's library, from the JSON
messages that `cargo test --no-run --message-format=json-render-diagnostics`
writes one a line."""

import json
import sys


def test_executable(messages, target):
    found = None
    for line in messages:
        if target not in line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == target
            and "lib" in message.get("target", {}).get("kind", [])
            and message.get("profile", {}).get("test") is True
            and isinstance(message.get("executable"), str)
        ):
            found = message["executable"]
    return found


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: test-executable.py <target name> < cargo-messages")
    executable = test_executable(sys.stdin, sys.argv[1])
    if executable is None:
        sys.exit(f"error: cargo built no {sys.argv[1]} test executable")
    print(executable)


if __name__ == "__main__":
    main()
