"""Windows provider launcher used to establish a Job Object before provider code runs."""

from __future__ import annotations

import subprocess  # nosec B404
import sys


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        return 64
    payload = sys.stdin.buffer.read()
    try:
        process = subprocess.Popen(  # nosec B603
            argv,
            stdin=subprocess.PIPE,
            stdout=None,
            stderr=None,
            shell=False,
        )
    except OSError:
        return 74
    try:
        process.communicate(input=payload)
    except (BrokenPipeError, OSError):
        process.kill()
        process.wait()
        return 74
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
