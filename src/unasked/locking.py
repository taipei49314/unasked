"""Cross-process file locks with safe same-thread reentrancy.

The run mutation lock is an integrity boundary, not an access-control boundary.  It
serializes cooperating UNASKED writers so a verifier can re-read and commit one
evidence graph without another normal writer changing it between those steps.
"""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from unasked.errors import IntegrityError

_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.RLock] = {}
_LOCAL = threading.local()


def _lock_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _thread_lock_for(path: Path) -> threading.RLock:
    key = _lock_key(path)
    with _LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.RLock())


def _depths() -> dict[str, int]:
    value = getattr(_LOCAL, "depths", None)
    if value is None:
        value = {}
        _LOCAL.depths = value
    return value


@contextmanager
def exclusive_file_lock(path: str | Path) -> Iterator[None]:
    """Hold an exclusive one-byte OS lock, re-entering safely on the same thread."""

    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    key = _lock_key(lock_path)
    thread_lock = _thread_lock_for(lock_path)
    with thread_lock:
        depths = _depths()
        if depths.get(key, 0):
            depths[key] += 1
            try:
                yield
            finally:
                depths[key] -= 1
            return

        flags = os.O_CREAT | os.O_RDWR
        for flag_name in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW"):
            flags |= getattr(os, flag_name, 0)
        descriptor = os.open(lock_path, flags, 0o600)
        locked = False
        try:
            lock_stat = os.fstat(descriptor)
            if not stat.S_ISREG(lock_stat.st_mode):
                raise IntegrityError(
                    "The mutation lock path is not a regular file.",
                    details={"path": str(lock_path)},
                )
            if lock_stat.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
            depths[key] = 1
            yield
        finally:
            depths.pop(key, None)
            if locked:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def file_lock_held_by_current_thread(path: str | Path) -> bool:
    """Return whether this thread currently holds ``path`` through this module."""

    return _depths().get(_lock_key(Path(path)), 0) > 0


__all__ = ["exclusive_file_lock", "file_lock_held_by_current_thread"]
