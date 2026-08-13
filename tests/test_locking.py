from __future__ import annotations

import threading

from unasked.locking import exclusive_file_lock, file_lock_held_by_current_thread


def test_exclusive_file_lock_is_same_thread_reentrant(tmp_path) -> None:
    path = tmp_path / "run" / ".mutation.lock"

    assert file_lock_held_by_current_thread(path) is False
    with exclusive_file_lock(path):
        assert file_lock_held_by_current_thread(path) is True
        with exclusive_file_lock(path):
            assert file_lock_held_by_current_thread(path) is True
        assert file_lock_held_by_current_thread(path) is True
    assert file_lock_held_by_current_thread(path) is False


def test_exclusive_file_lock_serializes_threads(tmp_path) -> None:
    path = tmp_path / ".mutation.lock"
    first_holds_lock = threading.Event()
    allow_first_to_finish = threading.Event()
    second_acquired = threading.Event()

    def first() -> None:
        with exclusive_file_lock(path):
            first_holds_lock.set()
            assert allow_first_to_finish.wait(timeout=5)

    def second() -> None:
        assert first_holds_lock.wait(timeout=5)
        with exclusive_file_lock(path):
            second_acquired.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    second_thread.start()
    assert first_holds_lock.wait(timeout=5)
    assert second_acquired.wait(timeout=0.1) is False
    allow_first_to_finish.set()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)

    assert first_thread.is_alive() is False
    assert second_thread.is_alive() is False
    assert second_acquired.is_set()
