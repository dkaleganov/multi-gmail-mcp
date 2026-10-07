"""Host-wide locks with bounded waits and a checked lock order.

Each lock is an flock() on a STABLE lock file under <runtime root>/locks/. Lock files are
created once and never replaced, renamed, or deleted, so their inode is stable for every
process on the host. A process-local mutex per lock file also serializes threads (and
avoids busy polling between them).

Lock order (PLAN-v4 5.8, 6, 9.2) — a thread may only acquire locks in increasing rank:

    10  label-admin   label administration and journal writes; membership changes
    20  export-XX     one export message identity (striped over 256 lock files)
    30  render        one render per host

The label-admin lock is never held together with the export or render locks in practice;
the export path takes message -> render. Acquiring out of order raises LockOrderError
before blocking, so an inversion fails loudly in tests instead of deadlocking.
"""
from __future__ import annotations

import fcntl
import os
import stat
import threading
import time

import runtime

RANK_ADMIN = 10
RANK_MESSAGE = 20
RANK_RENDER = 30


class LockOrderError(RuntimeError):
    pass


class LockTimeout(Exception):
    pass


_registry_guard = threading.Lock()
_mutexes: dict[str, threading.Lock] = {}
_held = threading.local()


def _held_ranks() -> list[int]:
    if not hasattr(_held, "ranks"):
        _held.ranks = []
    return _held.ranks


def _mutex_for(path: str) -> threading.Lock:
    with _registry_guard:
        m = _mutexes.get(path)
        if m is None:
            m = _mutexes[path] = threading.Lock()
        return m


def locks_dir():
    return runtime.private_dir("locks")


class HostLock:
    def __init__(self, name: str, rank: int):
        if not name.replace("-", "").isalnum():
            raise ValueError("invalid lock name")
        self.name = name
        self.rank = rank
        self.path = str(locks_dir() / f"{name}.lock")
        self._fd: int | None = None
        self._mutex = _mutex_for(self.path)

    def _open(self) -> int:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            os.close(fd)
            raise RuntimeError("lock file is not a regular file owned by this user")
        return fd

    def acquire(self, timeout: float) -> None:
        """Acquire within `timeout` seconds (0 = try once) or raise LockTimeout."""
        held = _held_ranks()
        if held and max(held) >= self.rank:
            raise LockOrderError(f"lock order violation: rank {self.rank} after {max(held)}")
        deadline = time.monotonic() + max(0.0, timeout)
        got = self._mutex.acquire(timeout=timeout) if timeout > 0 else self._mutex.acquire(blocking=False)
        if not got:
            raise LockTimeout(self.name)
        try:
            fd = self._open()
        except Exception:
            self._mutex.release()
            raise
        delay = 0.005
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    self._mutex.release()
                    raise LockTimeout(self.name) from None
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
                delay = min(delay * 2, 0.05)
        self._fd = fd
        held.append(self.rank)

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            held = _held_ranks()
            if self.rank in held:
                held.remove(self.rank)
            self._mutex.release()

    @property
    def held(self) -> bool:
        return self._fd is not None


class _Ctx:
    def __init__(self, lock: HostLock, timeout: float):
        self.lock, self.timeout = lock, timeout

    def __enter__(self):
        self.lock.acquire(self.timeout)
        return self.lock

    def __exit__(self, *exc):
        self.lock.release()
        return False


def admin_lock(timeout: float = 60.0) -> _Ctx:
    return _Ctx(HostLock("label-admin", RANK_ADMIN), timeout)


def message_lock(key_hex: str, timeout: float = 120.0) -> _Ctx:
    """Striped lock for one export message identity (key = sha256 hex of the identity)."""
    return _Ctx(HostLock(f"export-{key_hex[:2]}", RANK_MESSAGE), timeout)


def render_lock(timeout: float = 60.0) -> _Ctx:
    return _Ctx(HostLock("render", RANK_RENDER), timeout)
