"""Process inspection for the renderer supervisor (macOS libproc through ctypes; no new
dependency). Used to measure a Chrome process group's memory, to identify processes by
start time (pid reuse), and to find leftover processes referencing a render folder."""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import subprocess

_lib = None
_RUSAGE_INFO_V0 = 0
_PROC_PIDTBSDINFO = 3
_BSDINFO_SIZE = 136


def _libproc():
    global _lib
    if _lib is None:
        path = ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib"
        lib = ctypes.CDLL(path, use_errno=True)
        lib.proc_listpgrppids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listpgrppids.restype = ctypes.c_int
        lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        lib.proc_pid_rusage.restype = ctypes.c_int
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        _lib = lib
    return _lib


def group_pids(pgid: int) -> list[int]:
    """Pids currently in process group `pgid` (empty when the group is gone)."""
    lib = _libproc()
    cap = 256
    while True:
        buf = (ctypes.c_int * cap)()
        n = lib.proc_listpgrppids(pgid, buf, ctypes.sizeof(buf))
        if n < 0:
            return []
        if n < cap:
            return [buf[i] for i in range(n) if buf[i] > 0]
        cap *= 2
        if cap > 65536:
            return [buf[i] for i in range(n) if buf[i] > 0]


def memory(pid: int) -> tuple[int, int] | None:
    """(resident bytes, physical footprint bytes) for one process, or None if gone."""
    ru = (ctypes.c_uint64 * 12)()
    if _libproc().proc_pid_rusage(pid, _RUSAGE_INFO_V0, ru) != 0:
        return None
    return int(ru[8]), int(ru[9])


def group_memory(pgid: int) -> tuple[int, int, int]:
    """(process count, summed resident bytes, summed physical footprint bytes). The
    footprint sum is the budget measure: summed RSS double-counts shared framework pages."""
    n = rss = fp = 0
    for pid in group_pids(pgid):
        m = memory(pid)
        if m is None:
            continue
        n += 1
        rss += m[0]
        fp += m[1]
    return n, rss, fp


def bsd_info(pid: int) -> tuple[int, int] | None:
    """(pgid, start time in seconds) for a live process, or None."""
    buf = (ctypes.c_uint8 * _BSDINFO_SIZE)()
    if _libproc().proc_pidinfo(pid, _PROC_PIDTBSDINFO, 0, buf, _BSDINFO_SIZE) != _BSDINFO_SIZE:
        return None
    raw = bytes(buf)
    return struct.unpack_from("<I", raw, 100)[0], struct.unpack_from("<Q", raw, 120)[0]


def start_time(pid: int) -> int | None:
    info = bsd_info(pid)
    return None if info is None else info[1]


def alive_with_start(pid: int, start: int | None) -> bool:
    """True if `pid` is alive and (when given) started at `start` — guards pid reuse."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    st = start_time(pid)
    if st is None:
        return False
    return start is None or st == start


def pids_referencing(path_fragment: str) -> list[int]:
    """Pids whose command line contains `path_fragment` (our unique render folder).
    Catches descendants that left the process group."""
    if not path_fragment:
        return []
    try:
        out = subprocess.run(["/bin/ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True,
                             timeout=10, env={"PATH": "/usr/bin:/bin"}).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    pids = []
    me = os.getpid()
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and path_fragment in parts[1]:
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            if pid != me:
                pids.append(pid)
    return pids


def tree_bytes(path: str, max_entries: int = 200_000) -> int:
    """Allocated bytes under `path` (no symlink following), bounded in entries walked."""
    total = 0
    seen = 0
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    seen += 1
                    if seen > max_entries:
                        return total
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    total += getattr(st, "st_blocks", 0) * 512
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
        except OSError:
            continue
    return total
