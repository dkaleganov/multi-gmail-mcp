"""File-write controls for exports (PLAN-v4 8.2: C1, C3, C4, C5 free space).

- C1: owner-configured roots only. At startup each root is resolved, validated (directory,
  owned by this user, writable, not group/world-writable) and a directory descriptor is
  pinned for the life of the process. A root path is never reopened for an export.
- C3: every child directory is opened relative to the pinned descriptor with
  O_DIRECTORY|O_NOFOLLOW (created at 0700 when missing). Files are written to a random
  temporary name created with O_CREAT|O_EXCL|O_NOFOLLOW at 0600, bounded, attributed,
  fsynced, then published with a same-directory no-clobber hard link; the temporary name
  is removed and the directory change persisted. Existing objects are opened with
  O_NOFOLLOW|O_NONBLOCK and must be regular files by fstat; they are never chmodded,
  truncated, quarantined, or rewritten by name.
- C4: no execute bits on created files; the quarantine attribute is applied and verified
  before publication.
These defend against traversal and planted symlinks. They are not containment against a
hostile process running as the same user.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import os
import secrets
import stat
import time
from dataclasses import dataclass, field

TEMP_PREFIX = ".tmp-"
QUARANTINE_ATTR = b"com.apple.quarantine"
QUARANTINE_AGENT = b"gmail-mcp-private"
FREE_SPACE_RESERVE = 1024 * 1024 * 1024  # keep at least 1 GiB free beyond the file being written
_ENOATTR = getattr(errno, "ENOATTR", 93)

_O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class UnsafePath(Exception):
    """A path component is a symlink, not a directory, or not owned by this user."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class QuarantineError(Exception):
    pass


# --- durability ----------------------------------------------------------------------------------
def full_sync(fd: int) -> None:
    """Flush to stable storage. On macOS F_FULLFSYNC also flushes the drive cache; fall back
    to fsync where it is unsupported (some file systems and directory descriptors)."""
    try:
        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    except (OSError, AttributeError):
        os.fsync(fd)


# --- quarantine (C4) ---------------------------------------------------------------------------
_libc = None


def _lib():
    global _libc
    if _libc is None:
        lib = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        lib.fsetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_uint32, ctypes.c_int]
        lib.fsetxattr.restype = ctypes.c_int
        lib.fgetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_uint32, ctypes.c_int]
        lib.fgetxattr.restype = ctypes.c_ssize_t
        _libc = lib
    return _libc


def quarantine_value() -> bytes:
    # flags;hex-timestamp;agent;  — 0x0001 marks the file as downloaded (Gatekeeper checks).
    return b"0081;%08x;%s;" % (int(time.time()), QUARANTINE_AGENT)


def set_quarantine(fd: int) -> None:
    value = quarantine_value()
    try:
        lib = _lib()
        rc = lib.fsetxattr(fd, QUARANTINE_ATTR, value, len(value), 0, 0)
    except (OSError, AttributeError) as e:
        raise QuarantineError("unavailable") from e
    if rc != 0:
        raise QuarantineError(errno.errorcode.get(ctypes.get_errno(), "error"))
    if not has_quarantine(fd):
        raise QuarantineError("not-verified")


def has_quarantine(fd: int) -> bool:
    try:
        lib = _lib()
        n = lib.fgetxattr(fd, QUARANTINE_ATTR, None, 0, 0, 0)
    except (OSError, AttributeError):
        return False
    return n > 0


# --- C1: pinned roots ---------------------------------------------------------------------------
@dataclass
class Root:
    name: str
    display_path: str          # resolved path at startup (informational)
    fd: int | None
    dev: int = 0
    ino: int = 0
    problem: str | None = None  # fixed code when unavailable

    @property
    def available(self) -> bool:
        return self.fd is not None and self.problem is None

    def current_path(self) -> str:
        """The pinned root's path NOW (follows a rename of the directory); falls back to the
        path resolved at startup."""
        if self.fd is not None:
            try:
                return fcntl.fcntl(self.fd, fcntl.F_GETPATH, b"\0" * 1024).split(b"\0", 1)[0].decode()
            except (OSError, AttributeError, UnicodeDecodeError, ValueError):
                pass
        return self.display_path

    def check_live(self) -> str | None:
        """A pinned root whose directory was deleted is unavailable (no redirect)."""
        if self.fd is None:
            return self.problem or "destination-unavailable"
        try:
            st = os.fstat(self.fd)
        except OSError:
            return "destination-unavailable"
        if st.st_nlink == 0:
            return "destination-removed"
        # APFS keeps st_nlink at 2 for a removed directory. F_GETPATH follows renames of the
        # pinned directory but keeps a stale path after removal, so a path that no longer
        # names the pinned inode means it was removed. (Read-only check; exports still go
        # through the descriptor, never through this path.)
        try:
            cur = fcntl.fcntl(self.fd, fcntl.F_GETPATH, b"\0" * 1024).split(b"\0", 1)[0]
            pst = os.stat(cur, follow_symlinks=False)
            if (pst.st_dev, pst.st_ino) != (st.st_dev, st.st_ino):
                return "destination-removed"
        except FileNotFoundError:
            return "destination-removed"
        except (OSError, AttributeError, ValueError):
            pass
        return None


def pin_root(name: str, configured: str) -> Root:
    """Resolve, validate, and pin one configured destination root. Never creates it."""
    try:
        resolved = os.path.realpath(os.path.expanduser(configured), strict=True)
    except (OSError, ValueError):
        return Root(name, os.path.expanduser(configured), None, problem="destination-missing")
    try:
        fd = os.open(resolved, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return Root(name, resolved, None, problem="destination-not-a-directory")
    st = os.fstat(fd)
    problem = None
    if not stat.S_ISDIR(st.st_mode):
        problem = "destination-not-a-directory"
    elif st.st_uid != os.getuid():
        problem = "destination-not-owned"
    elif st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        problem = "destination-shared-writable"
    elif not st.st_mode & stat.S_IWUSR:
        problem = "destination-not-writable"
    if problem:
        os.close(fd)
        return Root(name, resolved, None, problem=problem)
    return Root(name, resolved, fd, dev=st.st_dev, ino=st.st_ino)


# --- C3: directories ------------------------------------------------------------------------------
def _check_dir_fd(fd: int) -> None:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePath("not-a-directory")
    if st.st_uid != os.getuid():
        raise UnsafePath("directory-not-owned")


def open_child_dir(parent_fd: int, name: str, create: bool = True) -> int:
    """Open (creating at 0700 if missing) a child directory with O_NOFOLLOW. A symlink,
    a non-directory, or a directory owned by someone else is refused."""
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise UnsafePath("invalid-component")
    for _ in range(3):
        try:
            fd = os.open(name, _O_DIR, dir_fd=parent_fd)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                full_sync(parent_fd)
            except FileExistsError:
                pass
            continue
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                raise UnsafePath("symlink-or-not-directory") from None
            raise
        try:
            _check_dir_fd(fd)
        except Exception:
            os.close(fd)
            raise
        return fd
    raise UnsafePath("directory-race")


def open_dir_chain(root_fd: int, components: list[str], create: bool = True) -> int:
    """Walk components from the pinned root; returns an fd for the last directory."""
    cur = os.dup(root_fd)
    try:
        for comp in components:
            nxt = open_child_dir(cur, comp, create=create)
            os.close(cur)
            cur = nxt
        return cur
    except Exception:
        os.close(cur)
        raise


# --- C3: files -------------------------------------------------------------------------------
@dataclass
class TempFile:
    name: str
    size: int
    sha256: str
    head: bytes
    ino: int
    dev: int
    quarantined: bool


class TooLarge(Exception):
    pass


class InsufficientSpace(Exception):
    pass


def free_bytes(dir_fd: int) -> int:
    st = os.statvfs(dir_fd)
    return st.f_bavail * st.f_frsize


def write_temp(dir_fd: int, chunks, max_bytes: int, expected_size: int | None = None,
               quarantine: bool = True) -> TempFile:
    """Write `chunks` (an iterable of bytes) to a fresh temporary file in dir_fd, bounded by
    max_bytes on ACTUAL bytes, with mode 0600 (never exec bits), the quarantine attribute
    applied and verified, and the data fsynced. On any failure the temporary file is
    removed (it was never published) and the error re-raised."""
    if expected_size is not None and free_bytes(dir_fd) < expected_size + FREE_SPACE_RESERVE:
        raise InsufficientSpace()
    name = TEMP_PREFIX + secrets.token_hex(12)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                 dir_fd=dir_fd)
    ok = False
    try:
        h = hashlib.sha256()
        size = 0
        head = b""
        for chunk in chunks:
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise TooLarge()
            if len(head) < 1024:
                head += chunk[: 1024 - len(head)]
            h.update(chunk)
            view = memoryview(chunk)
            while view:
                n = os.write(fd, view)
                view = view[n:]
        os.fchmod(fd, 0o600)
        if quarantine:
            set_quarantine(fd)
        full_sync(fd)
        st = os.fstat(fd)
        ok = True
        return TempFile(name, size, h.hexdigest(), head, st.st_ino, st.st_dev, quarantine)
    finally:
        os.close(fd)
        if not ok:
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError:
                pass


def publish(dir_fd: int, temp_name: str, final_name: str) -> list[str]:
    """No-clobber publication: same-directory hard link (EEXIST if the final name exists in
    any form, including APFS case/normalization variants), then remove the temporary name
    and persist the directory. Only the link itself can fail publication; once it exists,
    a failure to remove the temporary name or to sync is returned as a warning."""
    os.link(temp_name, final_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
    warnings = []
    try:
        os.unlink(temp_name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except OSError:
        warnings.append("temp-not-removed")
    try:
        full_sync(dir_fd)
    except OSError:
        warnings.append("directory-sync-failed")
    return warnings


def name_exists(dir_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


@dataclass
class Existing:
    kind: str                  # "regular" | "symlink" | "non-regular" | "unreadable"
    size: int | None = None
    sha256: str | None = None  # None when over the hashing cap
    head: bytes = b""
    mode: int | None = None
    quarantined: bool = False
    ino: int | None = None
    dev: int | None = None
    nlink: int | None = None


def inspect_existing(dir_fd: int, name: str, hash_cap: int) -> Existing | None:
    """Look at an existing object WITHOUT following symlinks or blocking on FIFOs. Hashes a
    regular file only within hash_cap bytes. Returns None when the name is absent."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            return Existing("symlink")
        if e.errno in (errno.EACCES, errno.EPERM):
            return Existing("unreadable")
        return Existing("non-regular")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return Existing("non-regular")
        ex = Existing("regular", size=st.st_size, mode=stat.S_IMODE(st.st_mode),
                      quarantined=has_quarantine(fd), ino=st.st_ino, dev=st.st_dev, nlink=st.st_nlink)
        if st.st_size <= hash_cap:
            h = hashlib.sha256()
            total = 0
            while True:
                b = os.read(fd, 1 << 20)
                if not b:
                    break
                total += len(b)
                if total > hash_cap:
                    return ex
                if len(ex.head) < 1024:
                    ex.head += b[: 1024 - len(ex.head)]
                h.update(b)
            ex.size = total
            ex.sha256 = h.hexdigest()
        return ex
    finally:
        os.close(fd)


def remove_temp(dir_fd: int, name: str, ino: int | None = None, dev: int | None = None) -> bool:
    """Remove one of OUR temporary files: only a `.tmp-` name, and only when its identity
    (inode/device) matches what we recorded."""
    if not name.startswith(TEMP_PREFIX):
        return False
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    if ino is not None and (st.st_ino != ino or st.st_dev != dev):
        return False
    os.unlink(name, dir_fd=dir_fd)
    return True


def list_names(dir_fd: int) -> list[str]:
    return os.listdir(dir_fd)


def write_reserved(dir_fd: int, name: str, data: bytes) -> None:
    """Atomically replace a reserved metadata file (the manifest): temp + fsync + rename +
    directory fsync. rename() replaces a planted symlink itself, never its target."""
    tmp = f".{name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                 dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        full_sync(fd)
    finally:
        os.close(fd)
    try:
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except Exception:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    full_sync(dir_fd)


def read_reserved(dir_fd: int, name: str, cap: int) -> bytes | None:
    """Read a reserved metadata file without following symlinks; None when absent."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise UnsafePath("reserved-metadata-unsafe") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            raise UnsafePath("reserved-metadata-unsafe")
        chunks, total = [], 0
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            total += len(b)
            if total > cap:
                raise UnsafePath("reserved-metadata-unsafe")
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)
