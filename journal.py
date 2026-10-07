"""Label recovery journal (PLAN-v4 section 5.8).

Format
- A versioned sequence of append-only JSONL segments, <runtime>/label-journal/seg-NNNNNN.jsonl,
  mode 0600 in a 0700 folder, opened without following symlinks. Existing lines are never
  edited. Each segment starts with a SEGMENT header naming its predecessor and the
  predecessor's validated prefix (bytes and last sequence number).
- Every record carries the schema version, a global sequence number, an operation id,
  its type, every field needed for the next remote mutation, and a SHA-256 checksum of
  its canonical form. Types: PREPARED, APPLIED, NOT_APPLIED, UNKNOWN_OUTCOME,
  UNDO_PREPARED, UNDO_PROGRESS, UNDONE, CONFLICT. (NOT_APPLIED is an addition to the
  plan's list: an outcome confirmed by a definitive API rejection plus a read-back, or an
  abort before any remote mutation, so such operations do not stay unresolved forever.)
- Separate from the metadata-only audit log, which is never used for recovery.

Locking: the host-wide label-admin lock (locks.admin_lock: one stable lock file plus a
process mutex) is held for the whole AdminSession: state read, durable prepare, remote
call, and durable outcome.

Durability: complete newline-terminated records, a write-all loop, then F_FULLFSYNC (or
fsync). New segments and their directory entries are persisted before use. Any durability
failure raises JournalError and the caller stops before its next remote mutation; once a
write fails the session refuses further appends.

Replay: the complete prefix is validated (checksums, contiguous sequence, headers); an
invalid record in the middle refuses label administration. An incomplete final record is
diagnostic data, never a recovery instruction: under the lock its segment is sealed
unchanged and a new segment naming the predecessor and validated prefix is persisted
before any new write. If that cannot complete durably, administration is refused.

Privacy and retention: records hold the verified account's address hash and alias, label
ids, label names and settings, message ids of a deletion snapshot, and counts. Segments
are kept indefinitely (nothing rotates away unresolved recovery entries); the owner may
archive or delete resolved segments manually while no server is running.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time

import exportfs
import locks
import runtime

SCHEMA = 1
SEG_RE = re.compile(r"^seg-(\d{6})\.jsonl$")
SEGMENT_MAX = 4 * 1024 * 1024
RECORD_MAX = 8 * 1024 * 1024
SEGMENT_READ_MAX = 256 * 1024 * 1024
HEADER = "SEGMENT"
EVENT_TYPES = frozenset({"PREPARED", "APPLIED", "NOT_APPLIED", "UNKNOWN_OUTCOME", "UNDO_PREPARED",
                         "UNDO_PROGRESS", "UNDONE", "CONFLICT"})
ADMIN_LOCK_TIMEOUT = 60.0


def _checkpoint(stage: str) -> None:
    """Crash-test seam: tests replace this to kill the process at a durability boundary."""


class JournalError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canon(rec: dict) -> bytes:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _line(rec: dict) -> bytes:
    body = {k: v for k, v in rec.items() if k != "sum"}
    return _canon({**body, "sum": hashlib.sha256(_canon(body)).hexdigest()}) + b"\n"


def _parse(line: bytes) -> dict | None:
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict) or rec.get("v") != SCHEMA or not isinstance(rec.get("seq"), int):
        return None
    body = {k: v for k, v in rec.items() if k != "sum"}
    if rec.get("sum") != hashlib.sha256(_canon(body)).hexdigest():
        return None
    if rec.get("type") != HEADER and rec.get("type") not in EVENT_TYPES:
        return None
    return rec


def host_id() -> str:
    """A stable random id for this host's install. Created atomically (temp file, fsync,
    no-clobber link), so a crash can never leave an empty or partial id behind."""
    d = runtime.private_dir()
    path = d / "host-id"
    if not os.path.lexists(path):
        tmp = d / f".host-id.{secrets.token_hex(6)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, secrets.token_hex(16).encode())
            exportfs.full_sync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, path, follow_symlinks=False)   # first writer wins; others keep theirs out
        except FileExistsError:
            pass
        finally:
            os.unlink(tmp)
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            exportfs.full_sync(dfd)
        finally:
            os.close(dfd)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        val = os.read(fd, 64).decode().strip()
    finally:
        os.close(fd)
    if not re.fullmatch(r"[0-9a-f]{32}", val):
        raise JournalError("host-id-invalid")
    return val


class Op:
    """Replayed state of one journaled operation (and its undo)."""

    def __init__(self, op_id: str):
        self.op_id = op_id
        self.events: list[dict] = []
        self.prepared: dict | None = None
        self.outcome: str | None = None          # APPLIED | NOT_APPLIED | UNKNOWN_OUTCOME | None (PREPARED only)
        self.observed: dict | None = None
        self.undo_prepared: dict | None = None
        self.undo_progress: list[dict] = []
        self.undo_terminal: str | None = None    # UNDONE | CONFLICT
        self.reconciled = False

    @property
    def kind(self) -> str | None:
        return (self.prepared or {}).get("kind")

    @property
    def unresolved(self) -> bool:
        return self.prepared is not None and self.outcome in (None, "UNKNOWN_OUTCOME")

    @property
    def blocking(self) -> bool:
        """Unresolved AND not yet reconciled. An UNKNOWN_OUTCOME that reconciliation already
        recorded (observed third state, label gone) no longer blocks new changes to the
        label; it only stays non-undoable."""
        return self.unresolved and not self.reconciled

    def apply(self, rec: dict) -> None:
        self.events.append({"type": rec["type"], "seq": rec["seq"]})
        t = rec["type"]
        if t == "PREPARED":
            self.prepared = rec
        elif t in ("APPLIED", "NOT_APPLIED", "UNKNOWN_OUTCOME"):
            if rec.get("phase") == "undo":
                self.undo_progress.append(rec)
            else:
                self.outcome = t
                self.observed = rec.get("observed")
                self.reconciled = bool(rec.get("reconciled")) and t == "UNKNOWN_OUTCOME"
        elif t == "UNDO_PREPARED":
            self.undo_prepared = rec
            self.undo_terminal = None
        elif t == "UNDO_PROGRESS":
            self.undo_progress.append(rec)
        elif t in ("UNDONE", "CONFLICT"):
            self.undo_terminal = t
            self.undo_progress.append(rec)


class AdminSession:
    """Holds the host-wide label-admin lock; replays, validates, and (if needed) seals the
    journal on entry. All label administration and membership changes run inside one."""

    def __init__(self, timeout: float = ADMIN_LOCK_TIMEOUT):
        self.timeout = timeout
        self._lock = None
        self.dir_fd: int | None = None
        self.seq = 0
        self.ops: dict[str, Op] = {}
        self.segments: list[dict] = []
        self.broken = False
        self.sealed_on_entry = False
        self.host = None

    def __enter__(self):
        self._lock = locks.admin_lock(self.timeout)
        try:
            self._lock.__enter__()
        except locks.LockTimeout:
            raise JournalError("admin-busy") from None
        try:
            self.host = host_id()
            d = runtime.private_dir("label-journal")
            self.dir_fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._replay()
        except Exception:
            self._close()
            raise
        return self

    def __exit__(self, *exc):
        self._close()
        return False

    def _close(self):
        if self.dir_fd is not None:
            os.close(self.dir_fd)
            self.dir_fd = None
        if self._lock is not None:
            self._lock.__exit__(None, None, None)
            self._lock = None

    # --- replay -----------------------------------------------------------------------------
    def _read(self, name: str) -> bytes:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.dir_fd)
        except OSError:
            raise JournalError("journal-unreadable") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_size > SEGMENT_READ_MAX:
                raise JournalError("journal-unreadable")
            chunks = []
            while True:
                b = os.read(fd, 1 << 20)
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _replay(self):
        for n in os.listdir(self.dir_fd):
            if n.startswith(".seg-") and n.endswith(".tmp"):
                try:
                    os.unlink(n, dir_fd=self.dir_fd)   # an interrupted segment creation (never linked)
                except OSError:
                    pass
        names = sorted(n for n in os.listdir(self.dir_fd) if SEG_RE.match(n))
        nums = [int(SEG_RE.match(n).group(1)) for n in names]
        if nums != list(range(1, len(nums) + 1)):
            raise JournalError("journal-corrupt")
        prev = None
        for i, name in enumerate(names):
            data = self._read(name)
            parts = data.split(b"\n")
            tail = parts[-1]
            complete = parts[:-1]
            valid = 0
            for j, raw in enumerate(complete):
                rec = _parse(raw)
                if rec is None or rec["seq"] != self.seq + 1:
                    raise JournalError("journal-corrupt")   # invalid record inside the prefix
                if j == 0:
                    if rec.get("type") != HEADER or rec.get("segment") != i + 1:
                        raise JournalError("journal-corrupt")
                    if prev is None:
                        if rec.get("pred") is not None:
                            raise JournalError("journal-corrupt")
                    elif (rec.get("pred") != prev["name"] or rec.get("pred_valid_bytes") != prev["valid"]
                          or rec.get("pred_last_seq") != prev["last_seq"]):
                        raise JournalError("journal-corrupt")
                elif rec.get("type") == HEADER:
                    raise JournalError("journal-corrupt")
                else:
                    op = rec.get("op")
                    if not isinstance(op, str) or not re.fullmatch(r"[0-9a-f]{32}", op):
                        raise JournalError("journal-corrupt")
                    self.ops.setdefault(op, Op(op)).apply(rec)
                self.seq = rec["seq"]
                valid += len(raw) + 1
            if not complete:
                # No complete record (not even the header): only a creation that never
                # finished. Acceptable as the FINAL segment (sealed below like any torn tail)
                # or when its successor's header recorded exactly a zero-byte valid prefix.
                if i != len(names) - 1:
                    nxt = _parse(self._read(names[i + 1]).split(b"\n")[0])
                    if (nxt is None or nxt.get("pred") != name or nxt.get("pred_valid_bytes") != 0
                            or nxt.get("pred_last_seq") != self.seq):
                        raise JournalError("journal-corrupt")
                prev = {"name": name, "size": len(data), "valid": 0, "torn": True, "last_seq": self.seq,
                        "records": 0}
                self.segments.append(prev)
                continue
            # a torn tail in an earlier segment is sealed: its successor's header (checked
            # above) recorded exactly this validated prefix, so the torn bytes are never replayed
            prev = {"name": name, "size": len(data), "valid": valid, "torn": bool(tail), "last_seq": self.seq,
                    "records": len(complete)}
            self.segments.append(prev)
        if not self.segments:
            self._new_segment(pred=None)
        elif self.segments[-1]["torn"]:
            try:
                self._new_segment(pred=self.segments[-1])  # seal the torn segment, unchanged
                self.sealed_on_entry = True
            except OSError:
                raise JournalError("journal-recovery-failed") from None

    # --- writing -----------------------------------------------------------------------------
    def _new_segment(self, pred: dict | None) -> None:
        n = len(self.segments) + 1
        name = f"seg-{n:06d}.jsonl"
        header = {"v": SCHEMA, "seq": self.seq + 1, "ts": round(time.time(), 3), "type": HEADER, "segment": n,
                  "pred": pred["name"] if pred else None, "pred_valid_bytes": pred["valid"] if pred else None,
                  "pred_last_seq": pred["last_seq"] if pred else None, "host": self.host}
        line = _line(header)
        # Atomic creation: the segment appears under its name only with a complete, synced
        # header (temp file + fsync + no-clobber link + directory fsync).
        tmp = f".{name}.{secrets.token_hex(6)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                     dir_fd=self.dir_fd)
        try:
            self._write_all(fd, line)
            exportfs.full_sync(fd)
        finally:
            os.close(fd)
        try:
            _checkpoint("journal-segment-before-link")
            os.link(tmp, name, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd, follow_symlinks=False)
        finally:
            try:
                os.unlink(tmp, dir_fd=self.dir_fd)
            except FileNotFoundError:
                pass
        exportfs.full_sync(self.dir_fd)
        self.seq += 1
        self.segments.append({"name": name, "size": len(line), "valid": len(line), "torn": False,
                              "last_seq": self.seq, "records": 1})

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError("short write")
            view = view[n:]

    def append(self, type_: str, op: str, **fields) -> dict:
        """Durably append one event. Raises JournalError on any failure; the caller must not
        perform its next remote mutation after that."""
        if self.broken:
            raise JournalError("journal-write-failed")
        if type_ not in EVENT_TYPES or not re.fullmatch(r"[0-9a-f]{32}", op):
            raise JournalError("journal-invalid-event")
        def build():
            r = {"v": SCHEMA, "seq": self.seq + 1, "ts": round(time.time(), 3), "type": type_, "op": op,
                 "host": self.host, **fields}
            return r, _line(r)

        rec, line = build()
        if len(line) > RECORD_MAX:
            raise JournalError("journal-record-too-large")
        try:
            cur = self.segments[-1]
            if cur["size"] + len(line) > SEGMENT_MAX and cur["records"] > 1:
                self._new_segment(pred=cur)   # rotation: a new segment; nothing is ever removed
                cur = self.segments[-1]
                rec, line = build()           # the header took a sequence number
            fd = os.open(cur["name"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.dir_fd)
            try:
                _checkpoint("journal-before-write")
                self._write_all(fd, line)
                exportfs.full_sync(fd)
            finally:
                os.close(fd)
        except OSError:
            self.broken = True
            raise JournalError("journal-write-failed") from None
        except JournalError:
            self.broken = True
            raise
        cur["size"] += len(line)
        cur["valid"] += len(line)
        cur["records"] += 1
        cur["last_seq"] = rec["seq"]
        self.seq = rec["seq"]
        self.ops.setdefault(op, Op(op)).apply(rec)
        return rec

    # --- queries ------------------------------------------------------------------------------
    def op(self, op_id: str) -> Op | None:
        return self.ops.get(op_id)

    def unresolved_for(self, account_id: str, label_id: str) -> list[Op]:
        """Operations on this account's label whose outcome still needs reconciliation."""
        return [o for o in self.ops.values() if o.blocking and o.prepared.get("account_id") == account_id
                and o.prepared.get("label_id") == label_id]

    def retained_bytes(self) -> int:
        return sum(s["size"] for s in self.segments)


def new_op_id() -> str:
    return secrets.token_hex(16)
