"""Export identity, manifest, durable artifact intent, and recovery (PLAN-v4 section 6).

Canonical directory: <root>/<account-ns>/<subfolder...>/<full message id>/ where
account-ns = "<alias>-<first 12 hex of sha256(verified address)>", so it binds to the
VERIFIED identity (rebinding an alias never reuses another account's exports). Subject,
date, and sender text live in the manifest and never name or rename a directory.

Inside it, three namespaces: attachments/, views/ (eml, html, pdf), and the reserved
metadata folder .gmail-mcp/ holding manifest.json — the only file ever atomically replaced.

Protocol for every artifact, under the message lock (held from manifest read through
publication and manifest completion):
  1. write a temporary file (bounded, 0600, quarantined, fsynced);
  2. durably record an INTENT in the manifest: artifact key, exact allocated basename,
     byte hash and size, required attributes, and the temporary file's identity;
  3. publish with a no-clobber hard link and persist the directory;
  4. durably mark the intent COMPLETE. A caller sees "saved" only after step 4.
Recovery (next call under the lock) verifies a final file against its intent before
completing it, resumes from a verified temporary file, or marks the intent abandoned so
the artifact is regenerated under the same name. Files with no durable binding are
reported as orphans and are never adopted by name or hash alone.

Manifest privacy: it holds the message's subject/sender/date display text, original
attachment names, hashes, and sizes. It is kept as long as the export folder exists; the
owner removes it with the export.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable

import exportfs
import locks
import names

SCHEMA = "gmail-mcp-export-manifest/1"
META_DIR = ".gmail-mcp"
MANIFEST = "manifest.json"
NAMESPACES = ("attachments", "views")
MANIFEST_CAP = 8 * 1024 * 1024
PER_FILE_CAP = 50 * 1024 * 1024
PER_CALL_FILES = 50
PER_CALL_BYTES = 200 * 1024 * 1024
MESSAGE_LOCK_TIMEOUT = 120.0
MAX_PUBLISH_ATTEMPTS = 20

STATES = ("saved", "already-present", "skipped", "refused", "failed")


def _checkpoint(stage: str) -> None:
    """Crash-test seam: tests replace this to kill the process at a protocol boundary."""


def identity_hash(verified_email: str) -> str:
    return hashlib.sha256(verified_email.strip().lower().encode()).hexdigest()


def account_namespace(alias: str, verified_email: str) -> str:
    return f"{alias}-{identity_hash(verified_email)[:12]}"


def artifact_key(*parts) -> str:
    """Stable key from the inputs that identify an artifact (never from output bytes)."""
    h = hashlib.sha256()
    for p in parts:
        b = p if isinstance(p, bytes) else json.dumps(p, sort_keys=True, ensure_ascii=False).encode()
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)
    return h.hexdigest()


@dataclass
class Target:
    root: exportfs.Root
    alias: str
    identity: str            # sha256 of the verified address
    account_ns: str
    subfolder: list[str]
    message_id: str

    @property
    def components(self) -> list[str]:
        return [self.account_ns, *self.subfolder, self.message_id]

    def display_path(self, namespace: str, name: str) -> str:
        return os.path.join(self.root.current_path(), *self.components, namespace, name)


def lock_key_for(dir_fd: int) -> str:
    """The message lock is keyed on the canonical directory's device and inode, so every
    spelling that reaches the same folder (APFS case or Unicode-normalization variants)
    shares one lock."""
    st = os.fstat(dir_fd)
    return artifact_key("message-lock", st.st_dev, st.st_ino)


@dataclass
class ItemResult:
    key: str
    kind: str
    state: str
    code: str = "ok"
    path: str | None = None
    name: str | None = None
    size: int | None = None
    sha256: str | None = None
    head: bytes = b""
    meta: dict = field(default_factory=dict)


class ProduceError(Exception):
    """A request could not be produced; `state` is "refused" or "failed"."""

    def __init__(self, state: str, code: str):
        super().__init__(code)
        self.state = state
        self.code = code


@dataclass
class Request:
    key: str
    kind: str                       # "attachment" | "eml" | "html" | "pdf"
    namespace: str                  # "attachments" | "views"
    plan: names.NamePlan
    produce: Callable[[int], exportfs.TempFile]   # writes a temp file into the namespace dir
    meta: dict = field(default_factory=dict)
    quarantine: bool = True


class ManifestError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ExportSession:
    """One canonical message directory, held under its message lock."""

    def __init__(self, target: Target, message_meta: dict, lock_timeout: float = MESSAGE_LOCK_TIMEOUT):
        self.t = target
        self.message_meta = message_meta
        self.lock_timeout = lock_timeout
        self._lock = None
        self._fds: dict[str, int] = {}
        self.manifest: dict = {}
        self.orphans: list[tuple[str, str]] = []
        self.recovered = 0
        self.conflicts = 0

    # --- lifecycle -----------------------------------------------------------------
    def __enter__(self):
        problem = self.t.root.check_live()
        if problem:
            raise ManifestError(problem)
        # Creating the directory chain needs no lock (mkdir races are handled); the lock is
        # then taken on the directory's identity before anything is read or written in it.
        try:
            msg_fd = exportfs.open_dir_chain(self.t.root.fd, self.t.components, create=True)
        except FileNotFoundError:
            raise ManifestError("destination-unavailable") from None
        self._fds["message"] = msg_fd
        try:
            self._lock = locks.message_lock(lock_key_for(msg_fd), self.lock_timeout)
            self._lock.__enter__()
        except Exception:
            self._lock = None
            self._close()
            raise
        try:
            for ns in (*NAMESPACES, META_DIR):
                self._fds[ns] = exportfs.open_child_dir(msg_fd, ns, create=True)
            self._load()
            self._recover()
        except Exception:
            self._close()
            raise
        return self

    def __exit__(self, *exc):
        self._close()
        return False

    def _close(self):
        for fd in self._fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds.clear()
        if self._lock is not None:
            self._lock.__exit__(None, None, None)
            self._lock = None

    # --- manifest --------------------------------------------------------------------
    def _load(self):
        raw = exportfs.read_reserved(self._fds[META_DIR], MANIFEST, MANIFEST_CAP)
        if raw is None:
            self.manifest = {
                "schema": SCHEMA,
                "account": {"alias": self.t.alias, "identity": self.t.identity},
                "message": {"id": self.t.message_id},
                "destination": {"name": self.t.root.name, "subfolder": self.t.subfolder},
                "entries": {},
            }
            return
        try:
            m = json.loads(raw)
        except ValueError:
            raise ManifestError("manifest-unreadable") from None
        if (not isinstance(m, dict) or m.get("schema") != SCHEMA
                or not isinstance(m.get("entries"), dict)
                or (m.get("account") or {}).get("identity") != self.t.identity
                or (m.get("message") or {}).get("id") != self.t.message_id):
            raise ManifestError("manifest-invalid")
        self.manifest = m

    def _save(self):
        self.manifest["message"].update({k: v for k, v in self.message_meta.items() if v is not None})
        self.manifest["updated"] = round(time.time(), 3)
        data = json.dumps(self.manifest, ensure_ascii=False, indent=1, sort_keys=True).encode()
        if len(data) > MANIFEST_CAP:
            raise ManifestError("manifest-too-large")
        exportfs.write_reserved(self._fds[META_DIR], MANIFEST, data)

    @property
    def entries(self) -> dict:
        return self.manifest["entries"]

    # --- verification --------------------------------------------------------------------
    @staticmethod
    def _matches(e: dict, ex: exportfs.Existing | None) -> bool:
        if ex is None or ex.kind != "regular":
            return False
        if ex.size != e.get("size") or ex.sha256 != e.get("sha256"):
            return False
        if ex.mode is None or ex.mode & 0o111:
            return False
        if (e.get("attrs") or {}).get("quarantine") and not ex.quarantined:
            return False
        return True

    def verify(self, e: dict) -> tuple[bool, str]:
        ex = exportfs.inspect_existing(self._fds[e["namespace"]], e["name"], PER_FILE_CAP)
        if ex is None:
            return False, "missing"
        if ex.kind != "regular":
            return False, "not-regular"
        if not self._matches(e, ex):
            return False, "modified"
        return True, "ok"

    # --- recovery ---------------------------------------------------------------------------
    def _recover(self):
        changed = False
        for e in self.entries.values():
            if e.get("state") != "intent":
                continue
            ns_fd = self._fds[e["namespace"]]
            ex = exportfs.inspect_existing(ns_fd, e["name"], PER_FILE_CAP)
            temp = e.get("temp") or {}
            if ex is not None:
                if self._matches(e, ex):
                    e["state"], e["completed"], e["recovered"] = "complete", round(time.time(), 3), True
                    exportfs.remove_temp(ns_fd, temp.get("name", ""), temp.get("ino"), temp.get("dev"))
                    self.recovered += 1
                else:
                    e["state"] = "conflict"  # the name holds something we cannot vouch for
                    self.conflicts += 1
                changed = True
                continue
            tex = exportfs.inspect_existing(ns_fd, temp["name"], PER_FILE_CAP) if temp.get("name") else None
            if tex is not None and tex.ino == temp.get("ino") and tex.dev == temp.get("dev") and self._matches(e, tex):
                try:
                    exportfs.publish(ns_fd, temp["name"], e["name"])
                    e["state"], e["completed"], e["recovered"] = "complete", round(time.time(), 3), True
                    self.recovered += 1
                except FileExistsError:
                    e["state"] = "conflict"
                    self.conflicts += 1
            else:
                e["state"] = "abandoned"  # regenerated under the same name when requested again
            changed = True
        if changed:
            self._save()
        bound = {(e["namespace"], (e.get("temp") or {}).get("name")) for e in self.entries.values()
                 if e.get("state") in ("intent", "conflict")}
        for ns in NAMESPACES:
            for n in exportfs.list_names(self._fds[ns]):
                if n.startswith(exportfs.TEMP_PREFIX) and (ns, n) not in bound:
                    self.orphans.append((ns, n))

    # --- names -------------------------------------------------------------------------------
    def _reserved_names(self, namespace: str, exclude_key: str | None = None) -> set[str]:
        return {e["name"].casefold() for k, e in self.entries.items()
                if e.get("namespace") == namespace and k != exclude_key and e.get("name")
                and e.get("state") in ("intent", "complete", "conflict", "stale")}

    def _allocate(self, req: Request, taken: set[str]) -> str:
        """The exact basename for a new intent: an abandoned (or vanished) artifact keeps its
        earlier name when that name is still free; otherwise the first free candidate.
        Names held by other entries (any live state) or present on disk are never reused."""
        ns_fd = self._fds[req.namespace]
        reserved = self._reserved_names(req.namespace, exclude_key=req.key) | taken
        prev = self.entries.get(req.key)
        if prev and prev.get("state") in ("abandoned", "stale") and prev.get("name"):
            n = prev["name"]
            if n.casefold() not in reserved and not exportfs.name_exists(ns_fd, n):
                return n
        for i in range(1, names.MAX_SUFFIX_N + 1):
            cand = req.plan.candidate(i)
            if cand.casefold() in reserved or exportfs.name_exists(ns_fd, cand):
                continue
            return cand
        raise ProduceError("failed", "name-collision-exhausted")

    # --- publication ----------------------------------------------------------------------------
    def publish(self, requests: list[Request]) -> list[ItemResult]:
        results: dict[str, ItemResult] = {}
        todo: list[Request] = []
        for r in requests:
            e = self.entries.get(r.key)
            if e and e.get("state") == "complete":
                ok, why = self.verify(e)
                if ok:
                    results[r.key] = ItemResult(r.key, r.kind, "already-present", "ok",
                                                self.t.display_path(e["namespace"], e["name"]), e["name"],
                                                e["size"], e["sha256"], bytes.fromhex(e.get("head", "")), dict(e.get("meta") or {}))
                    continue
                e["state"], e["stale_reason"] = "stale", why
            todo.append(r)

        produced: list[tuple[Request, exportfs.TempFile]] = []
        for r in todo:
            try:
                tf = r.produce(self._fds[r.namespace])
            except ProduceError as pe:
                results[r.key] = ItemResult(r.key, r.kind, pe.state, pe.code, meta=dict(r.meta))
                continue
            except exportfs.QuarantineError:
                results[r.key] = ItemResult(r.key, r.kind, "failed", "quarantine-failed", meta=dict(r.meta))
                continue
            except exportfs.TooLarge:
                results[r.key] = ItemResult(r.key, r.kind, "refused", "too-large", meta=dict(r.meta))
                continue
            except exportfs.InsufficientSpace:
                results[r.key] = ItemResult(r.key, r.kind, "failed", "insufficient-space", meta=dict(r.meta))
                continue
            except OSError:
                results[r.key] = ItemResult(r.key, r.kind, "failed", "write-failed", meta=dict(r.meta))
                continue
            except Exception:   # never let one artifact's failure abort the others
                results[r.key] = ItemResult(r.key, r.kind, "failed", "produce-failed", meta=dict(r.meta))
                continue
            produced.append((r, tf))
        _checkpoint("after-temp")

        # Step 1-2: durable intents (one manifest write for the batch).
        taken: set[str] = set()
        live: list[tuple[Request, exportfs.TempFile, dict]] = []
        for r, tf in produced:
            try:
                name = self._allocate(r, taken)
            except ProduceError as pe:
                exportfs.remove_temp(self._fds[r.namespace], tf.name, tf.ino, tf.dev)
                results[r.key] = ItemResult(r.key, r.kind, pe.state, pe.code, meta=dict(r.meta))
                continue
            taken.add(name.casefold())
            prev = self.entries.get(r.key)
            entry = {
                "key": r.key, "kind": r.kind, "namespace": r.namespace, "state": "intent",
                "name": name, "sha256": tf.sha256, "size": tf.size, "head": tf.head[:64].hex(),
                "attrs": {"mode": 0o600, "quarantine": tf.quarantined},
                "temp": {"name": tf.name, "ino": tf.ino, "dev": tf.dev},
                "meta": r.meta, "created": round(time.time(), 3),
            }
            if prev and prev.get("state") in ("stale", "abandoned", "conflict"):
                entry["previous"] = {k: prev.get(k) for k in ("name", "sha256", "state", "stale_reason")}
            self.entries[r.key] = entry
            live.append((r, tf, entry))
        try:
            if live:
                self._save()
        except Exception:
            for r, tf, entry in live:
                exportfs.remove_temp(self._fds[r.namespace], tf.name, tf.ino, tf.dev)
                results[r.key] = ItemResult(r.key, r.kind, "failed", "manifest-write-failed", meta=dict(r.meta))
            return [results[r.key] for r in requests]
        _checkpoint("after-intent")

        # Step 3: no-clobber publication; a name taken meanwhile gets a new durable intent.
        published = []
        for r, tf, entry in live:
            ns_fd = self._fds[r.namespace]
            for _ in range(MAX_PUBLISH_ATTEMPTS):
                try:
                    warns = exportfs.publish(ns_fd, tf.name, entry["name"])
                    if warns:
                        entry["publish_warnings"] = warns
                    published.append((r, tf, entry))
                    break
                except FileExistsError:
                    taken.add(entry["name"].casefold())
                    try:
                        entry["name"] = self._allocate(r, taken)
                        self._save()
                    except Exception:
                        entry["state"] = "abandoned"
                        break
                except OSError:
                    entry["state"] = "abandoned"
                    break
            else:
                entry["state"] = "abandoned"
            if entry["state"] == "abandoned":
                exportfs.remove_temp(ns_fd, tf.name, tf.ino, tf.dev)
                results[r.key] = ItemResult(r.key, r.kind, "failed", "publish-failed", meta=dict(r.meta))
        _checkpoint("after-link")

        # Step 4: durable completion; only now is anything reported as saved.
        for r, tf, entry in published:
            entry["state"], entry["completed"] = "complete", round(time.time(), 3)
            entry.pop("temp", None)
        try:
            self._save()
            ok = True
        except Exception:
            ok = False
        _checkpoint("after-complete")
        for r, tf, entry in published:
            if ok:
                results[r.key] = ItemResult(r.key, r.kind, "saved", "ok",
                                            self.t.display_path(r.namespace, entry["name"]), entry["name"],
                                            tf.size, tf.sha256, tf.head, dict(r.meta))
            else:
                results[r.key] = ItemResult(r.key, r.kind, "failed", "manifest-incomplete", meta=dict(r.meta))
        return [results[r.key] for r in requests]

    # --- reporting --------------------------------------------------------------------------------
    def retained_bytes(self) -> int:
        return sum(int(e.get("size") or 0) for e in self.entries.values() if e.get("state") == "complete")
