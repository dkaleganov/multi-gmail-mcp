"""PDF renderer: headless Chrome driven over the DevTools protocol on a private pipe
(PLAN-v4 section 9.2; decisions D1, D10, D13, D14).

Pipeline, all under the host render lock (one render per host across processes):
  spawn     posix_spawn (thread-safe; never preexec_fn) of Chrome with --headless=new
            --remote-debugging-pipe (no TCP port), a fresh private profile under
            <runtime>/render-tmp/, its own process group, the plan's dead-proxy and
            background-off flags, Chrome's sandbox ON. Only the two pipe ends become fds 3/4;
            stdin/stdout/stderr are /dev/null, so Chrome never writes to the MCP stdio
            stream. Chrome gets a private HOME and TMPDIR inside the render folder and never
            receives an export path.
  control   Before any untrusted content: target discovery, downloads denied, a fresh
            about:blank target (no opener), and ACKNOWLEDGED Page.enable,
            Emulation.setScriptExecutionDisabled(true), Fetch.enable for every URL, and
            auto-attach with wait-on-start. A failed or unsupported control fails closed.
  load      Page.setDocumentContent into about:blank (a load strategy, not a proof).
  police    Events are processed continuously. After content is loaded, only an allowlist
            of benign events passes; frames, navigation (including same-document), downloads,
            new targets, dialogs, crashes, and anything unknown fail the render. Every paused
            request is failed and every Fetch.failRequest reply is checked.
  ready     Load event, then a bounded poll (isolated world, prototype getters) until the
            document is complete, every <img> is complete, and fonts are loaded.
  D14       printToPDF of page max_pages+1: only the exact error "Page range exceeds page
            count" means the document fits; success means too many pages (refused); any
            other error fails. Re-checked after the full print.
  print     printToPDF(ReturnAsStream); IO.read in bounded chunks, decoded bytes counted and
            rejected at the first budget violation; IO.close.
  validate  %PDF- header, startxref/%%EOF trailer, xref offset in range and pointing at an
            xref table or object. A %PDF- prefix alone is not proof of completeness.
  supervise An independent thread enforces the whole-render deadline (work deadline =
            budget - shutdown grace) and the memory/scratch budgets, and on expiry attempts
            Browser.close, then SIGTERM/SIGKILL of the process group, reaps, and verifies the
            group (and any process still referencing the render folder) is gone before the
            profile is deleted.
Nothing is published by this module: it streams bytes into a caller-supplied sink (the
export protocol's temporary file) and raises RenderFailure on any failure.
"""
from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import select
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field

import exportfs
import locks
import procinfo
import runtime

RENDER_RECIPE = "v5-render-2"
OVERFLOW_ERROR = "Page range exceeds page count"
GRACE_SECONDS = 5.0            # shutdown grace, INSIDE the whole-render budget
RENDER_LOCK_WAIT = 60.0
MAX_PDF_BYTES = 50 * 1024 * 1024
MAX_IN_FRAME = 16 * 1024 * 1024
MAX_OUT_FRAME = 64 * 1024 * 1024
MAX_OUTSTANDING = 256
MAX_EVENTS = 20_000
IO_CHUNK = 1024 * 1024
MEASURE_INTERVAL_MS = 100      # sampling when no budget is configured (measurement only)

CHROME_CANDIDATES = ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",)

FLAGS = (
    "--headless=new", "--remote-debugging-pipe", "--disable-gpu", "--no-first-run",
    "--no-default-browser-check", "--disable-extensions", "--disable-sync",
    "--disable-background-networking", "--disable-component-update", "--mute-audio",
    "--proxy-server=127.0.0.1:9", "--proxy-bypass-list=<-loopback>",
    "--host-resolver-rules=MAP * ~NOTFOUND",
    # Additions beyond the plan's list; each only removes surface:
    "--use-mock-keychain",                                  # never touch the macOS Keychain
    "--disable-breakpad",                                   # (does NOT stop crashpad on macOS; see spawn env)
    "--disable-component-extensions-with-background-pages", # no component extension targets
    "--disable-default-apps",
)

PRINT_PARAMS = {
    "printBackground": True, "displayHeaderFooter": False, "preferCSSPageSize": False,
    "landscape": False, "scale": 1, "paperWidth": 8.5, "paperHeight": 11,
    "marginTop": 0.4, "marginBottom": 0.4, "marginLeft": 0.4, "marginRight": 0.4,
    "generateTaggedPDF": False, "generateDocumentOutline": False, "transferMode": "ReturnAsStream",
}

_INTERNAL_SCHEMES = ("chrome://", "chrome-untrusted://", "devtools://", "chrome-extension://", "chrome-search://")
# what the pipe reports once the supervisor has stopped Chrome: the supervisor's reason is the cause
_SUPERVISED_CODES = ("pipe-closed", "cdp-timeout", "control-not-acknowledged", "pipe-write-stalled")
_INTERNAL_TYPES = {"browser", "browser_ui", "tab"}
_ALLOWED_PAGE_EVENTS = {"Page.domContentEventFired", "Page.loadEventFired", "Page.lifecycleEvent",
                        "Page.frameStartedLoading", "Page.frameStoppedLoading", "Page.frameResized"}

# Printable width in CSS px (96 per inch) for the fixed paper and margins below.
PRINTABLE_WIDTH_PX = 739
MIN_SCALE = 0.1   # Chrome's lower bound for printToPDF scale

WIDTH_JS = r"""(() => {
  const g = (p, n, o) => Object.getOwnPropertyDescriptor(p, n).get.call(o);
  const sw = (e) => e ? g(Element.prototype, 'scrollWidth', e) : 0;
  return Math.max(sw(g(Document.prototype, 'documentElement', document)), sw(g(Document.prototype, 'body', document)));
})()"""

READY_JS = r"""(() => {
  const D = Document.prototype;
  const g = (p, n, o) => Object.getOwnPropertyDescriptor(p, n).get.call(o);
  const rs = g(D, 'readyState', document);
  const imgs = g(D, 'images', document);
  const len = g(HTMLCollection.prototype, 'length', imgs);
  const complete = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'complete').get;
  let pending = 0;
  for (let i = 0; i < len; i++) { if (!complete.call(HTMLCollection.prototype.item.call(imgs, i))) pending++; }
  const fs = g(FontFaceSet.prototype, 'status', g(D, 'fonts', document));
  return rs + '|' + pending + '|' + fs;
})()"""


class RenderFailure(Exception):
    """A render that must not be published. state: "refused" | "failed"; code: fixed."""

    def __init__(self, state: str, code: str, detail: str | None = None):
        super().__init__(code)
        self.state, self.code, self.detail = state, code, detail


class _Cancelled(Exception):
    pass


class _CDPError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


# --- readiness -----------------------------------------------------------------------------------
@dataclass
class Readiness:
    ready: bool
    code: str
    chrome_path: str | None = None
    chrome_version: str | None = None
    detail: str | None = None


_ready_cache: dict = {}


def find_chrome(settings) -> str | None:
    cands = (settings.chrome_path,) if settings.chrome_path else CHROME_CANDIDATES
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def chrome_version(path: str) -> str | None:
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=20,
                             env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out)
    return out[:120] if m else None


def _version_number(s: str | None) -> str | None:
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", s or "")
    return m.group(1) if m else None


def _sha_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _framework_stat(chrome: str) -> dict | None:
    """Identity of the Chrome framework binary (where the engine code lives): path, size,
    mtime, inode. Hashing ~400 MB on every readiness check would be too slow."""
    contents = pathlib.Path(chrome).resolve().parents[1]
    for fw in sorted(contents.glob("Frameworks/*.framework")):
        binary = fw / fw.stem
        if binary.exists():
            st = os.stat(binary)          # follows the Versions/Current symlink
            return {"path": os.path.realpath(binary), "size": st.st_size, "mtime_ns": st.st_mtime_ns,
                    "ino": st.st_ino}
    return None


def chrome_identity(path: str, version: str) -> dict:
    """What a gate record binds to: the Chrome launcher, its framework binary, the version,
    the render recipe, and the exact renderer and view code that the gates exercised."""
    here = pathlib.Path(__file__).resolve().parent
    return {"path": path, "version": version, "exe_sha256": _sha_file(path), "framework": _framework_stat(path),
            "recipe": RENDER_RECIPE, "code": {"renderer.py": _sha_file(here / "renderer.py"),
                                              "htmlview.py": _sha_file(here / "htmlview.py")}}


def _gate_path(identity: dict):
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:32]
    return runtime.private_dir("render-gates") / f"gates-{digest}.json"


def write_gate_record(identity: dict, summary: dict) -> str:
    """Written by tools/render_gates.py only when EVERY renderer gate passed for this exact
    Chrome binary, version, and render recipe."""
    p = _gate_path(identity)
    data = json.dumps({"identity": identity, "passed": True, "summary": summary,
                       "written": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, indent=1).encode()
    exportfs_fd = os.open(str(p.parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        exportfs.write_reserved(exportfs_fd, p.name, data)
    finally:
        os.close(exportfs_fd)
    _ready_cache.clear()
    return str(p)


def gates_passed(identity: dict) -> bool:
    p = _gate_path(identity)
    fd = None
    try:
        fd = os.open(str(p.parent), os.O_RDONLY | os.O_DIRECTORY)
        raw = exportfs.read_reserved(fd, p.name, 4 * 1024 * 1024)
    except (OSError, exportfs.UnsafePath):
        return False
    finally:
        if fd is not None:
            os.close(fd)
    if raw is None:
        return False
    try:
        rec = json.loads(raw)
    except ValueError:
        return False
    return rec.get("passed") is True and rec.get("identity") == identity


def readiness(settings, use_cache: bool = True) -> Readiness:
    """PDF output requires: valid settings, a Chrome binary, measured budget settings, and a
    passing gate record for this exact Chrome identity and render recipe. With the shipped
    defaults (budgets null) this returns budgets-not-set WITHOUT starting Chrome."""
    if settings.problems:
        return Readiness(False, "pdf-settings-invalid", detail=", ".join(settings.problems))
    path = find_chrome(settings)
    if path is None:
        return Readiness(False, "chrome-not-found")
    if not settings.budgets_set:
        return Readiness(False, "budgets-not-set", chrome_path=path,
                         detail="memory_budget_mb, scratch_budget_mb, and monitor_interval_ms are null")
    try:
        st = os.stat(path)
        cache_key = (path, st.st_mtime_ns, st.st_size, settings.memory_budget_mb, settings.scratch_budget_mb,
                     settings.monitor_interval_ms, settings.max_pages)
    except OSError:
        return Readiness(False, "chrome-not-found")
    hit = _ready_cache.get(cache_key)
    if use_cache and hit and time.monotonic() - hit[0] < 300:
        return hit[1]
    version = chrome_version(path)
    if version is None:
        res = Readiness(False, "chrome-version-unknown", chrome_path=path)
    else:
        ident = chrome_identity(path, version)
        if not gates_passed(ident):
            res = Readiness(False, "gates-not-passed", chrome_path=path, chrome_version=version,
                            detail="run tools/render_gates.py for this Chrome build")
        else:
            res = Readiness(True, "ready", chrome_path=path, chrome_version=version)
    _ready_cache[cache_key] = (time.monotonic(), res)
    return res


# --- process ---------------------------------------------------------------------------------------
class ChromeProc:
    """The spawned Chrome leader. Its exit is OBSERVED without reaping (waitid WNOWAIT), so
    its pid — which is the process group id — cannot be reused by an unrelated process while
    group signals are still being sent. reap() runs once, after the group is confirmed empty."""

    def __init__(self, pid: int):
        self.pid = self.pgid = pid
        self.returncode: int | None = None
        self.reaped = False
        self._lock = threading.Lock()

    def poll(self) -> int | None:
        with self._lock:
            if self.returncode is None and not self.reaped:
                try:
                    r = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    self.returncode, self.reaped = -1, True
                    return self.returncode
                if r is not None:
                    self.returncode = r.si_status if r.si_code == os.CLD_EXITED else -r.si_status
            return self.returncode

    def others_in_group(self) -> list[int]:
        return [p for p in procinfo.group_pids(self.pgid) if p != self.pid]

    def group_alive(self) -> bool:
        return self.poll() is None or bool(self.others_in_group())

    def signal_group(self, sig) -> None:
        with self._lock:
            if self.reaped:
                return  # never signal a group id that may since have been reused
            try:
                os.killpg(self.pgid, sig)
            except (ProcessLookupError, PermissionError):
                pass

    def reap(self) -> None:
        with self._lock:
            if self.reaped:
                return
            try:
                p, _ = os.waitpid(self.pid, os.WNOHANG)
                self.reaped = bool(p)
            except ChildProcessError:
                self.reaped = True


def _inheritable_fds() -> list[int]:
    out = []
    try:
        names = os.listdir("/dev/fd")
    except OSError:
        return out
    for n in names:
        try:
            fd = int(n)
        except ValueError:
            continue
        if fd <= 2:
            continue
        try:
            if os.get_inheritable(fd):
                out.append(fd)
        except OSError:
            continue
    return out


_PROXY_FLAGS = ("--proxy-server=127.0.0.1:9", "--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND")


LISTENER_ONLY_RESOLVER = "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1"


def spawn_chrome(chrome: str, rdir: str, extra_args: tuple = (), no_proxy: bool = False,
                 resolver: str | None = None) -> tuple[ChromeProc, int, int]:
    """Thread-safe spawn: posix_spawn file actions map the two pipe ends to fds 3 and 4,
    /dev/null to 0-2, and close any other inheritable descriptor. New process group."""
    profile = os.path.join(rdir, "profile")
    # BREAKPAD_DUMP_LOCATION moves Chrome's crash handler database into the render folder;
    # without it, chrome_crashpad_handler (which starts even with --disable-breakpad) binds to
    # the user's real Chrome crash database. MAC_CHROMIUM_TMPDIR does the same for temp state.
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(rdir, "home"),
           "TMPDIR": os.path.join(rdir, "tmp") + "/", "MAC_CHROMIUM_TMPDIR": os.path.join(rdir, "tmp"),
           "BREAKPAD_DUMP_LOCATION": os.path.join(rdir, "crashpad"), "LANG": "en_US.UTF-8"}
    mode = resolver or ("listener-only" if no_proxy else "production")
    flags = [f for f in FLAGS if not ((no_proxy and f in _PROXY_FLAGS[:2])
                                      or (mode != "production" and f.startswith("--host-resolver-rules=")))]
    if mode == "listener-only":
        # gate/test runs reach ONLY the local listener: every other host fails to resolve
        flags.append(LISTENER_ONLY_RESOLVER)
    argv = [chrome, *flags, *extra_args, f"--user-data-dir={profile}", "about:blank"]
    cmd_r, cmd_w = os.pipe()     # we write commands; Chrome reads fd 3
    res_r, res_w = os.pipe()     # Chrome writes fd 4; we read results
    child_in = fcntl.fcntl(cmd_r, fcntl.F_DUPFD_CLOEXEC, 10)
    child_out = fcntl.fcntl(res_w, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(cmd_r)
    os.close(res_w)
    devnull = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    try:
        last = None
        for _ in range(3):
            actions = [(os.POSIX_SPAWN_DUP2, devnull, 0), (os.POSIX_SPAWN_DUP2, devnull, 1),
                       (os.POSIX_SPAWN_DUP2, devnull, 2), (os.POSIX_SPAWN_DUP2, child_in, 3),
                       (os.POSIX_SPAWN_DUP2, child_out, 4)]
            for fd in _inheritable_fds():
                if fd not in (3, 4, child_in, child_out, devnull):
                    actions.append((os.POSIX_SPAWN_CLOSE, fd))
            try:
                pid = os.posix_spawn(chrome, argv, env, file_actions=actions, setpgroup=0,
                                     setsigdef=(signal.SIGPIPE, signal.SIGXFSZ, signal.SIGINT, signal.SIGTERM),
                                     setsigmask=())
                break
            except OSError as e:
                last = e
                if e.errno != errno.EBADF:
                    raise
        else:
            raise last
    except Exception:
        for fd in (cmd_w, res_r):
            os.close(fd)
        raise
    finally:
        for fd in (child_in, child_out, devnull):
            os.close(fd)
    os.set_blocking(cmd_w, False)
    os.set_blocking(res_r, False)
    return ChromeProc(pid), cmd_w, res_r


# --- transport --------------------------------------------------------------------------------------
class Transport:
    """NUL-delimited JSON over the pipe. Non-blocking fds, poll() with monotonic deadlines,
    partial-write handling, bounded frames. Checks the cancel event at least every 100 ms."""

    def __init__(self, wfd: int, rfd: int, cancel: threading.Event, reason):
        self.wfd, self.rfd = wfd, rfd
        self.cancel, self.reason = cancel, reason
        self.buf = bytearray()
        self.wlock = threading.Lock()
        self.bytes_in = 0

    def _check(self):
        if self.cancel.is_set():
            raise _Cancelled(self.reason() or "cancelled")

    def send(self, obj: dict, deadline: float, lock_timeout: float | None = None) -> None:
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode() + b"\0"
        if len(data) > MAX_OUT_FRAME:
            raise RenderFailure("refused", "html-too-large")
        if not self.wlock.acquire(timeout=max(0.0, lock_timeout if lock_timeout is not None else deadline - time.monotonic())):
            raise RenderFailure("failed", "pipe-write-stalled")
        try:
            view = memoryview(data)
            poller = select.poll()
            poller.register(self.wfd, select.POLLOUT)
            blocked = False                  # the pipe was full at least once (Chrome not reading)
            while view:
                if lock_timeout is None:
                    self._check()
                left = deadline - time.monotonic()
                if left <= 0:
                    # out of time: a stall only if Chrome left the pipe full; a write that found
                    # its deadline already gone (a busy host) is the caller's timeout
                    raise RenderFailure("failed", "pipe-write-stalled" if blocked else "deadline-passed")
                ev = poller.poll(min(left, 0.1) * 1000)
                if not ev:
                    blocked = True
                    continue
                if ev[0][1] & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                    raise RenderFailure("failed", "pipe-closed")
                try:
                    n = os.write(self.wfd, view)
                except BlockingIOError:
                    blocked = True
                    continue
                except (BrokenPipeError, OSError):
                    raise RenderFailure("failed", "pipe-closed") from None
                view = view[n:]
        finally:
            self.wlock.release()

    def recv(self, deadline: float) -> dict | None:
        poller = select.poll()
        poller.register(self.rfd, select.POLLIN)
        while True:
            idx = self.buf.find(b"\0")
            if idx >= 0:
                frame = bytes(self.buf[:idx])
                del self.buf[: idx + 1]
                try:
                    msg = json.loads(frame)
                except ValueError:
                    raise RenderFailure("failed", "protocol-error") from None
                if not isinstance(msg, dict):
                    raise RenderFailure("failed", "protocol-error")
                return msg
            if len(self.buf) > MAX_IN_FRAME:
                raise RenderFailure("failed", "frame-too-large")
            self._check()
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            ev = poller.poll(min(left, 0.1) * 1000)
            if not ev:
                continue
            try:
                chunk = os.read(self.rfd, 1 << 20)
            except BlockingIOError:
                continue
            except OSError:
                raise RenderFailure("failed", "pipe-closed") from None
            if not chunk:
                self._check()
                raise RenderFailure("failed", "pipe-closed")
            self.bytes_in += len(chunk)
            self.buf += chunk


# --- supervisor -----------------------------------------------------------------------------------------
@dataclass
class Metrics:
    samples: int = 0
    interval_ms: int = 0
    peak_footprint: int = 0
    peak_rss: int = 0
    peak_scratch: int = 0
    max_processes: int = 0
    trip_reason: str | None = None
    trip_at: float | None = None          # seconds since start
    trip_value: int | None = None
    post_trip_peak: int = 0               # highest observed value of the tripped measure after the trip
    kill_latency: float | None = None     # trip -> group gone
    group_gone: bool = False
    leftovers: int = 0
    elapsed: float = 0.0


class Supervisor(threading.Thread):
    """Independent of the CDP request loop: enforces the deadline and budgets and owns
    teardown. terminate() is idempotent and safe from either thread."""

    def __init__(self, proc: ChromeProc, rdir: str, t0: float, work_deadline: float, hard_deadline: float,
                 interval_ms: int | None, mem_budget: int | None, scratch_budget: int | None):
        super().__init__(daemon=True, name="render-supervisor")
        self.proc, self.rdir, self.t0 = proc, rdir, t0
        self.work_deadline, self.hard_deadline = work_deadline, hard_deadline
        self.interval = (interval_ms or MEASURE_INTERVAL_MS) / 1000.0
        self.mem_budget, self.scratch_budget = mem_budget, scratch_budget
        self.cancel = threading.Event()
        self.done = threading.Event()
        self.reason: str | None = None
        self.metrics = Metrics(interval_ms=int(self.interval * 1000))
        self.transport: Transport | None = None
        self._term_lock = threading.Lock()
        self._terminated = False
        self.external_cancel: threading.Event | None = None

    def run(self):
        """Tick at most every 50 ms for the deadline and cancellation; sample memory and
        scratch every monitor interval. Any fault in the supervisor itself fails closed: the
        render is tripped and Chrome is torn down."""
        try:
            next_sample = time.monotonic()
            while not self.done.is_set():
                now = time.monotonic()
                if self.reason is None and now >= self.work_deadline:
                    self.trip("render-timeout", None)
                if self.reason is None and self.external_cancel is not None and self.external_cancel.is_set():
                    self.trip("cancelled", None)
                if self.reason is None and now >= next_sample:
                    self.sample()
                    next_sample = now + self.interval
                if self.reason is not None:
                    self.terminate()
                    return
                now = time.monotonic()
                self.done.wait(max(0.0, min(0.05, next_sample - now, self.work_deadline - now)))
        except Exception:
            try:
                self.trip("supervisor-error", None)
            finally:
                self.terminate()

    def sample(self):
        n, rss, fp = procinfo.group_memory(self.proc.pgid)
        scratch = procinfo.tree_bytes(self.rdir)
        m = self.metrics
        m.samples += 1
        m.max_processes = max(m.max_processes, n)
        m.peak_rss = max(m.peak_rss, rss)
        m.peak_footprint = max(m.peak_footprint, fp)
        m.peak_scratch = max(m.peak_scratch, scratch)
        if self.reason is None:
            if self.mem_budget is not None and fp > self.mem_budget:
                self.trip("memory-budget-exceeded", fp)
            elif self.scratch_budget is not None and scratch > self.scratch_budget:
                self.trip("scratch-budget-exceeded", scratch)
        elif self.metrics.trip_reason == "memory-budget-exceeded":
            m.post_trip_peak = max(m.post_trip_peak, fp)
        elif self.metrics.trip_reason == "scratch-budget-exceeded":
            m.post_trip_peak = max(m.post_trip_peak, scratch)

    def trip(self, reason: str, value: int | None):
        if self.reason is None:
            self.reason = reason
            m = self.metrics
            m.trip_reason, m.trip_value = reason, value
            m.trip_at = round(time.monotonic() - self.t0, 3)
            m.post_trip_peak = value or 0
            self.cancel.set()

    def terminate(self, graceful: bool = False):
        """Browser.close (bounded), then SIGTERM/SIGKILL of the group, reap, verify gone."""
        with self._term_lock:
            if self._terminated:
                return
            self._terminated = True
            t_start = time.monotonic()
            close_by = min(self.hard_deadline - 1.0, t_start + (2.0 if graceful else 1.0))
            if self.transport is not None and self.proc.poll() is None:
                try:
                    self.transport.send({"id": 999_999_999, "method": "Browser.close", "params": {}},
                                        deadline=max(time.monotonic() + 0.05, min(close_by, time.monotonic() + 0.5)),
                                        lock_timeout=0.2)
                except Exception:
                    pass
            while time.monotonic() < close_by and self.proc.poll() is None:
                if self.reason in ("memory-budget-exceeded", "scratch-budget-exceeded"):
                    try:
                        self.sample()
                    except Exception:
                        pass
                time.sleep(0.02)
            if self.proc.group_alive():          # the leader is still unreaped here
                self.proc.signal_group(signal.SIGTERM)
                t_term = time.monotonic() + 0.3
                while time.monotonic() < t_term and self.proc.group_alive():
                    time.sleep(0.02)
                self.proc.signal_group(signal.SIGKILL)
            while time.monotonic() < self.hard_deadline and self.proc.group_alive():
                time.sleep(0.02)
            left = procinfo.pids_referencing(self.rdir)   # e.g. a crash handler outside the group
            for pid in left:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            if left:
                end = min(self.hard_deadline, time.monotonic() + 1.0)
                while time.monotonic() < end and procinfo.pids_referencing(self.rdir):
                    time.sleep(0.05)
            gone = not self.proc.group_alive() and not procinfo.pids_referencing(self.rdir)
            self.proc.reap()                      # only now may the group id be reused
            m = self.metrics
            m.leftovers = len(left)
            m.group_gone = gone
            if m.trip_at is not None:
                m.kill_latency = round(time.monotonic() - self.t0 - m.trip_at, 3)
            m.elapsed = round(time.monotonic() - self.t0, 3)
            self.done.set()


# --- CDP client with event policy ----------------------------------------------------------------------
@dataclass
class Ablations:
    """TEST AND GATE USE ONLY (positive controls and single-layer runs). Production
    (render_to_temp) never passes this, so every control is always on there."""
    scripts_enabled: bool = False
    no_intercept: bool = False
    no_auto_attach: bool = False
    no_proxy: bool = False            # drop the dead-proxy flags
    # Resolver rule: "production" (MAP * ~NOTFOUND) or "listener-only" (everything still fails
    # to resolve except localhost and 127.0.0.1, so a control can reach the local listener but
    # Chrome's own background services cannot reach the internet). None = production, or
    # listener-only when no_proxy is set.
    resolver: str | None = None
    observe_only: bool = False        # record isolation violations instead of failing
    navigate_url: str | None = None   # load by navigation (file-origin positive control)


@dataclass
class RenderReport:
    sink_result: object = None
    chrome_product: str | None = None
    metrics: Metrics | None = None
    blocked_requests: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    events: list = field(default_factory=list)
    acks: list = field(default_factory=list)
    inspect: dict = field(default_factory=dict)
    pdf_bytes: int = 0
    scale: float | None = None
    pages_ok: bool | None = None
    tail_ok: bool | None = None
    failure: str | None = None
    cleaned: bool = False


class _Session:
    def __init__(self, transport: Transport, sup: Supervisor, report: RenderReport, record_events: bool,
                 observe_only: bool = False):
        self.t, self.sup, self.r = transport, sup, report
        self.observe_only = observe_only
        self.next_id = 0
        self.replies: dict[int, dict] = {}
        self.waiting: set[int] = set()
        self.fail_ids: set[int] = set()
        self.events_seen = 0
        self.record_events = record_events
        self.page_session: str | None = None
        self.target_id: str | None = None
        self.main_frame: str | None = None
        self.content_loaded = False
        self.documents_opened = 0
        self.load_fired = False

    # transport-level
    def _send(self, method: str, params: dict | None, session: str | None, deadline: float) -> int:
        if len(self.waiting) + len(self.fail_ids) >= MAX_OUTSTANDING:
            raise RenderFailure("failed", "too-many-outstanding-requests")
        self.next_id += 1
        msg = {"id": self.next_id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        try:
            self.t.send(msg, deadline)
        except RenderFailure as rf:
            if rf.code != "deadline-passed":
                raise
            # same rule as a missing reply: past the whole-render work deadline it is a render
            # timeout, whichever thread notices first; an earlier private deadline is a CDP timeout
            code = "render-timeout" if deadline >= self.sup.work_deadline else "cdp-timeout"
            raise RenderFailure("failed", code, detail=method) from None
        return self.next_id

    def call(self, method: str, params: dict | None = None, session: str | None = None,
             deadline: float | None = None, ack: bool = False) -> dict:
        deadline = deadline or self.sup.work_deadline
        mid = self._send(method, params, session, deadline)
        self.waiting.add(mid)
        while mid not in self.replies:
            msg = self.t.recv(deadline)
            if msg is None:
                # no reply by the whole-render work deadline is a render timeout, whichever
                # thread notices first; an earlier private deadline is a CDP timeout
                code = "render-timeout" if deadline >= self.sup.work_deadline else "cdp-timeout"
                raise RenderFailure("failed", code, detail=method)
            self._dispatch(msg)
        reply = self.replies.pop(mid)
        if "error" in reply:
            err = reply.get("error") or {}
            if ack:
                raise RenderFailure("failed", "control-not-acknowledged", detail=method)
            raise _CDPError(err.get("code"), err.get("message"))
        if ack:
            self.r.acks.append(method)
        return reply.get("result") or {}

    def pump(self, until: float) -> None:
        while time.monotonic() < until:
            msg = self.t.recv(until)
            if msg is None:
                return
            self._dispatch(msg)

    def _dispatch(self, msg: dict) -> None:
        if "id" in msg:
            mid = msg.get("id")
            if mid in self.fail_ids:
                self.fail_ids.discard(mid)
                if "error" in msg:
                    self._violation("fetch-fail-request-rejected")
                return
            if mid in self.waiting:
                self.waiting.discard(mid)
                self.replies[mid] = msg
            return
        self.events_seen += 1
        if self.events_seen > MAX_EVENTS:
            raise RenderFailure("failed", "event-flood")
        method = msg.get("method") or ""
        params = msg.get("params") or {}
        sid = msg.get("sessionId")
        if self.record_events and len(self.r.events) < 2000:
            self.r.events.append(self._summarize(method, params, sid))
        self._police(method, params, sid)

    @staticmethod
    def _summarize(method, params, sid):
        info = params.get("targetInfo") or {}
        frame = params.get("frame") or {}
        return {"m": method, "s": bool(sid), "type": info.get("type"), "url": (info.get("url") or frame.get("url")
                or params.get("url") or "")[:200], "name": params.get("name")}

    def _violation(self, code: str) -> None:
        self.r.violations.append(code)
        if not self.observe_only:
            raise RenderFailure("failed", "isolation-violation", detail=code)

    @staticmethod
    def _internal(info: dict) -> bool:
        return info.get("type") in _INTERNAL_TYPES or (info.get("url") or "").startswith(_INTERNAL_SCHEMES)

    def _police(self, method: str, params: dict, sid: str | None) -> None:
        if method == "Fetch.requestPaused":
            req = params.get("request") or {}
            if len(self.r.blocked_requests) < 200:
                self.r.blocked_requests.append((req.get("url") or "")[:200])
            fid = self._send("Fetch.failRequest", {"requestId": params.get("requestId"), "errorReason": "BlockedByClient"},
                             sid, self.sup.work_deadline)
            self.fail_ids.add(fid)
            return
        if method in ("Inspector.detached", "Inspector.targetCrashed", "Target.targetCrashed"):
            raise RenderFailure("failed", "renderer-crashed")
        if method.startswith("Browser.download") or method.startswith("Page.download"):
            return self._violation("download")
        if method.startswith("Target."):
            info = params.get("targetInfo") or {}
            if method == "Target.attachedToTarget":
                if sid is not None and sid == self.page_session:
                    # an auxiliary target auto-attached under our page: close and reject it
                    tid = info.get("targetId")
                    if tid:
                        try:
                            self._send("Target.closeTarget", {"targetId": tid}, None, self.sup.work_deadline)
                        except RenderFailure:
                            pass
                    self._violation("auxiliary-target")
                return
            if method == "Target.detachedFromTarget":
                if params.get("sessionId") == self.page_session:
                    raise RenderFailure("failed", "target-detached")
                return
            if method == "Target.targetDestroyed":
                if params.get("targetId") == self.target_id:
                    raise RenderFailure("failed", "target-destroyed")
                return
            if info.get("targetId") == self.target_id:
                if method == "Target.targetInfoChanged" and self.content_loaded and info.get("url") != "about:blank":
                    self._violation("navigation")
                return
            if self.content_loaded and not self._internal(info):
                self._violation("unexpected-target")
            return
        if sid is not None and sid == self.page_session:
            if not self.content_loaded:
                return
            if method == "Page.documentOpened":
                self.documents_opened += 1
                if self.documents_opened > 1:
                    self._violation("document-replaced")
                return
            if method == "Page.lifecycleEvent":
                if params.get("frameId") != self.main_frame:
                    self._violation("unexpected-frame")
                return
            if method == "Page.loadEventFired":
                self.load_fired = True
                return
            if method in _ALLOWED_PAGE_EVENTS:
                return
            return self._violation({
                "Page.frameAttached": "frame", "Page.frameNavigated": "navigation",
                "Page.navigatedWithinDocument": "navigation", "Page.frameRequestedNavigation": "navigation",
                "Page.frameScheduledNavigation": "navigation", "Page.frameStartedNavigating": "navigation",
                "Page.windowOpen": "window-open", "Page.javascriptDialogOpening": "dialog",
                "Page.fileChooserOpened": "file-chooser",
            }.get(method, "unexpected-event"))
        if self.content_loaded and sid is not None and sid != self.page_session:
            self._violation("unexpected-session")   # e.g. a child target's session
        if sid is None and self.content_loaded and not method.startswith("Target."):
            self._violation("unexpected-event")


def _drain_fail_requests(s: "_Session") -> None:
    """Wait (bounded) for the reply to every Fetch.failRequest sent so far; a rejected or
    missing acknowledgement fails the render."""
    end = min(s.sup.work_deadline, time.monotonic() + 3.0)
    while s.fail_ids and time.monotonic() < end:
        msg = s.t.recv(end)
        if msg is not None:
            s._dispatch(msg)
    if s.fail_ids:
        raise RenderFailure("failed", "isolation-violation", detail="fetch-fail-request-unacknowledged")


def _validate_pdf_tail(tail: bytes, total: int) -> int | None:
    """The xref offset if the trailer is well formed, else None."""
    m = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", tail)
    if not m:
        return None
    off = int(m.group(1))
    return off if 0 < off < total else None


def make_render_dir() -> str:
    base = runtime.private_dir("render-tmp")
    rdir = base / f"r-{secrets.token_hex(8)}"
    os.mkdir(rdir, 0o700)
    for sub in ("profile", "tmp", "home", "crashpad"):
        os.mkdir(rdir / sub, 0o700)
    return str(rdir)


def _write_owner(rdir: str, pgid: int | None) -> None:
    rec = {"pid": os.getpid(), "start": procinfo.start_time(os.getpid()), "pgid": pgid,
           "created": round(time.time(), 3)}
    fd = os.open(os.path.join(rdir, "owner.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(rec).encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def render(page: bytes, settings, chrome: str, sink, *, chrome_version_expected: str | None = None,
           ablate: Ablations | None = None, record_events: bool = False, inspect=None,
           extra_args: tuple = (), cancel: threading.Event | None = None) -> RenderReport:
    """Render `page` (the wrapped HTML) and stream the PDF into sink(chunks). The caller
    must hold the render lock. Raises RenderFailure (report attached as .report)."""
    ablate = ablate or Ablations()
    report = RenderReport()
    budget = float(settings.render_timeout_seconds)
    t0 = time.monotonic()
    work_deadline = t0 + budget - GRACE_SECONDS
    hard_deadline = t0 + budget
    mem = int(settings.memory_budget_mb * 1024 * 1024) if settings.memory_budget_mb else None
    scr = int(settings.scratch_budget_mb * 1024 * 1024) if settings.scratch_budget_mb else None
    rdir = make_render_dir()
    _write_owner(rdir, None)
    try:
        proc, wfd, rfd = spawn_chrome(chrome, rdir, extra_args, no_proxy=ablate.no_proxy, resolver=ablate.resolver)
    except OSError:
        shutil.rmtree(rdir, ignore_errors=True)
        raise RenderFailure("failed", "chrome-spawn-failed") from None
    _write_owner(rdir, proc.pgid)
    sup = Supervisor(proc, rdir, t0, work_deadline, hard_deadline, settings.monitor_interval_ms, mem, scr)
    sup.external_cancel = cancel
    transport = Transport(wfd, rfd, sup.cancel, lambda: sup.reason)
    sup.transport = transport
    sup.start()
    s = _Session(transport, sup, report, record_events, observe_only=ablate.observe_only)
    failure: RenderFailure | None = None
    try:
        try:
            report.sink_result = _drive(s, page, settings, sink, ablate, inspect, chrome_version_expected, report)
        except _Cancelled as c:
            raise RenderFailure("failed", sup.reason or str(c)) from None
        except _CDPError:
            raise RenderFailure("failed", "render-failed") from None
        except RenderFailure:
            raise
        except exportfs.QuarantineError:
            raise RenderFailure("failed", "quarantine-failed") from None
        except exportfs.InsufficientSpace:
            raise RenderFailure("failed", "insufficient-space") from None
        except exportfs.TooLarge:
            raise RenderFailure("refused", "pdf-too-large") from None
        except OSError:
            raise RenderFailure("failed", "write-failed") from None
        except Exception:   # e.g. a malformed DevTools reply: fail closed, never escape
            raise RenderFailure("failed", "render-failed") from None
    except RenderFailure as rf:
        if sup.reason and rf.code in _SUPERVISED_CODES:
            rf = RenderFailure("failed", sup.reason, rf.detail)
        failure = rf
        report.failure = rf.code
    finally:
        sup.terminate(graceful=failure is None)
        sup.done.set()
        sup.join(timeout=max(0.0, hard_deadline - time.monotonic()) + 1.0)
        for fd in (wfd, rfd):
            try:
                os.close(fd)
            except OSError:
                pass
        report.metrics = sup.metrics
        if sup.metrics.group_gone:
            shutil.rmtree(rdir, ignore_errors=True)
            report.cleaned = not os.path.exists(rdir)
    if failure is None and not sup.metrics.group_gone:
        failure = RenderFailure("failed", "cleanup-incomplete")
        report.failure = failure.code
    if failure is not None:
        failure.report = report
        raise failure
    return report


def _drive(s: _Session, page: bytes, settings, sink, ablate: Ablations, inspect, expected_version, report):
    ver = s.call("Browser.getVersion", ack=True)
    report.chrome_product = ver.get("product")
    if expected_version and _version_number(ver.get("product")) != _version_number(expected_version):
        raise RenderFailure("failed", "chrome-version-changed")
    s.call("Target.setDiscoverTargets", {"discover": True}, ack=True)
    s.call("Browser.setDownloadBehavior", {"behavior": "deny", "eventsEnabled": True}, ack=True)
    existing = [t for t in (s.call("Target.getTargets").get("targetInfos") or [])
                if t.get("type") == "page" and not _Session._internal(t)]
    s.target_id = s.call("Target.createTarget", {"url": "about:blank", "newWindow": False}, ack=True)["targetId"]
    for t in existing:   # the initial about:blank tab: close it so only our target exists
        if t.get("targetId") != s.target_id:
            s.call("Target.closeTarget", {"targetId": t["targetId"]})
    s.page_session = s.call("Target.attachToTarget", {"targetId": s.target_id, "flatten": True}, ack=True)["sessionId"]
    ps = s.page_session
    s.call("Page.enable", session=ps, ack=True)
    s.call("Page.setLifecycleEventsEnabled", {"enabled": True}, session=ps, ack=True)
    s.call("Emulation.setScriptExecutionDisabled", {"value": not ablate.scripts_enabled}, session=ps, ack=True)
    if not ablate.no_intercept:
        s.call("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]}, session=ps, ack=True)
    if not ablate.no_auto_attach:
        s.call("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True},
               session=ps, ack=True)
    tree = s.call("Page.getFrameTree", session=ps)["frameTree"]
    if tree.get("childFrames") or tree["frame"].get("url") != "about:blank":
        raise RenderFailure("failed", "unexpected-initial-state")
    s.main_frame = tree["frame"]["id"]
    s.content_loaded = True
    if ablate.navigate_url:
        s.call("Page.navigate", {"url": ablate.navigate_url}, session=ps)
    else:
        s.call("Page.setDocumentContent", {"frameId": s.main_frame, "html": page.decode("utf-8")},
               session=ps, ack=True)

    # Readiness: load event, then a bounded synchronous poll (timers do not run with scripts off).
    # Running out of the work budget here means the page never became ready, whichever thread
    # notices first (this one, or the supervisor's timeout): always render-not-ready.
    try:
        while not s.load_fired:
            msg = s.t.recv(s.sup.work_deadline)
            if msg is None:
                raise RenderFailure("failed", "render-not-ready")
            s._dispatch(msg)
        ctx = s.call("Page.createIsolatedWorld", {"frameId": s.main_frame, "worldName": "gmcp-ready",
                                                  "grantUniveralAccess": False}, session=ps)["executionContextId"]
        delay = 0.02
        while True:
            r = s.call("Runtime.evaluate", {"expression": READY_JS, "contextId": ctx, "returnByValue": True},
                       session=ps)
            val = ((r.get("result") or {}).get("value") or "")
            parts = val.split("|")
            if len(parts) == 3 and parts[0] == "complete" and parts[1] == "0" and parts[2] == "loaded":
                break
            if time.monotonic() + delay >= s.sup.work_deadline:
                raise RenderFailure("failed", "render-not-ready")
            s.pump(time.monotonic() + delay)
            delay = min(delay * 2, 0.2)
            if time.monotonic() >= s.sup.work_deadline:      # a busy host can overshoot the pause
                raise RenderFailure("failed", "render-not-ready")
    except _Cancelled as c:
        if (s.sup.reason or str(c)) == "render-timeout":
            raise RenderFailure("failed", "render-not-ready") from None
        raise
    except RenderFailure as rf:
        # the work deadline passed while waiting for readiness: whatever the pipe reported once
        # the supervisor acted (render() would otherwise map it to render-timeout)
        if rf.code == "render-timeout" or (s.sup.reason == "render-timeout" and rf.code in _SUPERVISED_CODES):
            raise RenderFailure("failed", "render-not-ready", rf.detail) from None
        raise
    if inspect is not None:
        report.inspect = inspect(s, ps, ctx) or {}

    # Horizontal fit (never clip silently): measure the content width in print media at the
    # printable width; if it is wider, print at scale = width / content width (Chrome lays the
    # page out at width / scale), verify the fit at that width, and refuse what cannot fit.
    s.call("Emulation.setEmulatedMedia", {"media": "print"}, session=ps, ack=True)

    def measure(width: int) -> int:
        s.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": 1100, "deviceScaleFactor": 1,
                                                      "mobile": False}, session=ps, ack=True)
        r = s.call("Runtime.evaluate", {"expression": WIDTH_JS, "contextId": ctx, "returnByValue": True}, session=ps)
        v = (r.get("result") or {}).get("value")
        if not isinstance(v, (int, float)) or v < 0:
            raise RenderFailure("failed", "measure-failed")
        return int(v)

    W = PRINTABLE_WIDTH_PX
    width1 = measure(W)
    scale = 1.0
    if width1 > W + 1:
        scale = math.floor(W / width1 * 10000) / 10000
        if scale < MIN_SCALE:
            raise RenderFailure("refused", "too-wide")
        W2 = math.ceil(W / scale)
        if measure(W2) > W2 + 2:
            raise RenderFailure("refused", "too-wide")      # content grows with the page width
    s.call("Emulation.clearDeviceMetricsOverride", session=ps, ack=True)
    report.scale = scale
    params = {**PRINT_PARAMS, "scale": scale}
    _drain_fail_requests(s)

    n = int(settings.max_pages)

    def fits() -> bool:
        try:
            res = s.call("Page.printToPDF", {**params, "pageRanges": str(n + 1)}, session=ps)
        except _CDPError as e:
            if e.message == OVERFLOW_ERROR:
                return True
            raise RenderFailure("failed", "print-error") from None
        h = res.get("stream")
        if h:
            try:
                s.call("IO.close", {"handle": h}, session=ps)
            except _CDPError:
                pass
        return False

    if not fits():
        report.pages_ok = False
        raise RenderFailure("refused", "too-many-pages")
    try:
        res = s.call("Page.printToPDF", params, session=ps)
    except _CDPError:
        raise RenderFailure("failed", "print-error") from None
    handle = res.get("stream")
    if not handle:
        raise RenderFailure("failed", "print-no-stream")
    tail = bytearray()
    total = [0]

    def chunks():
        while True:
            try:
                r = s.call("IO.read", {"handle": handle, "size": IO_CHUNK}, session=ps)
            except _CDPError:
                raise RenderFailure("failed", "stream-error") from None
            data = r.get("data") or ""
            if not r.get("base64Encoded"):
                raise RenderFailure("failed", "stream-not-binary")
            try:
                b = base64.b64decode(data, validate=True)
            except ValueError:
                raise RenderFailure("failed", "stream-error") from None
            if len(b) > IO_CHUNK * 2:
                raise RenderFailure("failed", "stream-chunk-too-large")
            total[0] += len(b)
            if total[0] > MAX_PDF_BYTES:
                raise RenderFailure("refused", "pdf-too-large")
            tail.extend(b)
            if len(tail) > 4096:
                del tail[: len(tail) - 4096]
            if b:
                yield b
            if r.get("eof"):
                break
        try:
            s.call("IO.close", {"handle": handle}, session=ps)
        except _CDPError:
            pass

    result = sink(chunks())
    report.pdf_bytes = total[0]
    try:
        if not fits():   # D14 re-check after the full print: layout must not have grown
            report.pages_ok = False
            raise RenderFailure("refused", "too-many-pages")
        report.pages_ok = True
        off = _validate_pdf_tail(bytes(tail), total[0])
        report.tail_ok = off is not None
        if off is None:
            raise RenderFailure("failed", "malformed-pdf")
        verify = getattr(sink, "verify_xref", None)
        if verify is not None and not verify(result, off):
            raise RenderFailure("failed", "malformed-pdf")
        _drain_fail_requests(s)     # every request-blocking reply checked before acceptance
    except RenderFailure:
        discard = getattr(sink, "discard", None)
        if discard is not None:
            discard(result)
        raise
    return result


# --- production entry point -------------------------------------------------------------------------------
class TempSink:
    """Streams the PDF into an export temporary file (exportfs.write_temp) and can verify
    the xref offset and discard the temp file on a late failure."""

    def __init__(self, dir_fd: int):
        self.dir_fd = dir_fd

    def __call__(self, chunks):
        # free space is checked against the PDF cap before anything is written (C5)
        tf = exportfs.write_temp(self.dir_fd, chunks, MAX_PDF_BYTES, expected_size=MAX_PDF_BYTES, quarantine=True)
        if not tf.head.startswith(b"%PDF-"):
            self.discard(tf)
            raise RenderFailure("failed", "malformed-pdf")
        return tf

    def verify_xref(self, tf, off: int) -> bool:
        try:
            fd = os.open(tf.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.dir_fd)
        except OSError:
            return False
        try:
            st = os.fstat(fd)
            if st.st_ino != tf.ino:
                return False
            at = os.pread(fd, 32, off)
        finally:
            os.close(fd)
        return at.startswith(b"xref") or re.match(rb"\d+\s+\d+\s+obj", at) is not None

    def discard(self, tf) -> None:
        if tf is not None:
            exportfs.remove_temp(self.dir_fd, tf.name, tf.ino, tf.dev)


def render_to_temp(dir_fd: int, page: bytes, settings, ready: Readiness):
    """Production: one render under the host render lock, after cleanup of proven-abandoned
    render folders; returns the export temporary file (never published here)."""
    if not ready.ready:
        raise RenderFailure("refused", "pdf-unavailable")
    try:
        with locks.render_lock(RENDER_LOCK_WAIT):
            cleanup_abandoned()
            rep = render(page, settings, ready.chrome_path, TempSink(dir_fd),
                         chrome_version_expected=ready.chrome_version)
            rep.sink_result.render_scale = rep.scale
            return rep.sink_result
    except locks.LockTimeout:
        raise RenderFailure("failed", "renderer-busy") from None


# --- cleanup of abandoned render folders -----------------------------------------------------------------
def cleanup_abandoned() -> dict:
    """Caller holds the render lock, so no render on this host is active. A folder is
    removed only when PROVEN abandoned: its owner process is gone (pid + start time), and no
    process remains in its recorded group or references the folder (leftovers are killed
    first, then re-verified). A folder whose owner is alive is left alone."""
    base = runtime.private_dir("render-tmp")
    stats = {"removed": 0, "kept_owner_alive": 0, "kept_processes": 0}
    for entry in sorted(os.listdir(base)):
        if not entry.startswith("r-"):
            continue
        path = str(base / entry)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        if not os.path.isdir(path) or os.path.islink(path) or st.st_uid != os.getuid():
            continue
        owner = {}
        try:
            with open(os.path.join(path, "owner.json"), "rb") as f:
                owner = json.loads(f.read(4096) or b"{}")
        except (OSError, ValueError):
            owner = {}
        opid, ostart = owner.get("pid"), owner.get("start")
        if isinstance(opid, int) and opid != os.getpid() and procinfo.alive_with_start(opid, ostart):
            stats["kept_owner_alive"] += 1
            continue
        pgid = owner.get("pgid")
        if isinstance(pgid, int) and pgid > 1:
            for pid in procinfo.group_pids(pgid):
                if path in " ".join(_cmdline(pid)):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
        for pid in procinfo.pids_referencing(path):
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        end = time.monotonic() + 2.0
        while time.monotonic() < end and procinfo.pids_referencing(path):
            time.sleep(0.05)
        if procinfo.pids_referencing(path):
            stats["kept_processes"] += 1
            continue
        shutil.rmtree(path, ignore_errors=True)
        stats["removed"] += 1
    return stats


def _cmdline(pid: int) -> list[str]:
    try:
        out = subprocess.run(["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=5, env={"PATH": "/usr/bin:/bin"}).stdout
        return [out.strip()]
    except (OSError, subprocess.SubprocessError):
        return []


def startup_cleanup() -> None:
    """At server start: try the render lock without waiting; if another render is active,
    skip (the next render cleans up under the lock)."""
    try:
        with locks.render_lock(0):
            cleanup_abandoned()
    except Exception:
        pass
