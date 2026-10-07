"""A fake Chrome speaking the DevTools pipe protocol on fds 3 (in) and 4 (out), with
deliberate misbehaviour modes for the transport and supervisor gates. Synthetic only.

Invoked through a per-mode wrapper script: fake_chrome.py --mode=<mode> <chrome flags...>
"""
import base64
import json
import os
import signal
import subprocess
import sys
import time

if "--version" in sys.argv:
    print("Google Chrome 154.0.8037.93")
    sys.exit(0)
MODE = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--mode=")), "normal")
REPORT = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--report=")), None)
if REPORT:
    _fds, _ids = [], []
    for _x in sorted(int(x) for x in os.listdir("/dev/fd")):
        try:
            _st = os.fstat(_x)
        except OSError:
            continue  # the listdir handle, already closed
        _fds.append(_x)
        _ids.append([_st.st_dev, _st.st_ino])
    with open(REPORT, "w") as f:
        json.dump({"fds": _fds, "ids": _ids, "pgrp": os.getpgrp(), "pid": os.getpid(),
                   "env": dict(os.environ), "argv": sys.argv[1:],
                   "stdout_null": os.fstat(1).st_rdev == os.stat("/dev/null").st_rdev,
                   "stderr_null": os.fstat(2).st_rdev == os.stat("/dev/null").st_rdev}, f)
PROFILE = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--user-data-dir=")), "")
PAGES = 100 if MODE == "too-many-pages" else 2
_BODY = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
PDF = (_BODY + b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\n"
       + b"startxref\n" + str(len(_BODY)).encode() + b"\n%%EOF\n")
if MODE == "bad-pdf":
    PDF = b"%PDF-1.4\n" + b"x" * 100
os.set_blocking(3, True)
inbuf = b""
printed_full = False
stream_left = {}


def send(obj):
    data = json.dumps(obj).encode() + b"\0"
    view = memoryview(data)
    while view:
        n = os.write(4, view)
        view = view[n:]


def event(method, params=None, sid=None):
    m = {"method": method, "params": params or {}}
    if sid:
        m["sessionId"] = sid
    send(m)


def reply(msg, result=None, error=None):
    out = {"id": msg["id"]}
    if msg.get("sessionId"):
        out["sessionId"] = msg["sessionId"]
    if error:
        out["error"] = {"code": -32000, "message": error}
    else:
        out["result"] = result or {}
    send(out)


if MODE == "ignore-close":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if MODE == "leftover":
    # a descendant that leaves the process group but still references the render folder
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)", f"--user-data-dir={PROFILE}"],
                     start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)


def handle(msg):
    global printed_full
    m, p, sid = msg.get("method"), msg.get("params") or {}, msg.get("sessionId")
    if MODE == "frozen" and m == "Page.setDocumentContent":
        while True:
            time.sleep(60)
    if MODE == "crash" and m == "Page.enable":
        os._exit(1)
    if m == "Browser.getVersion":
        return reply(msg, {"product": "Chrome/1.2.3.4" if MODE == "version-mismatch" else "Chrome/154.0.8037.93",
                           "protocolVersion": "1.3"})
    if m == "Target.setDiscoverTargets":
        reply(msg)
        return event("Target.targetCreated", {"targetInfo": {"targetId": "INIT", "type": "page", "url": "about:blank"}})
    if m == "Target.getTargets":
        return reply(msg, {"targetInfos": [{"targetId": "INIT", "type": "page", "url": "about:blank"}]})
    if m == "Target.createTarget":
        return reply(msg, {"targetId": "T1"})
    if m == "Target.attachToTarget":
        return reply(msg, {"sessionId": "S1"})
    if m == "Fetch.enable" and MODE == "noack-fetch":
        return reply(msg, error="Fetch.enable is not supported")
    if m == "Page.getFrameTree":
        return reply(msg, {"frameTree": {"frame": {"id": "F1", "url": "about:blank"}}})
    if m == "Page.setDocumentContent":
        if MODE == "huge-frame":
            os.write(4, b"{" + b"x" * (17 * 1024 * 1024))
            return
        if MODE == "memory-hog":
            hog = []
            for _ in range(16):
                b = bytearray(32 * 1024 * 1024)
                for i in range(0, len(b), 4096):
                    b[i] = 1
                hog.append(b)
                time.sleep(0.05)
            globals()["_HOG"] = hog
        if MODE == "scratch-hog":
            tmp = os.environ.get("TMPDIR", "/nonexistent")
            for i in range(40):
                with open(os.path.join(tmp, f"fill-{i}"), "wb") as f:
                    f.write(os.urandom(1024 * 1024))
                time.sleep(0.02)
        reply(msg)
        event("Page.documentOpened", {"frame": {"id": "F1", "url": "about:blank"}}, sid)
        event("Page.domContentEventFired", {}, sid)
        event("Page.loadEventFired", {}, sid)
        if MODE == "navigate":
            event("Page.frameNavigated", {"frame": {"id": "F1", "url": "file:///etc/hosts"}}, sid)
        if MODE == "download":
            event("Browser.downloadWillBegin", {"url": "data:,x"})
        if MODE == "failrequest-error":
            event("Fetch.requestPaused", {"requestId": "R1", "request": {"url": "http://127.0.0.1:1/x"}}, sid)
        if MODE == "event-flood":
            for _ in range(25000):
                event("Page.lifecycleEvent", {"frameId": "F1", "name": "noise"}, sid)
        return
    if m == "Fetch.failRequest":
        return reply(msg, error="Invalid InterceptionId." if MODE == "failrequest-error" else None)
    if m == "Page.createIsolatedWorld":
        return reply(msg, {"executionContextId": 7})
    if m == "Emulation.setDeviceMetricsOverride":
        globals()["_WIDTH"] = int(p.get("width") or 0)
        return reply(msg)
    if m == "Runtime.evaluate":
        if "scrollWidth" in (p.get("expression") or ""):
            w = globals().get("_WIDTH", 739)
            if MODE == "wide":           # content 1600 px wide; fits once laid out that wide
                val = max(1600, w)
            elif MODE == "too-wide":     # content always 50 px wider than the page
                val = w + 50
            elif MODE == "ultra-wide":   # needs a scale below Chrome's 0.1 floor
                val = 100000
            else:
                val = min(w, 700)
            return reply(msg, {"result": {"type": "number", "value": val}})
        return reply(msg, {"result": {"type": "string", "value": "loading|1|loading" if MODE == "not-ready" else "complete|0|loaded"}})
    if m == "Page.printToPDF":
        globals().setdefault("_SCALES", []).append(p.get("scale"))
        if REPORT and p.get("scale") is not None:
            with open(REPORT + ".scales", "a") as f:
                f.write(f"{p.get('scale')}\n")
        if "pageRanges" in p:
            n = int(p["pageRanges"])
            limit = PAGES + (100 if (MODE == "grow-after-print" and printed_full) else 0)
            if n > limit:
                return reply(msg, error="Page range exceeds page count")
            return reply(msg, {"data": "", "stream": f"S-{n}"})
        if MODE == "stall-print":
            return
        printed_full = True
        stream_left["PDF"] = 0
        return reply(msg, {"data": "", "stream": "PDF"})
    if m == "IO.read":
        h = p.get("handle")
        if MODE == "huge-stream":
            return reply(msg, {"base64Encoded": True, "data": base64.b64encode(b"%PDF-" + b"z" * (1024 * 1024 - 5)).decode(), "eof": False})
        off = stream_left.get(h, 0)
        size = min(int(p.get("size") or 1 << 16), 64)
        chunk = PDF[off:off + size]
        stream_left[h] = off + len(chunk)
        return reply(msg, {"base64Encoded": True, "data": base64.b64encode(chunk).decode(),
                           "eof": stream_left[h] >= len(PDF)})
    if m == "Browser.close":
        if MODE == "ignore-close":
            return reply(msg)
        reply(msg)
        os._exit(0)
    return reply(msg)


while True:
    if MODE == "slow-reader":
        time.sleep(0.002)
        chunk = os.read(3, 4096)
    else:
        chunk = os.read(3, 1 << 20)
    if not chunk:
        sys.exit(0)
    inbuf += chunk
    while b"\0" in inbuf:
        raw, inbuf = inbuf.split(b"\0", 1)
        handle(json.loads(raw))
