#!/usr/bin/env python3
"""Renderer release gates (PLAN-v4 section 14) against the REAL Chrome on this host.

Synthetic fixtures only; the only network target is a local 127.0.0.1 listener this tool
starts; local-file canaries live in this run's own output folder. Every negative result is
paired with a positive control showing the fixture does leak/execute when the layer under
test is removed. PDFs are inspected independently of Chrome with macOS PDFKit (osascript).

    GMAIL_MCP_RUNTIME_DIR=<runtime root> python tools/render_gates.py --out <evidence dir> [--write-record]

--write-record writes the gate record for this exact Chrome binary + render recipe ONLY
if every gate passed; readiness() requires it (plus measured budgets) before PDF output is
enabled. Re-run whenever Chrome changes.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import pathlib
import platform
import signal
import struct
import subprocess
import sys
import threading
import time
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import config  # noqa: E402
import htmlview  # noqa: E402
import locks  # noqa: E402
import renderer  # noqa: E402
import runtime  # noqa: E402

PDFINFO_JS = r"""
ObjC.import('PDFKit');
function run(argv) {
  const doc = $.PDFDocument.alloc.initWithURL($.NSURL.fileURLWithPath(argv[0]));
  if (!doc || doc.isNil()) return JSON.stringify({ok: false});
  const pages = [];
  for (let i = 0; i < doc.pageCount; i++) pages.push(ObjC.unwrap(doc.pageAtIndex(i).string) || "");
  const attrs = doc.documentAttributes;
  const title = attrs.isNil() ? null : ObjC.unwrap(attrs.objectForKey('Title'));
  return JSON.stringify({ok: true, pages: Number(doc.pageCount), text: pages, title: title});
}
"""


# --- helpers ------------------------------------------------------------------------------------
def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Listener:
    """127.0.0.1 HTTP listener that counts connections (the only network target)."""

    def __init__(self):
        self.hits: list[str] = []
        self.paths: list[str] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def handle(self):
                outer.hits.append("conn")
                try:
                    super().handle()
                except Exception:
                    pass

            def do_GET(self):
                outer.paths.append(self.path[:80])
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"LISTENER_BODY")

            def log_message(self, *a):
                pass

            def log_error(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        # "localhost" resolves to ::1 first on macOS: listen on the IPv6 loopback too (same
        # port, loopback only) so the positive control does not depend on fallback timing.
        self.v6 = None
        try:
            import socket

            class V6(http.server.ThreadingHTTPServer):
                address_family = socket.AF_INET6

            self.v6 = V6(("::1", self.port), H)
            threading.Thread(target=self.v6.serve_forever, daemon=True).start()
        except OSError:
            self.v6 = None

    def count(self) -> int:
        time.sleep(0.5)
        return len(self.hits)

    def reset(self):
        self.hits.clear()
        self.paths.clear()


def png(width: int, height: int, rgb=(200, 30, 30)) -> bytes:
    """A valid solid-color PNG built with zlib (streamed: memory stays small even for
    huge dimensions; the compressed size is tiny, the DECODED size is width*height*4)."""
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    row = b"\x00" + bytes(rgb) * width
    comp = zlib.compressobj(9)
    parts = []
    for _ in range(height):
        out = comp.compress(row)
        if out:
            parts.append(out)
    parts.append(comp.flush())
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", b"".join(parts)) + chunk(b"IEND", b"")


def email_bytes(html: str, subject="Gate fixture", related: list | None = None) -> bytes:
    """A synthetic message: text/plain + text/html alternative, optional related images."""
    from email.message import EmailMessage
    import email.policy

    m = EmailMessage(policy=email.policy.default)
    m["From"] = "Gate Sender <sender@example.test>"
    m["To"] = "gate@example.test"
    m["Subject"] = subject
    m["Date"] = "Mon, 5 Oct 2026 10:00:00 +0000"
    m.set_content("plain alternative")
    m.add_alternative(html, subtype="html")
    if related:
        hp = m.get_payload()[1]
        for data, subtype, cid in related:
            hp.add_related(data, maintype="image", subtype=subtype, cid=f"<{cid}>", disposition="inline",
                           filename=f"{cid.split('@')[0]}.{subtype}")
    return m.as_bytes()


def split_email_bytes(image: bytes) -> bytes:
    """Apple Mail's split shape (owner decision 2): alternative[text, mixed[html section 1,
    inline PDF, related[html section 2 -> cid:, the image]]]."""
    b64 = lambda d: base64.encodebytes(d).decode()  # noqa: E731
    return ("From: Gate Sender <sender@example.test>\r\nTo: gate@example.test\r\nSubject: Gate split\r\n"
            "Date: Mon, 5 Oct 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n"
            'Content-Type: multipart/alternative; boundary="A"\r\n\r\n'
            "--A\r\nContent-Type: text/plain\r\n\r\nplain alternative\r\n"
            '--A\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n'
            "--B\r\nContent-Type: text/html\r\n\r\n<p style='font:30px Helvetica'>SPLIT_SECTION_ONE</p>\r\n"
            "--B\r\nContent-Type: application/pdf; name=Invoice.pdf\r\nContent-Disposition: inline; filename=Invoice.pdf\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n" + b64(b"%PDF-1.4\n%%EOF\n") +
            '--B\r\nContent-Type: multipart/related; type="text/html"; boundary="C"\r\n\r\n'
            "--C\r\nContent-Type: text/html\r\n\r\n<p style='font:30px Helvetica'>SPLIT_SECTION_TWO</p>"
            "<img src='cid:sig@gate' width='64' height='64'>\r\n"
            "--C\r\nContent-Type: image/png\r\nContent-ID: <sig@gate>\r\nContent-Disposition: inline; filename=sig.png\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n" + b64(image) + "--C--\r\n--B--\r\n--A--\r\n").encode()


def classify_chrome_processes(procs: dict, t_start: float, browser_pid: int, render_pgid: int, render_dir: str,
                              gate_pid: int, gate_pgid: int) -> dict:
    """Every Chrome-family process started during a render, from a process table
    {pid: (ppid, pgid, start time, command)}.

    A process counts as a helper of a browser that was already running (your own Chrome),
    and is left out, only when ALL hold: its parent is not launchd and not this gate; its
    group is neither the render's nor this gate's; its parent and its process-group leader
    both started before the gate. A process the render starts cannot meet that while the
    renderer starts Chrome in its own new process group, so `browser_own_group` checks that
    premise directly: the render's browser must lead its own group, separate from this
    gate's. If the renderer ever stopped doing that, the browser would join the gate's group
    and the gate fails here instead of exempting it."""
    def before_gate(pid):
        return pid in procs and procs[pid][2] + 1 < t_start

    rows, excluded = [], 0
    for pid, (ppid, pgid, started, cmd) in procs.items():
        if "Google Chrome" not in cmd and "crashpad" not in cmd:
            continue
        if started + 1 < t_start:
            continue                      # your own Chrome, started earlier
        if (ppid not in (1, gate_pid) and pgid not in (render_pgid, gate_pgid)
                and before_gate(ppid) and before_gate(pgid)):
            excluded += 1                 # a new helper of a browser that was already running
            continue
        db = cmd.split("--database=")[1].split(" --")[0] if "--database=" in cmd else None
        rows.append({"pgid_matches": pgid == render_pgid, "references_render_dir": render_dir in cmd,
                     "crashpad": "crashpad" in cmd,
                     "database_in_render_dir": (db or "").startswith(render_dir) if db else None})
    browser = procs.get(browser_pid)
    own = (browser is not None and browser[1] == browser_pid == render_pgid
           and browser_pid != gate_pgid and browser[1] != gate_pgid)
    return {"rows": rows, "excluded": excluded, "browser_own_group": own}


def outside_rows(c: dict) -> list:
    return [r for r in c["rows"] if not (r["pgid_matches"] or r["references_render_dir"])]


def bad_db_rows(c: dict) -> list:
    return [r for r in c["rows"] if r["crashpad"] and not r["database_in_render_dir"]]


def containment_ok(c: dict) -> bool:
    return bool(c["browser_own_group"] and c["rows"] and not outside_rows(c) and not bad_db_rows(c)
                and any(r["crashpad"] for r in c["rows"]))


class Gates:
    def __init__(self, out: pathlib.Path, chrome: str):
        self.out = out
        self.chrome = chrome
        self.results: dict = {}
        self.renders: list = []
        self.listener = Listener()
        self.version = renderer.chrome_version(chrome)
        self.pdf_js = out / "pdfinfo.js"
        self.pdf_js.write_text(PDFINFO_JS)
        self.canary_dir = out / "canaries"
        self.canary_dir.mkdir(exist_ok=True)
        self._make_canaries()

    # -- infrastructure --------------------------------------------------------------------
    def settings(self, max_pages=50, timeout=45.0, mem=None, scratch=None, interval=100):
        s = config.PdfSettings(max_pages=max_pages, render_timeout_seconds=timeout)
        s.memory_budget_mb, s.scratch_budget_mb, s.monitor_interval_ms = mem, scratch, interval
        return s

    def inspect_pdf(self, pdf: bytes, name: str) -> dict:
        path = self.out / f"{name}.pdf"
        path.write_bytes(pdf)
        try:
            out = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(self.pdf_js), str(path)],
                                 capture_output=True, text=True, timeout=60).stdout.strip()
            info = json.loads(out)
        except Exception as e:  # noqa: BLE001
            info = {"ok": False, "error": type(e).__name__}
        info["file"] = path.name
        info["bytes"] = len(pdf)
        info["sha256"] = sha(pdf)
        return info

    def run(self, name: str, page: bytes, *, st=None, ablate=None, inspect=None, expect_ok=True, cancel=None,
            extra_args=()) -> dict:
        st = st or self.settings()
        sink_box = {}

        class Sink:
            def __call__(self, chunks):
                data = b"".join(chunks)
                sink_box["pdf"] = data
                return data

            def verify_xref(self, data, off):
                return data[off:off + 4] == b"xref" or bool(__import__("re").match(rb"\d+\s+\d+\s+obj", data[off:off + 32]))

            def discard(self, data):
                sink_box["discarded"] = True

        rec = {"name": name, "fixture_sha256": sha(page), "fixture_bytes": len(page),
               "ablations": vars(ablate) if ablate else None,
               "settings": {"max_pages": st.max_pages, "timeout": st.render_timeout_seconds,
                            "memory_budget_mb": st.memory_budget_mb, "scratch_budget_mb": st.scratch_budget_mb,
                            "interval_ms": st.monitor_interval_ms},
               "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        t0 = time.monotonic()
        with locks.render_lock(120):
            try:
                rep = renderer.render(page, st, self.chrome, Sink(), chrome_version_expected=self.version,
                                      ablate=ablate, record_events=True, inspect=inspect, cancel=cancel,
                                      extra_args=extra_args)
                rec["outcome"] = "ok"
            except renderer.RenderFailure as rf:
                rep = getattr(rf, "report", None)
                rec["outcome"] = rf.code
                rec["detail"] = rf.detail
        rec["seconds"] = round(time.monotonic() - t0, 3)
        if rep is not None:
            m = rep.metrics
            rec.update({"scale": rep.scale, "acks": rep.acks, "violations": rep.violations, "blocked_requests": rep.blocked_requests,
                        "events": rep.events[:200], "inspect": rep.inspect, "chrome_product": rep.chrome_product,
                        "pages_ok": rep.pages_ok, "tail_ok": rep.tail_ok, "cleaned": rep.cleaned,
                        "metrics": vars(m) if m else None})
        if "pdf" in sink_box:
            rec["pdf"] = self.inspect_pdf(sink_box["pdf"], name)
        rec["discarded"] = sink_box.get("discarded", False)
        self.renders.append(rec)
        return rec

    @staticmethod
    def text(rec) -> str:
        return "\n".join((rec.get("pdf") or {}).get("text") or [])

    def sentinels(self, ids):
        js = ("JSON.stringify(Object.fromEntries(%s.map(i => [i, (document.getElementById(i)||{}).textContent || null])))"
              % json.dumps(ids))

        def inspect(s, ps, ctx):
            r = s.call("Runtime.evaluate", {"expression": js, "returnByValue": True}, session=ps)
            try:
                return {"sentinels": json.loads(r["result"]["value"])}
            except Exception:  # noqa: BLE001
                return {"sentinels": None}
        return inspect

    def view(self, html: str, related=None) -> bytes:
        return htmlview.build_view(email_bytes(html, related=related)).page

    # -- fixtures ------------------------------------------------------------------------------
    def _make_canaries(self):
        d = self.canary_dir
        (d / "canary.html").write_text("<html><body style='font:40px Helvetica'>LOCAL_CANARY_HTML</body></html>")
        (d / "canary.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" width="900" height="80">'
                                      '<text x="5" y="60" font-size="50">LOCAL_CANARY_SVG</text></svg>')
        (d / "canary.css").write_text("body::after{content:'LOCAL_CANARY_CSS';font:40px Helvetica}")
        (d / "host.html").write_text(
            "<html><head><link rel='stylesheet' href='canary.css'></head><body style='font:30px Helvetica'>HOST"
            "<iframe src='canary.html' width='900' height='120'></iframe>"
            "<object data='canary.svg' width='900' height='90'></object>"
            "<img src='canary.svg' width='900' height='90'></body></html>")
        self.canary_uri = (d / "canary.html").as_uri()
        self.canary_svg = (d / "canary.svg").as_uri()
        self.canary_css = (d / "canary.css").as_uri()

    # -- gate: scripts ----------------------------------------------------------------------------
    def gate_scripts(self):
        fixture = ("<!doctype html><html><head><meta charset='utf-8'><style>body{font:26px Helvetica}</style></head><body>"
                   "<div id='s1'>S1_NOT_EXECUTED</div>"
                   "<script>document.getElementById('s1').textContent='S1_EXECUTED'</script>"
                   "<div id='s2'>S2_NOT_EXECUTED</div>"
                   "<img src='data:image/gif;base64,AAAA' onerror=\"document.getElementById('s2').textContent='S2_EXECUTED'\">"
                   "<div id='s3'>S3_NOT_EXECUTED</div>"
                   "<iframe src=\"javascript:parent.document.getElementById('s3').textContent='S3_EXECUTED';''\"></iframe>"
                   "</body></html>")
        ids = ["s1", "s2", "s3"]
        ctrl = self.run("scripts-control", fixture.encode(), ablate=renderer.Ablations(scripts_enabled=True, observe_only=True),
                        inspect=self.sentinels(ids))
        prot = self.run("scripts-engine-off", fixture.encode(), ablate=renderer.Ablations(observe_only=True),
                        inspect=self.sentinels(ids))
        full = self.run("scripts-full-pipeline", self.view(fixture), inspect=self.sentinels(ids))
        ran = lambda r: sorted(k for k, v in ((r.get("inspect") or {}).get("sentinels") or {}).items() if v and v.endswith("_EXECUTED") and "NOT" not in v)
        ok = (ran(ctrl) == ids and all(f"S{i}_EXECUTED" in self.text(ctrl) for i in (1, 2, 3))
              and ran(prot) == [] and all(f"S{i}_NOT_EXECUTED" in self.text(prot) for i in (1, 2, 3))
              and full["outcome"] == "ok" and ran(full) == [] and "S1_NOT_EXECUTED" in self.text(full))
        self.results["scripts"] = {"pass": ok, "control_executed": ran(ctrl), "engine_off_executed": ran(prot),
                                   "full_pipeline": full["outcome"], "full_executed": ran(full)}

    # -- gate: network -------------------------------------------------------------------------
    def gate_network(self):
        P = self.listener.port
        paths = ["img-ip", "img-host", "css-import", "css-bg", "font", "link-css", "poster", "object", "iframe",
                 "img-ip-local", "css-bg-local"]
        body = (f"<img src='http://127.0.0.1:{P}/img-ip'><img src='http://localhost:{P}/img-host'>"
                f"<img src='https://127.0.0.1:{P}/img-tls'><style>@import url(http://127.0.0.1:{P}/css-import);</style>"
                f"<div style='background:url(http://127.0.0.1:{P}/css-bg);width:20px;height:20px'></div>"
                f"<style>@font-face{{font-family:gx;src:url(http://localhost:{P}/font)}}</style><span style='font-family:gx'>F</span>"
                f"<link rel='stylesheet' href='http://localhost:{P}/link-css'>"
                f"<video poster='http://127.0.0.1:{P}/poster'></video><object data='http://localhost:{P}/object'></object>"
                f"<iframe src='http://127.0.0.1:{P}/iframe'></iframe><img src='http://localhost:{P}/img-ip-local'>"
                f"<div style='background:url(http://localhost:{P}/css-bg-local);width:20px;height:20px'></div>NETWORK FIXTURE")
        raw = f"<!doctype html><html><head><meta charset='utf-8'></head><body>{body}</body></html>"
        csp = (f"<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' "
               f"content=\"{htmlview.CSP}\"></head><body>{body}</body></html>")
        A = renderer.Ablations
        runs = {}
        for name, page, abl in (
            ("network-control", raw, A(no_proxy=True, no_intercept=True, observe_only=True)),
            ("network-intercept-only", raw, A(no_proxy=True, observe_only=True)),
            ("network-proxy-only", raw, A(no_intercept=True, resolver="listener-only", observe_only=True)),
            ("network-resolver-only", raw, A(no_proxy=True, no_intercept=True, resolver="production", observe_only=True)),
            ("network-csp-only", csp, A(no_proxy=True, no_intercept=True, observe_only=True)),
            ("network-full-pipeline", None, None),
        ):
            self.listener.reset()
            p = self.view(body) if page is None else page.encode()
            rec = self.run(name, p, ablate=abl)
            rec["listener_connections"] = self.listener.count()
            rec["listener_requests"] = sorted({x.strip("/") for x in self.listener.paths})
            runs[name] = rec
        c = {k: v["listener_connections"] for k, v in runs.items()}
        req = {k: v["listener_requests"] for k, v in runs.items()}
        control_complete = set(paths) <= set(req["network-control"])
        # Claims, each on a control that reached EVERY path: interception and CSP each stop every
        # REQUEST (a bare speculative TCP preconnect can still reach the host and is recorded);
        # the dead proxy and the full pipeline stop every CONNECTION. The resolver rule alone
        # is evidence only (it covers host names, not IP literals).
        ok = (control_complete
              and req["network-intercept-only"] == [] and req["network-csp-only"] == []
              and c["network-proxy-only"] == 0 and c["network-full-pipeline"] == 0
              and len(runs["network-intercept-only"]["blocked_requests"]) >= len(paths)
              and runs["network-full-pipeline"]["outcome"] == "ok")
        self.results["network"] = {
            "pass": ok, "control_reached_every_path": control_complete, "expected_paths": paths,
            "listener_connections": c, "listener_requests": req,
            "bare_connections_without_request": {k: max(0, c[k] - len(req[k])) for k in c if k != "network-control"},
            "intercepted_in_intercept_only": len(runs["network-intercept-only"]["blocked_requests"]),
            "resolver_only_evidence": {"reached": req["network-resolver-only"],
                                       "note": "host-resolver MAP rule alone; claimed for host names only"},
            "full_pipeline": runs["network-full-pipeline"]["outcome"]}

    # -- gate: local files ----------------------------------------------------------------------
    def gate_local_files(self):
        canaries = ("LOCAL_CANARY_HTML", "LOCAL_CANARY_SVG", "LOCAL_CANARY_CSS")
        ctrl = self.run("local-file-origin-control", b"", ablate=renderer.Ablations(
            no_proxy=True, no_intercept=True, observe_only=True, navigate_url=(self.canary_dir / "host.html").as_uri()))
        working = [c for c in canaries if c in self.text(ctrl)]
        u, s, css = self.canary_uri, self.canary_svg, self.canary_css
        path_only = u[len("file://"):]
        variants = {
            "plain": f"<iframe src='{u}' width=900 height=120></iframe><object data='{s}'></object><img src='{s}'>"
                     f"<link rel=stylesheet href='{css}'><div style=\"background:url('{s}');height:90px\"></div>",
            "declarative-navigation": f"<meta http-equiv='refresh' content='0;url={u}'>BEFORE",
            "malformed": f"<img src={s} <iframe src={u} width=900 height=120 <ifr<b></b>ame src='{u}'></iframe>",
            "svg-mathml": f"<svg width=900 height=200><image href='{s}' width=900 height=90/><foreignObject width=900 height=100>"
                          f"<iframe src='{u}'></iframe></foreignObject></svg><math><mtext><iframe src='{u}'></iframe></mtext></math>",
            "protocol-encoding": f"<iframe src='FILE://{path_only}'></iframe><iframe src='file:{path_only}'></iframe>"
                                 f"<iframe src='file://localhost{path_only}'></iframe><iframe src='fi&#x6c;e://{path_only}'></iframe>"
                                 f"<img src='file:%2F%2F{path_only}'><iframe src='file:\\\\\\\\{path_only}'></iframe>",
            "frames": None,   # a real frameset document, built below
            "new-target": f"<a href='{u}' target='_blank'>link</a><form action='{u}' target='_blank'><input type=submit></form>",
        }
        runs = {}
        for name, body in variants.items():
            if body is None:
                page = f"<html><head></head><frameset rows='50%,50%'><frame src='{u}'><frame src='{s}'></frameset></html>"
                body = f"<frameset><frame src='{u}'></frameset>"
            else:
                page = f"<!doctype html><html><head><meta charset='utf-8'></head><body style='font:30px Helvetica'>{body} VARIANT</body></html>"
            prot = self.run(f"local-{name}", page.encode(), ablate=renderer.Ablations(observe_only=True))
            full = self.run(f"local-{name}-full-pipeline", self.view(body + " VARIANT"))
            runs[name] = {"engine_controls": {"outcome": prot["outcome"], "violations": sorted(set(prot.get("violations") or [])),
                                              "leaked": [c for c in canaries if c in self.text(prot)]},
                          "full_pipeline": {"outcome": full["outcome"], "leaked": [c for c in canaries if c in self.text(full)]}}
        # new targets: a scripted window.open is detected (positive control), and nothing opens with scripts off
        opener = f"<!doctype html><body>OPENER<script>window.open('{u}')</script></body>"

        def open_with_gesture(s, ps, ctx):   # positive control for the detector itself
            s.call("Runtime.evaluate", {"expression": "window.open('about:blank#popup'); 1", "userGesture": True},
                   session=ps)
            s.pump(time.monotonic() + 1.0)
            return {"opened": True}

        nt_ctrl = self.run("local-new-target-control", opener.encode(),
                           ablate=renderer.Ablations(scripts_enabled=True, observe_only=True), inspect=open_with_gesture)
        nt_prot = self.run("local-new-target-engine-off", opener.encode(), ablate=renderer.Ablations(observe_only=True))
        ok = (len(working) >= 1
              and all(not v["engine_controls"]["leaked"] and not v["full_pipeline"]["leaked"] for v in runs.values())
              and all(v["full_pipeline"]["outcome"] in ("ok", "isolation-violation") for v in runs.values())
              and any(x in (nt_ctrl.get("violations") or []) for x in ("unexpected-target", "window-open"))
              and not nt_prot.get("violations"))
        self.results["local_files"] = {"pass": ok, "positive_control_rendered": working, "variants": runs,
                                       "new_target_control_violations": sorted(set(nt_ctrl.get("violations") or [])),
                                       "new_target_engine_off_violations": sorted(set(nt_prot.get("violations") or []))}

    # -- gate: images, fonts, readiness, saved HTML ----------------------------------------------
    def gate_images_and_saved_html(self):
        logo = png(64, 64)
        font_path = pathlib.Path("/System/Library/Fonts/Supplemental/Courier New.ttf")
        font_css = ""
        if font_path.exists():
            font_css = ("<style>@font-face{font-family:gatefont;src:url(data:font/ttf;base64,"
                        + base64.b64encode(font_path.read_bytes()).decode() + ")}</style>")
        html = (font_css + "<p style='font-family:gatefont;font-size:30px'>FONT_FIXTURE_TEXT</p>"
                "<img src='cid:logo@gate' width='64' height='64'><img src='cid:missing@gate'>")
        v = htmlview.build_view(email_bytes(html, related=[(logo, "png", "logo@gate")]))
        ready_js = renderer.READY_JS

        def readiness_probe(s, ps, ctx):
            r = s.call("Runtime.evaluate", {"expression": ready_js, "contextId": ctx, "returnByValue": True}, session=ps)
            return {"ready_state": r["result"]["value"]}

        rec = self.run("images-cid-fonts", v.page, inspect=readiness_probe)
        pdf = (self.out / "images-cid-fonts.pdf").read_bytes() if rec.get("pdf") else b""
        has_image = b"/Subtype /Image" in pdf
        has_font = (b"CourierNew" in pdf) if font_css else None
        no_cid = htmlview.build_view(email_bytes("<p>NO_IMAGE</p><img src='cid:absent@gate'>"))
        rec2 = self.run("images-missing-cid", no_cid.page)
        pdf2 = (self.out / "images-missing-cid.pdf").read_bytes() if rec2.get("pdf") else b""
        # owner decision 2: a split body prints every section in order, the second one's cid image included
        split = htmlview.build_view(split_email_bytes(logo))
        rec4 = self.run("images-split-sections", split.page)
        pdf4 = (self.out / "images-split-sections.pdf").read_bytes() if rec4.get("pdf") else b""
        t4 = self.text(rec4)
        split_ok = (rec4["outcome"] == "ok" and "SPLIT_SECTION_ONE" in t4 and "SPLIT_SECTION_TWO" in t4
                    and t4.index("SPLIT_SECTION_ONE") < t4.index("SPLIT_SECTION_TWO")
                    and b"/Subtype /Image" in pdf4 and split.cid_used == 1 and not split.warnings
                    and [x["content_type"] for x in split.body_part["sections"]] == ["text/html", "text/html"])
        # saved HTML opened later WITHOUT the renderer's engine controls (scripts on, no interception, no proxy)
        P = self.listener.port
        hostile = (f"<div id='h1'>H1_NOT_EXECUTED</div><script>document.getElementById('h1').textContent='H1_EXECUTED'</script>"
                   f"<img src=x onerror=\"document.getElementById('h1').textContent='H1_EXECUTED'\">"
                   f"<img src='http://127.0.0.1:{P}/saved-img'><img src='http://localhost:{P}/saved-img-host'>"
                   f"<iframe src='{self.canary_uri}'></iframe>"
                   f"<div style='background:url(http://localhost:{P}/saved-bg);height:9px'></div>SAVED_HTML")
        raw_copy = self.out / "saved-control-unsanitized.html"
        raw_copy.write_text(f"<!doctype html><html><body>{hostile}</body></html>")
        saved = self.out / "saved-view.html"
        saved.write_bytes(htmlview.build_view(email_bytes(hostile)).page)
        abl = dict(scripts_enabled=True, no_intercept=True, no_proxy=True, observe_only=True)
        self.listener.reset()
        ctrl3 = self.run("saved-html-control-unsanitized", b"", ablate=renderer.Ablations(**abl, navigate_url=raw_copy.as_uri()),
                         inspect=self.sentinels(["h1"]))
        ctrl_conns = self.listener.count()
        ctrl_sent = ((ctrl3.get("inspect") or {}).get("sentinels") or {}).get("h1")
        self.listener.reset()
        rec3 = self.run("saved-html-without-engine-controls", b"", ablate=renderer.Ablations(**abl, navigate_url=saved.as_uri()),
                        inspect=self.sentinels(["h1"]))
        conns = self.listener.count()
        sent = ((rec3.get("inspect") or {}).get("sentinels") or {}).get("h1")
        ok = (rec["outcome"] == "ok" and (rec.get("inspect") or {}).get("ready_state") == "complete|0|loaded"
              and has_image and (has_font is not False) and "FONT_FIXTURE_TEXT" in self.text(rec)
              and v.cid_used == 1 and "missing-cid" in v.warnings
              and rec2["outcome"] == "ok" and b"/Subtype /Image" not in pdf2
              and ctrl_sent == "H1_EXECUTED" and ctrl_conns > 0
              and sent == "H1_NOT_EXECUTED" and conns == 0 and "LOCAL_CANARY_HTML" not in self.text(rec3)
              and "SAVED_HTML" in self.text(rec3) and split_ok)
        self.results["images_and_saved_html"] = {
            "pass": ok, "cid_converted": v.cid_used, "warnings": v.warnings, "pdf_has_image": has_image,
            "split_sections": {"pass": split_ok, "outcome": rec4["outcome"], "sections": split.body_part["sections"],
                               "cid_converted": split.cid_used, "warnings": split.warnings,
                               "pdf_has_image": b"/Subtype /Image" in pdf4,
                               "text_order": [w for w in ("SPLIT_SECTION_ONE", "SPLIT_SECTION_TWO") if w in t4]},
            "pdf_has_embedded_font": has_font, "ready_state": (rec.get("inspect") or {}).get("ready_state"),
            "missing_cid_pdf_has_image": b"/Subtype /Image" in pdf2,
            "saved_html": {"control_sentinel": ctrl_sent, "control_connections": ctrl_conns,
                           "sentinel": sent, "listener_connections": conns,
                           "canary_leaked": "LOCAL_CANARY_HTML" in self.text(rec3)}}

    # -- gate: page limit (D14) -------------------------------------------------------------------
    def gate_page_limit(self):
        def pages(n):
            divs = "".join(f"<div style='break-after:page;font:30px Helvetica'>PAGE_{i}_MARKER</div>" for i in range(1, n))
            return f"<!doctype html><body>{divs}<div style='font:30px Helvetica'>PAGE_{n}_MARKER</div></body>".encode()

        out = {}
        for n_cap in (3, 50):
            fit = self.run(f"pages-{n_cap}-of-{n_cap}", pages(n_cap), st=self.settings(max_pages=n_cap))
            over = self.run(f"pages-{n_cap + 1}-of-{n_cap}", pages(n_cap + 1), st=self.settings(max_pages=n_cap))
            info = fit.get("pdf") or {}
            out[str(n_cap)] = {
                "fits": {"outcome": fit["outcome"], "pdfkit_pages": info.get("pages"),
                         "last_marker_present": f"PAGE_{n_cap}_MARKER" in self.text(fit)},
                "over": {"outcome": over["outcome"], "pdf_published": "pdf" in over}}
        grow = self.run("pages-css-growth", b"<html><body><div style='height:100000000px'>SYNTHETIC MANY PAGES</div></body></html>",
                        st=self.settings(max_pages=50))
        ok = all(v["fits"]["outcome"] == "ok" and v["fits"]["pdfkit_pages"] == int(k) and v["fits"]["last_marker_present"]
                 and v["over"]["outcome"] == "too-many-pages" and not v["over"]["pdf_published"] for k, v in out.items())
        ok = ok and grow["outcome"] == "too-many-pages" and "pdf" not in grow
        self.results["page_limit"] = {"pass": ok, "cases": out, "css_growth": grow["outcome"],
                                      "overflow_error_text": renderer.OVERFLOW_ERROR}

    # -- gate: supervisor with real Chrome ---------------------------------------------------------
    def gate_supervisor(self):
        def freeze(s, ps, ctx):
            os.killpg(s.sup.proc.pgid, signal.SIGSTOP)   # stalled pipe + unresponsive Browser.close
            return {"frozen": True}

        frozen = self.run("supervisor-sigstop", b"<html><body>FREEZE</body></html>", st=self.settings(timeout=15.0),
                          inspect=freeze)
        ev = threading.Event()

        def cancel_mid_render(s, ps, ctx):     # after every control is acknowledged, before printing
            ev.set()
            return {"acks_before_cancel": list(s.r.acks)}

        slow = "".join(f"<div style='box-shadow:0 0 30px #000;filter:blur(1px)'>row {i}</div>" for i in range(20000))
        cancelled = self.run("supervisor-cancel", f"<html><body>{slow}</body></html>".encode(), cancel=ev,
                             inspect=cancel_mid_render)
        m1, m2 = frozen.get("metrics") or {}, cancelled.get("metrics") or {}
        ok = (frozen["outcome"] == "render-timeout" and frozen["seconds"] <= 15.5 and m1.get("group_gone") and frozen.get("cleaned")
              and cancelled["outcome"] == "cancelled" and m2.get("group_gone") and cancelled.get("cleaned")
              and "Fetch.enable" in ((cancelled.get("inspect") or {}).get("acks_before_cancel") or []))
        self.results["supervisor"] = {"pass": ok, "sigstop": {"outcome": frozen["outcome"], "seconds": frozen["seconds"],
                                                              "group_gone": m1.get("group_gone"), "kill_latency": m1.get("kill_latency")},
                                      "cancel": {"outcome": cancelled["outcome"], "seconds": cancelled["seconds"],
                                                 "group_gone": m2.get("group_gone"), "kill_latency": m2.get("kill_latency")}}

    # -- gate: spawn hygiene with real Chrome --------------------------------------------------------
    def gate_spawn(self):
        marker = self.out / "inheritable-marker.txt"
        fd = os.open(marker, os.O_CREAT | os.O_RDWR, 0o600)
        os.set_inheritable(fd, True)
        seen = {}

        def lsof(s, ps, ctx):
            pid = s.sup.proc.pid
            out = subprocess.run(["/usr/sbin/lsof", "-n", "-P", "-p", str(pid)], capture_output=True, text=True,
                                 timeout=30).stdout
            seen["marker_open_in_chrome"] = str(marker) in out
            std = {}
            for line in out.splitlines()[1:]:
                cols = line.split()
                if len(cols) > 4 and __import__("re").fullmatch(r"[0-4][rwu]?", cols[3]):
                    std[cols[3][0]] = cols[4] + " " + cols[-1]
            seen["std_fds"] = std
            ps_out = subprocess.run(["/bin/ps", "-axww", "-o", "pid=,pgid=,command="], capture_output=True, text=True).stdout
            argvs = [l for l in ps_out.splitlines() if s.sup.rdir in l]
            seen["processes_referencing_render_dir"] = len(argvs)
            seen["export_path_in_argv"] = any("gmail-exports" in l or "/exports" in l for l in argvs)
            return seen

        try:
            rec = self.run("spawn-hygiene", b"<html><body>SPAWN</body></html>", inspect=lsof)
        finally:
            os.close(fd)
        std = seen.get("std_fds", {})
        ok = (rec["outcome"] == "ok" and seen.get("marker_open_in_chrome") is False
              and all("/dev/null" in std.get(k, "") for k in ("0", "1", "2"))
              and all(std.get(k, "").startswith("PIPE") for k in ("3", "4"))
              and not seen.get("export_path_in_argv"))
        self.results["spawn"] = {"pass": ok, **seen}

    # -- gate: cleanup under the render lock with real Chrome ----------------------------------------------
    def gate_cleanup(self):
        state = {}

        def during(s, ps, ctx):
            state["active_dir"] = s.sup.rdir
            r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import renderer; renderer.startup_cleanup()"
                                % str(REPO)], env=dict(os.environ), timeout=60)
            state["second_server_rc"] = r.returncode
            state["active_dir_survived"] = os.path.isdir(s.sup.rdir)
            return state

        rec = self.run("cleanup-second-server", b"<html><body>CLEANUP GATE</body></html>", inspect=during)
        # an abandoned folder (owner gone) is removed later; one with a live owner is kept
        base = runtime.private_dir("render-tmp")
        dead = renderer.make_render_dir()
        with open(os.path.join(dead, "owner.json"), "w") as f:
            json.dump({"pid": 999999, "start": 1, "pgid": None}, f)
        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        live = renderer.make_render_dir()
        with open(os.path.join(live, "owner.json"), "w") as f:
            import procinfo
            json.dump({"pid": sleeper.pid, "start": procinfo.start_time(sleeper.pid), "pgid": None}, f)
        try:
            with locks.render_lock(30):
                stats = renderer.cleanup_abandoned()
            ok = (rec["outcome"] == "ok" and state.get("active_dir_survived") and state.get("second_server_rc") == 0
                  and not os.path.exists(dead) and os.path.isdir(live) and rec.get("cleaned"))
        finally:
            sleeper.kill()
            sleeper.wait()
            with locks.render_lock(30):
                renderer.cleanup_abandoned()
        self.results["cleanup"] = {"pass": bool(ok), "active_render_dir_survived_second_server": state.get("active_dir_survived"),
                                   "abandoned_removed": not os.path.exists(dead), "live_owner_kept": True, "stats": stats,
                                   "leftover_render_dirs": [n for n in os.listdir(base) if n.startswith("r-")]}

    # -- gate: wide content is scaled to fit, never clipped ------------------------------------------------
    def gate_wide_content(self):
        wide = ("<table style='width:1600px' border='1'><tr><td>LEFT_EDGE_MARKER</td><td style='width:1200px'>middle</td>"
                "<td>RIGHT_EDGE_MARKER</td></tr></table><pre>" + "x" * 300 + " END_OF_LONG_PRE_LINE</pre>")
        rec = self.run("wide-content", self.view(wide))
        txt = self.text(rec)
        grows = self.run("wide-content-grows", self.view("<div style='width:130%;background:#eee'>GROWS_WITH_PAGE</div>"))
        ok = (rec["outcome"] == "ok" and all(m in txt for m in ("LEFT_EDGE_MARKER", "RIGHT_EDGE_MARKER", "END_OF_LONG_PRE_LINE"))
              and (rec.get("scale") or 1) < 1 and grows["outcome"] == "too-wide" and "pdf" not in grows)
        self.results["wide_content"] = {"pass": ok, "outcome": rec["outcome"], "scale": rec.get("scale"),
                                        "markers": {m: m in txt for m in ("LEFT_EDGE_MARKER", "RIGHT_EDGE_MARKER",
                                                                          "END_OF_LONG_PRE_LINE")},
                                        "grows_with_page": grows["outcome"]}

    # -- gate: the production path (render_to_temp + temp-file sink) on real Chrome ---------------------------
    def gate_production_path(self):
        import exportfs
        d = self.out / "production-path"
        d.mkdir(exist_ok=True)
        os.chmod(d, 0o700)
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            st = self.settings(mem=4096, scratch=512, interval=100)
            ready = renderer.Readiness(True, "ready", chrome_path=self.chrome, chrome_version=self.version)
            page = self.view("<p>PRODUCTION_PATH_MARKER</p>")
            tf = renderer.render_to_temp(fd, page, st, ready)
            fdp = os.open(tf.name, os.O_RDONLY, dir_fd=fd)
            try:
                data = os.read(fdp, 50 * 1024 * 1024)
                quarantined = exportfs.has_quarantine(fdp)
                mode = os.fstat(fdp).st_mode & 0o777
            finally:
                os.close(fdp)
            info = self.inspect_pdf(data, "production-path")
            exportfs.remove_temp(fd, tf.name, tf.ino, tf.dev)
        finally:
            os.close(fd)
        ok = (info.get("ok") and "PRODUCTION_PATH_MARKER" in "\n".join(info.get("text") or [])
              and quarantined and mode == 0o600 and tf.head.startswith(b"%PDF-"))
        self.results["production_path"] = {"pass": bool(ok), "quarantined": quarantined, "mode": oct(mode),
                                           "pages": info.get("pages"), "bytes": tf.size, "scale": getattr(tf, "render_scale", None)}

    # -- gate: every Chrome-family process stays inside the render's containment ------------------------------
    def gate_process_containment(self):
        seen = {}
        t_start = time.time()

        def snapshot(s, ps, ctx):
            out = subprocess.run(["/bin/ps", "-axww", "-o", "pid=,ppid=,pgid=,lstart=,command="], capture_output=True,
                                 text=True).stdout
            procs = {}
            for line in out.splitlines():
                parts = line.split(None, 8)
                if len(parts) < 9:
                    continue
                try:
                    started = time.mktime(time.strptime(" ".join(parts[3:8]), "%a %b %d %H:%M:%S %Y"))
                except ValueError:
                    continue
                procs[int(parts[0])] = (int(parts[1]), int(parts[2]), started, parts[8])
            seen.update(classify_chrome_processes(procs, t_start, s.sup.proc.pid, s.sup.proc.pgid, s.sup.rdir,
                                                  os.getpid(), os.getpgrp()))
            return {"chrome_processes": len(seen["rows"])}

        rec = self.run("process-containment", b"<html><body>CONTAINMENT</body></html>", inspect=snapshot)
        c = seen or {"rows": [], "excluded": 0, "browser_own_group": False}
        ok = rec["outcome"] == "ok" and containment_ok(c)
        self.results["process_containment"] = {
            "pass": bool(ok), "chrome_processes": len(c["rows"]),
            "crash_handlers": sum(1 for r in c["rows"] if r["crashpad"]),
            "outside_containment": len(outside_rows(c)),
            "crash_database_outside_render_dir": len(bad_db_rows(c)),
            "browser_leads_own_process_group": c["browser_own_group"],
            "preexisting_browser_children_excluded": c["excluded"]}

    # -- resources: measurements and budget enforcement -------------------------------------------------
    def measure_resources(self, safety_mb: int):
        st = lambda **kw: self.settings(mem=safety_mb, scratch=4096, interval=kw.get("interval", 100), max_pages=50)
        cases = {}
        receipt = ("<table width='600' style='border-collapse:collapse;font:14px Helvetica'>"
                   + "".join(f"<tr><td style='border:1px solid #ccc;padding:4px'>Item {i}</td><td>${i}.00</td></tr>" for i in range(60))
                   + "</table><img src='cid:logo@m' width='120'>")
        fixtures = {
            "baseline-plain": htmlview.build_view(email_bytes("<p>Hello</p>")).page,
            "typical-receipt": htmlview.build_view(email_bytes(receipt, related=[(png(240, 80), "png", "logo@m")])).page,
            "css-heavy-20k": f"<html><body>{''.join(f'<div style=\"box-shadow:0 0 40px #000;filter:blur(2px);border-radius:9px\">r{i}</div>' for i in range(20000))}</body></html>".encode(),
            "css-deep-nesting-3k": ("<html><body>" + "<div style='padding-left:1px'>" * 3000 + "DEEP" + "</div>" * 3000 + "</body></html>").encode(),
            "text-5mb": ("<html><body><pre>" + ("lorem ipsum dolor sit amet " * 200000)[:5_000_000] + "</pre></body></html>").encode(),
            "image-decode-4000": ("<html><body><img style='width:7in' src='data:image/png;base64,"
                                  + base64.b64encode(png(4000, 4000)).decode() + "'></body></html>").encode(),
            "image-decode-8000": ("<html><body><img style='width:7in' src='data:image/png;base64,"
                                  + base64.b64encode(png(8000, 8000)).decode() + "'></body></html>").encode(),
            "image-decode-12000": ("<html><body><img style='width:7in' src='data:image/png;base64,"
                                   + base64.b64encode(png(12000, 12000)).decode() + "'></body></html>").encode(),
        }
        for name, page in fixtures.items():
            rec = self.run(f"measure-{name}", page, st=st())
            m = rec.get("metrics") or {}
            cases[name] = {"outcome": rec["outcome"], "seconds": rec["seconds"], "fixture_bytes": len(page),
                           "peak_footprint_mb": round(m.get("peak_footprint", 0) / 2**20, 1),
                           "peak_rss_mb": round(m.get("peak_rss", 0) / 2**20, 1),
                           "peak_scratch_mb": round(m.get("peak_scratch", 0) / 2**20, 2),
                           "max_processes": m.get("max_processes"), "samples": m.get("samples"),
                           "interval_ms": m.get("interval_ms")}
        # enforcement: a budget below the image-decode peak must trip, and we record overshoot and kill latency
        peak = max(cases["image-decode-12000"]["peak_footprint_mb"], cases["image-decode-8000"]["peak_footprint_mb"])
        enforce = {}
        for interval in (50, 250):
            budget = max(200, int(peak * 0.5))
            rec = self.run(f"enforce-memory-{interval}ms", fixtures["image-decode-12000"],
                           st=self.settings(mem=budget, scratch=4096, interval=interval))
            m = rec.get("metrics") or {}
            enforce[f"{interval}ms"] = {"budget_mb": budget, "outcome": rec["outcome"],
                                        "trip_at_s": m.get("trip_at"),
                                        "value_at_trip_mb": round((m.get("trip_value") or 0) / 2**20, 1),
                                        "post_trip_peak_mb": round((m.get("post_trip_peak") or 0) / 2**20, 1),
                                        "overshoot_mb": round(max(0, (m.get("post_trip_peak") or 0) - budget * 2**20) / 2**20, 1),
                                        "kill_latency_s": m.get("kill_latency"), "group_gone": m.get("group_gone")}
        scr = self.run("enforce-scratch", fixtures["typical-receipt"], st=self.settings(mem=safety_mb, scratch=1, interval=50))
        sm = scr.get("metrics") or {}
        enforce["scratch_1mb"] = {"outcome": scr["outcome"], "value_at_trip_mb": round((sm.get("trip_value") or 0) / 2**20, 2),
                                  "kill_latency_s": sm.get("kill_latency"), "group_gone": sm.get("group_gone")}
        ok = (all(v["outcome"] == "memory-budget-exceeded" and v["group_gone"] for k, v in enforce.items() if k.endswith("ms"))
              and enforce["scratch_1mb"]["outcome"] == "scratch-budget-exceeded" and enforce["scratch_1mb"]["group_gone"])
        self.results["resources"] = {"pass": ok, "safety_budget_mb_during_measurement": safety_mb,
                                     "measurements": cases, "enforcement": enforce,
                                     "host": {"machine": platform.machine(), "macos": platform.mac_ver()[0],
                                              "memory_gb": round(int(subprocess.run(["/usr/sbin/sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout) / 2**30, 1)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--chrome", default=None)
    ap.add_argument("--write-record", action="store_true")
    ap.add_argument("--only", default=None, help="comma-separated gate names (debugging)")
    ap.add_argument("--safety-mb", type=int, default=6144)
    args = ap.parse_args()
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    st = config.PdfSettings(chrome_path=args.chrome)
    chrome = renderer.find_chrome(st)
    if not chrome:
        print(json.dumps({"error": "chrome-not-found"}))
        return 2
    g = Gates(out, chrome)
    names = ["scripts", "network", "local_files", "images_and_saved_html", "page_limit", "wide_content", "supervisor",
             "spawn", "process_containment", "production_path", "cleanup", "resources"]
    if args.only:
        names = [n for n in names if n in args.only.split(",")]
    fn = {"scripts": g.gate_scripts, "network": g.gate_network, "local_files": g.gate_local_files,
          "images_and_saved_html": g.gate_images_and_saved_html, "page_limit": g.gate_page_limit,
          "supervisor": g.gate_supervisor, "spawn": g.gate_spawn, "cleanup": g.gate_cleanup,
          "wide_content": g.gate_wide_content, "production_path": g.gate_production_path,
          "process_containment": g.gate_process_containment,
          "resources": lambda: g.measure_resources(args.safety_mb)}
    user_tmp = subprocess.run(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True).stdout.strip()

    def chrome_tmp_entries():
        try:
            return {e for e in os.listdir(user_tmp) if "com.google.Chrome" in e}
        except OSError:
            return set()

    tmp_before = chrome_tmp_entries()
    t0 = time.time()
    for n in names:
        try:
            fn[n]()
        except Exception as e:  # noqa: BLE001
            g.results[n] = {"pass": False, "error": f"{type(e).__name__}: {e}"}
        print(json.dumps({n: g.results[n].get("pass")}), flush=True)
    created_outside = sorted(chrome_tmp_entries() - tmp_before)
    g.results["chrome_state_outside_render_dir"] = {"pass": not created_outside, "new_entries_in_user_temp": len(created_outside)}
    complete = len(names) == 12 and len(g.results) == 13
    all_pass = all(v.get("pass") for v in g.results.values()) and (complete or bool(args.only))
    script_sha = sha(pathlib.Path(__file__).read_bytes())
    summary = {"date": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seconds": round(time.time() - t0, 1),
               "chrome_path": chrome, "chrome_version": g.version, "render_recipe": renderer.RENDER_RECIPE,
               "view_recipe": htmlview.RECIPE_VERSION, "flags": list(renderer.FLAGS), "print_params": renderer.PRINT_PARAMS,
               "gate_script_sha256": script_sha, "renderer_sha256": sha((REPO / "renderer.py").read_bytes()),
               "htmlview_sha256": sha((REPO / "htmlview.py").read_bytes()),
               "all_pass": all_pass, "gates": {k: v.get("pass") for k, v in g.results.items()},
               "identity": renderer.chrome_identity(chrome, g.version)}
    (out / "gates.json").write_text(json.dumps({"summary": summary, "results": g.results}, indent=1, default=str))
    (out / "renders.json").write_text(json.dumps(g.renders, indent=1, default=str))
    if args.write_record and all_pass and complete:  # only a complete run may write the record
        summary["record"] = renderer.write_gate_record(summary["identity"], summary)
    print(json.dumps(summary, indent=1, default=str))
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
