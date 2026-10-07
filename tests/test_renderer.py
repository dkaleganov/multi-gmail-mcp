"""Renderer transport and supervisor gates against a scripted fake Chrome (deterministic
misbehaviour), readiness logic, PDF integration through export_email, and the
startup-cleanup gate (PLAN-v4 9.2 and section 14)."""
from tests import support  # noqa: F401

import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import config
import locks
import procinfo
import renderer
import runtime

FAKE = support.REPO / "tests" / "fake_chrome.py"


def wrapper(mode: str) -> str:
    d = support.RUN_DIR / "fake-chrome"
    d.mkdir(exist_ok=True)
    path = d / f"chrome-{mode}"
    if not path.exists():
        path.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" --mode={mode} "$@"\n')
        os.chmod(path, 0o700)
    return str(path)


def settings(**kw):
    s = config.PdfSettings(max_pages=3, render_timeout_seconds=10.0)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


class MemSink:
    def __init__(self, cap=8 * 1024 * 1024):
        self.cap, self.data, self.discarded, self.called = cap, None, False, False

    def __call__(self, chunks):
        self.called = True
        out = bytearray()
        for c in chunks:
            out += c
            if len(out) > self.cap:
                raise AssertionError("sink cap")
        self.data = bytes(out)
        return self.data

    def verify_xref(self, data, off):
        return data[off:off + 4] == b"xref"

    def discard(self, data):
        self.discarded = True


def render(mode, page=b"<html><body>x</body></html>", **kw):
    st = kw.pop("st", None) or settings()
    sink = kw.pop("sink", None) or MemSink()
    t0 = time.monotonic()
    with locks.render_lock(30):
        try:
            rep = renderer.render(page, st, wrapper(mode), sink, **kw)
            return "ok", rep, sink, time.monotonic() - t0
        except renderer.RenderFailure as rf:
            return rf.code, rf.report, sink, time.monotonic() - t0


def render_dirs():
    base = runtime.private_dir("render-tmp")
    return sorted(n for n in os.listdir(base) if n.startswith("r-"))


class TransportAndSupervisorTests(unittest.TestCase):
    def tearDown(self):
        support.assert_isolated(self)

    def assertCleaned(self, rep):
        self.assertTrue(rep.metrics.group_gone, rep.metrics)
        self.assertTrue(rep.cleaned)

    def test_normal_render_acknowledges_every_control(self):
        before = render_dirs()
        code, rep, sink, _ = render("normal")
        self.assertEqual(code, "ok")
        self.assertTrue(sink.data.startswith(b"%PDF-"))
        for m in ("Page.enable", "Emulation.setScriptExecutionDisabled", "Fetch.enable", "Target.setAutoAttach",
                  "Browser.setDownloadBehavior", "Page.setDocumentContent"):
            self.assertIn(m, rep.acks)
        self.assertCleaned(rep)
        self.assertEqual(render_dirs(), before)

    def test_missing_acknowledgement_fails_closed(self):
        code, rep, sink, _ = render("noack-fetch")
        self.assertEqual(code, "control-not-acknowledged")
        self.assertFalse(sink.called)
        self.assertCleaned(rep)

    def test_oversized_frame(self):
        code, rep, sink, _ = render("huge-frame")
        self.assertEqual(code, "frame-too-large")
        self.assertCleaned(rep)

    def test_oversized_stream_is_refused_at_first_violation(self):
        orig = renderer.MAX_PDF_BYTES
        renderer.MAX_PDF_BYTES = 3 * 1024 * 1024
        try:
            code, rep, sink, _ = render("huge-stream")
        finally:
            renderer.MAX_PDF_BYTES = orig
        self.assertEqual(code, "pdf-too-large")
        self.assertIsNone(sink.data)
        self.assertCleaned(rep)

    def test_partial_writes_to_a_slow_reader(self):
        page = b"<html><body>" + b"y" * (3 * 1024 * 1024) + b"</body></html>"
        code, rep, sink, _ = render("slow-reader", page=page, st=settings(render_timeout_seconds=40.0))
        self.assertEqual(code, "ok")
        self.assertCleaned(rep)

    def test_stalled_reply_hits_the_independent_deadline(self):
        code, rep, sink, elapsed = render("stall-print")
        self.assertEqual(code, "render-timeout")
        self.assertLessEqual(elapsed, 10.0 + 0.5)
        self.assertCleaned(rep)

    def test_frozen_chrome(self):
        code, rep, sink, elapsed = render("frozen")
        self.assertEqual(code, "render-timeout")
        self.assertLessEqual(elapsed, 10.5)
        self.assertCleaned(rep)

    def test_unresponsive_browser_close_and_ignored_sigterm(self):
        code, rep, sink, elapsed = render("ignore-close")
        self.assertEqual(code, "ok")
        self.assertLessEqual(elapsed, 10.5)
        self.assertCleaned(rep)

    def test_leftover_descendant_outside_the_group_is_killed(self):
        code, rep, sink, _ = render("leftover")
        self.assertEqual(code, "ok")
        self.assertGreaterEqual(rep.metrics.leftovers, 1)
        self.assertCleaned(rep)

    def test_cancellation(self):
        ev = threading.Event()
        threading.Timer(1.0, ev.set).start()
        code, rep, sink, elapsed = render("stall-print", cancel=ev)
        self.assertEqual(code, "cancelled")
        self.assertLess(elapsed, 5.0)
        self.assertCleaned(rep)

    def test_isolation_events_fail_the_render(self):
        for mode, detail in (("navigate", "navigation"), ("download", "download"),
                             ("failrequest-error", "fetch-fail-request-rejected")):
            code, rep, sink, _ = render(mode)
            self.assertEqual(code, "isolation-violation", mode)
            self.assertIn(detail, rep.violations, mode)
            self.assertFalse(sink.called, mode)
            self.assertCleaned(rep)

    def test_page_limit_before_and_after_print(self):
        code, rep, sink, _ = render("too-many-pages")
        self.assertEqual(code, "too-many-pages")
        self.assertFalse(sink.called)
        code, rep, sink, _ = render("grow-after-print")
        self.assertEqual(code, "too-many-pages")
        self.assertTrue(sink.discarded)

    def test_malformed_pdf_version_change_crash_not_ready_flood(self):
        for mode, want in (("bad-pdf", "malformed-pdf"), ("crash", "pipe-closed"),
                           ("not-ready", "render-not-ready"), ("event-flood", "event-flood")):
            code, rep, sink, _ = render(mode)
            self.assertEqual(code, want, mode)
            self.assertCleaned(rep)
        code, rep, sink, _ = render("version-mismatch", chrome_version_expected="Google Chrome 154.0.8037.93")
        self.assertEqual(code, "chrome-version-changed")

    def test_busy_host_labels_a_deadline_as_a_timeout_not_a_stall(self):
        # a busy host: the supervisor thread is starved just as the main thread passes the
        # work deadline (owner item 3: this surfaced as pipe-write-stalled under load)
        real_trip, real_pump, real_send = renderer.Supervisor.trip, renderer._Session.pump, renderer._Session._send

        def starved_trip(sup, reason, detail):
            if reason == "render-timeout":
                time.sleep(0.5)
            return real_trip(sup, reason, detail)

        def late_pump(sess, until):
            real_pump(sess, until)
            if until >= sess.sup.work_deadline - 0.25:
                time.sleep(max(0.0, sess.sup.work_deadline - time.monotonic()) + 0.01)

        def slow_send(sess, method, params, session, deadline):
            if method == "Emulation.setEmulatedMedia" and not getattr(sess, "_slowed", False):
                sess._slowed = True              # after readiness: the host stalled a healthy render
                time.sleep(max(0.0, sess.sup.work_deadline - time.monotonic()) + 0.01)
            return real_send(sess, method, params, session, deadline)

        real_recv = renderer.Transport.recv
        state = {}

        def marking_pump(sess, until):
            state["work_deadline"], state["in_pump"] = sess.sup.work_deadline, True
            try:
                real_pump(sess, until)
            finally:
                state["in_pump"] = False

        def starved_recv(transport, deadline):
            # the main thread does not run inside a readiness pause; the supervisor trips on
            # time, so the receive's own cancel check sees the timeout first
            if state.get("in_pump") and not state.get("done"):
                state["done"] = True
                time.sleep(max(0.0, state["work_deadline"] - time.monotonic()) + 0.2)
            return real_recv(transport, deadline)

        with mock.patch.object(renderer.Supervisor, "trip", starved_trip):
            with mock.patch.object(renderer._Session, "pump", late_pump):
                self.assertEqual(render("not-ready")[0], "render-not-ready")
            with mock.patch.object(renderer._Session, "_send", slow_send):
                self.assertEqual(render("normal")[0], "render-timeout")
        with mock.patch.object(renderer._Session, "pump", marking_pump), \
                mock.patch.object(renderer.Transport, "recv", starved_recv):
            self.assertEqual(render("not-ready")[0], "render-not-ready")

    def test_a_pipe_failure_after_the_readiness_timeout_is_not_ready(self):
        # the supervisor stops Chrome at the work deadline while readiness is still pending, and
        # the pipe reports that first: still a readiness timeout, never render-timeout
        real_pump = renderer._Session.pump

        def closing_pump(sess, until):
            if until >= sess.sup.work_deadline - 0.3:
                end = time.monotonic() + 10
                while sess.sup.reason != "render-timeout" and time.monotonic() < end:
                    time.sleep(0.01)
                raise renderer.RenderFailure("failed", code)
            return real_pump(sess, until)

        for code in ("pipe-closed", "pipe-write-stalled", "cdp-timeout"):
            with mock.patch.object(renderer._Session, "pump", closing_pump):
                self.assertEqual(render("not-ready", st=settings(render_timeout_seconds=7.0))[0],
                                 "render-not-ready", code)       # work deadline 2 s

    def test_a_full_pipe_is_a_stall_a_spent_deadline_is_not(self):
        r, w = os.pipe()
        try:
            os.set_blocking(w, False)
            while True:                          # fill the pipe: nobody reads it
                try:
                    os.write(w, b"x" * 65536)
                except BlockingIOError:
                    break
            t = renderer.Transport(w, r, threading.Event(), lambda: None)
            with self.assertRaises(renderer.RenderFailure) as cm:
                t.send({"id": 1}, time.monotonic() + 0.3)
            self.assertEqual(cm.exception.code, "pipe-write-stalled")
            with self.assertRaises(renderer.RenderFailure) as cm:
                t.send({"id": 2}, time.monotonic() - 1)
            self.assertEqual(cm.exception.code, "deadline-passed")
        finally:
            os.close(r)
            os.close(w)

    def test_wide_content_is_scaled_to_fit_never_clipped(self):
        report = support.scratch("scales") / "r.json"
        code, rep, sink, _ = render("wide", extra_args=(f"--report={report}",))
        self.assertEqual(code, "ok")
        expected = int(739 / 1600 * 10000) / 10000
        self.assertEqual(rep.scale, expected)
        scales = [float(x) for x in open(str(report) + ".scales").read().split()]
        self.assertTrue(scales and all(x == expected for x in scales))   # D14 probes and the print agree
        for mode in ("too-wide", "ultra-wide"):
            code, rep, sink, _ = render(mode)
            self.assertEqual(code, "too-wide", mode)
            self.assertFalse(sink.called, mode)

    def test_python_side_stall_still_kills_chrome_on_time(self):
        class StuckSink(MemSink):
            def __call__(self, chunks):
                next(chunks)
                time.sleep(12)        # e.g. a blocked disk write in the server process
                return super().__call__(chunks)

        t0 = time.monotonic()
        code, rep, sink, elapsed = render("normal", sink=StuckSink())
        self.assertEqual(code, "render-timeout")
        m = rep.metrics
        self.assertTrue(m.group_gone)
        self.assertLessEqual(m.trip_at, 5.0 + 0.3)        # work deadline = 10 s budget - 5 s grace
        self.assertLessEqual(m.trip_at + m.kill_latency, 10.0 + 0.5)

    def test_supervisor_fault_fails_closed(self):
        import procinfo as pi
        orig = pi.group_memory

        def boom(pgid):
            raise RuntimeError("sampling failed")

        pi.group_memory = boom
        try:
            code, rep, sink, elapsed = render("stall-print")
        finally:
            pi.group_memory = orig
        self.assertEqual(code, "supervisor-error")
        self.assertLess(elapsed, 5.0)
        self.assertCleaned(rep)

    def test_memory_budget_trips_and_records_overshoot(self):
        st = settings(memory_budget_mb=150, scratch_budget_mb=4096, monitor_interval_ms=50)
        code, rep, sink, _ = render("memory-hog", st=st)
        self.assertEqual(code, "memory-budget-exceeded")
        m = rep.metrics
        self.assertGreater(m.trip_value, 150 * 1024 * 1024)
        self.assertIsNotNone(m.kill_latency)
        self.assertCleaned(rep)

    def test_scratch_budget_trips(self):
        st = settings(memory_budget_mb=4096, scratch_budget_mb=16, monitor_interval_ms=50)
        code, rep, sink, _ = render("scratch-hog", st=st)
        self.assertEqual(code, "scratch-budget-exceeded")
        self.assertCleaned(rep)

    def test_spawn_inherits_only_the_pipe_and_null_stdio(self):
        marker = support.scratch("fdmark") / "leak.txt"
        fd = os.open(marker, os.O_CREAT | os.O_RDWR, 0o600)
        os.set_inheritable(fd, True)
        report = support.scratch("fdreport") / "report.json"
        try:
            code, rep, sink, _ = render("normal", extra_args=(f"--report={report}",))
        finally:
            os.close(fd)
        self.assertEqual(code, "ok")
        r = json.loads(report.read_text())
        self.assertEqual(r["fds"], [0, 1, 2, 3, 4])
        mst = os.stat(marker)
        self.assertNotIn([mst.st_dev, mst.st_ino], r["ids"])      # the inheritable marker did not leak
        self.assertTrue(r["stdout_null"] and r["stderr_null"])
        self.assertEqual(r["pgrp"], r["pid"])                        # its own process group
        # the test's /bin/sh wrapper adds SHLVL, PWD, and _ before exec; our spawn passes only four
        self.assertEqual(set(r["env"]) - {"__CF_USER_TEXT_ENCODING", "SHLVL", "PWD", "_"},
                         {"PATH", "HOME", "TMPDIR", "MAC_CHROMIUM_TMPDIR", "BREAKPAD_DUMP_LOCATION", "LANG"})
        for var in ("HOME", "TMPDIR", "MAC_CHROMIUM_TMPDIR", "BREAKPAD_DUMP_LOCATION"):
            self.assertTrue(r["env"][var].startswith(str(support.RUNTIME_DIR / "render-tmp")), var)
        self.assertFalse(any(str(support.EXPORTS_DIR) in a for a in r["argv"]))


class ReadinessTests(unittest.TestCase):
    def test_default_budgets_null_means_unavailable_without_starting_chrome(self):
        marker = support.scratch("never-run") / "ran"
        w = support.scratch("never-run-chrome") / "chrome"
        w.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        os.chmod(w, 0o700)
        r = renderer.readiness(config.PdfSettings(chrome_path=str(w)), use_cache=False)
        self.assertEqual((r.ready, r.code), (False, "budgets-not-set"))
        self.assertFalse(marker.exists())

    def test_invalid_settings_and_missing_chrome(self):
        bad = config.parse_pdf({"max_pages": 0, "memory_budget_mb": "lots"})
        self.assertEqual(renderer.readiness(bad).code, "pdf-settings-invalid")
        self.assertEqual(renderer.readiness(config.PdfSettings(chrome_path="/nonexistent/chrome")).code,
                         "chrome-not-found")

    def test_gate_record_binds_to_the_exact_binary(self):
        d = support.scratch("gated-chrome")
        w = d / "chrome"
        w.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" --mode=normal "$@"\n')
        os.chmod(w, 0o700)
        st = config.PdfSettings(chrome_path=str(w), memory_budget_mb=1024, scratch_budget_mb=512,
                                monitor_interval_ms=100)
        r = renderer.readiness(st, use_cache=False)
        self.assertEqual((r.ready, r.code), (False, "gates-not-passed"))
        ident = renderer.chrome_identity(str(w), r.chrome_version)
        renderer.write_gate_record(ident, {"all": "pass"})
        r = renderer.readiness(st, use_cache=False)
        self.assertEqual((r.ready, r.code), (True, "ready"))
        self.assertIn("154.0.8037.93", r.chrome_version)
        with open(w, "a") as f:            # the binary changes: the gate record no longer applies
            f.write("# updated\n")
        r = renderer.readiness(st, use_cache=False)
        self.assertEqual(r.code, "gates-not-passed")

    def test_config_defaults_ship_null_budgets(self):
        s = config.parse({})
        self.assertIsNone(s.pdf.memory_budget_mb)
        self.assertIsNone(s.pdf.scratch_budget_mb)
        self.assertIsNone(s.pdf.monitor_interval_ms)
        self.assertEqual((s.pdf.max_pages, s.pdf.render_timeout_seconds), (50, 45.0))
        self.assertTrue(s.label_admin)
        self.assertEqual(s.label_delete_max_messages, 10000)
        self.assertEqual(config.parse_pdf({"render_timeout_seconds": 60}).problems, ["pdf-timeout-invalid"])


class PdfExportIntegrationTests(unittest.TestCase):
    """export_email with a ready renderer (fake Chrome + gate record for it)."""

    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")
        d = support.scratch("export-chrome")
        self.mode_file = d / "mode"
        w = d / "chrome"
        w.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" --mode=$(cat "{self.mode_file}") "$@"\n')
        os.chmod(w, 0o700)
        self.mode_file.write_text("normal")
        self.orig = self.s.SETTINGS.pdf
        self.s.SETTINGS.pdf = config.PdfSettings(chrome_path=str(w), max_pages=3, render_timeout_seconds=15,
                                                 memory_budget_mb=4096, scratch_budget_mb=4096, monitor_interval_ms=100)
        r = renderer.readiness(self.s.SETTINGS.pdf, use_cache=False)
        renderer.write_gate_record(renderer.chrome_identity(str(w), r.chrome_version), {"test": True})

    def tearDown(self):
        self.s.SETTINGS.pdf = self.orig
        self.h.close()

    def test_pdf_saved_then_already_present(self):
        from tests import messages as M
        from tests.test_legacy_contract import fenced_part, trusted_part
        mid = self.f.add_message(M.plain(subject="Receipt"))
        out = self.s.export_email("alpha", mid, formats=["pdf"])
        self.assertIn("saved=1", trusted_part(out), out)
        self.assertIn("qbo_compatible: true (ok)", fenced_part(out))
        out2 = self.s.export_email("alpha", mid, formats=["pdf"])
        self.assertIn("already-present=1", trusted_part(out2))

    def test_too_many_pages_publishes_nothing(self):
        from tests import messages as M
        from tests.test_legacy_contract import fenced_part, trusted_part
        self.mode_file.write_text("too-many-pages")
        mid = self.f.add_message(M.plain(subject="Long"))
        out = self.s.export_email("alpha", mid, formats=["pdf", "eml"])
        self.assertIn("saved=1 already-present=0 skipped=0 refused=1", trusted_part(out))
        self.assertIn("pdf: state=refused reason=too-many-pages", fenced_part(out))
        views = [p for p in support.EXPORTS_DIR.rglob(f"{mid}/views/*")]
        self.assertEqual([p.suffix for p in views], [".eml"])


class CleanupGateTests(unittest.TestCase):
    """A second server starts while the first holds an active render: startup cleanup
    preserves the first profile, and later removes only proven-abandoned state."""

    def test_active_render_preserved_then_abandoned_removed(self):
        code = (
            "from tests import support; import locks, renderer, time, sys\n"
            "with locks.render_lock(5):\n"
            "    d = renderer.make_render_dir(); renderer._write_owner(d, None)\n"
            "    print(d, flush=True); time.sleep(4)\n"
        )
        holder = subprocess.Popen([sys.executable, "-c", code], cwd=support.REPO, stdout=subprocess.PIPE, text=True)
        active = holder.stdout.readline().strip()
        self.assertTrue(os.path.isdir(active))
        # "second server" startup: render lock busy -> cleanup skipped, active profile kept
        second = subprocess.run([sys.executable, "-c", "from tests import support; import renderer; renderer.startup_cleanup()"],
                                cwd=support.REPO, timeout=60)
        self.assertEqual(second.returncode, 0)
        self.assertTrue(os.path.isdir(active))
        holder.wait(timeout=30)                 # owner exits without cleaning: now abandoned
        holder.stdout.close()
        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            kept = renderer.make_render_dir()
            with open(os.path.join(kept, "owner.json"), "w") as f:
                json.dump({"pid": sleeper.pid, "start": procinfo.start_time(sleeper.pid), "pgid": None}, f)
            with locks.render_lock(10):
                stats = renderer.cleanup_abandoned()
            self.assertFalse(os.path.exists(active))     # proven abandoned: owner gone, no processes
            self.assertTrue(os.path.isdir(kept))          # owner alive: not proven abandoned
            self.assertGreaterEqual(stats["removed"], 1)
            self.assertGreaterEqual(stats["kept_owner_alive"], 1)
        finally:
            sleeper.kill()
            sleeper.wait()
        with locks.render_lock(10):
            renderer.cleanup_abandoned()
        self.assertFalse(os.path.exists(kept))


if __name__ == "__main__":
    unittest.main()
