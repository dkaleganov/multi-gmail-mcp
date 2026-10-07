"""Regression tests for the independent code and security review findings (v5 build)."""
from tests import support  # noqa: F401

import json
import os
import re
import subprocess
import sys
import time
import unittest

import auth
import exportfs
import exports
import htmlview
import journal
import runtime
from tests import messages as M
from tests.fakegmail import http_error
from tests.test_exports import make_root, manifest, msg_dir, req, target
from tests.test_labels import OP_RE, wipe_journal
from tests.test_legacy_contract import fenced_part, trusted_part


class ExportReviewFixes(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()

    def test_one_failing_attachment_fetch_is_a_per_item_state(self):
        mid = self.f.add_message(M.with_attachments([(M.PDF, "application", "pdf", "a.pdf", "attachment"),
                                                     (M.JPEG, "image", "jpeg", "b.jpg", "attachment")]))
        att2 = self.f.messages[mid]["payload"]["parts"][2]["body"]["attachmentId"]
        self.f.fail("messages.attachments.get", 500, when=lambda kw: kw["id"] == att2)
        out = self.s.save_attachments("alpha", mid)
        self.assertIn("saved=1 already-present=0 skipped=0 refused=0 failed=1", trusted_part(out))
        self.assertIn("reason=gmail-500", fenced_part(out))

    def test_uppercase_message_id_uses_gmails_canonical_id(self):
        mid = self.f.add_message(M.with_attachments([(M.PDF, "application", "pdf", "a.pdf", "attachment")]))
        out = self.s.save_attachments("alpha", mid)
        orig_get = self.f._messages_get
        self.f._messages_get = lambda userId, id, **kw: orig_get(userId, id.lower(), **kw)
        upper = self.s.save_attachments("alpha", mid.upper())
        self.assertIn(f"message={mid} ", trusted_part(upper))        # canonical id, same folder
        self.assertIn("already-present=1", trusted_part(upper))

    def test_eml_survives_a_view_crash_and_surrogates_are_scrubbed(self):
        raw = ("From: a@example.test\nSubject: s\nDate: Вт, 6 окт 2026 10:00\n"
               "MIME-Version: 1.0\nContent-Type: text/html; charset=utf-7\n\n+2D3ePv-hello\n").replace("\n", "\r\n").encode("utf-8")
        mid = self.f.add_message(raw)
        out = self.s.export_email("alpha", mid, formats=["eml", "html"])
        self.assertIn("saved=2", trusted_part(out), out)
        v = htmlview.build_view(raw)
        self.assertIn("Вт, 6 окт 2026 10:00", v.page.decode())   # 8-bit date recovered
        self.assertIn("body-charset-refused", v.warnings)

    def test_view_is_not_built_when_only_an_unavailable_pdf_needs_it(self):
        mid = self.f.add_message(M.plain())
        calls = []
        orig = htmlview.build_view
        htmlview.build_view = lambda raw: calls.append(1) or orig(raw)
        try:
            out = self.s.export_email("alpha", mid)        # default: pdf (unavailable) + eml
        finally:
            htmlview.build_view = orig
        self.assertEqual(calls, [])
        self.assertIn("saved=1", trusted_part(out))

    def test_retained_bytes_survive_session_notes(self):
        d, root = make_root("retained")
        with exports.ExportSession(target(root), {}) as s:
            s.publish([req("k1", M.PDF)])
        att = os.path.join(msg_dir(d), "attachments")
        open(os.path.join(att, ".tmp-orphan"), "wb").close()
        import exporttools
        with exports.ExportSession(target(root), {}) as s:
            t, lines = exporttools._session_notes(s)
        self.assertIn("retained_bytes=", t)
        self.assertIn("orphans=1", t)


class ExportProtocolReviewFixes(unittest.TestCase):
    def test_case_variant_subfolders_share_one_lock_and_drop_nothing(self):
        d, root = make_root("case-lock")
        mid = "18c00000000000e1"
        specs = [{"subfolder": [sub], "items": [{"key": f"k{i}", "kind": "attachment", "namespace": "attachments",
                                                 "name": "same.bin", "data": None, "random": 2000 + i, "sleep": 0.3}]}
                 for i, sub in enumerate(["Receipts", "receipts", "RECEIPTS", "rEcEiPtS"])]
        procs = [subprocess.Popen([sys.executable, "-m", "tests.export_worker", str(d), mid, json.dumps(sp)],
                                  cwd=support.REPO, stdout=subprocess.PIPE, text=True) for sp in specs]
        for pr in procs:
            pr.communicate(timeout=120)
        m = manifest(d, mid, sub=("Receipts",))
        self.assertEqual(sorted(m["entries"]), ["k0", "k1", "k2", "k3"])
        files = [n for n in os.listdir(os.path.join(msg_dir(d, mid, sub=("Receipts",)), "attachments")) if not n.startswith(".")]
        self.assertEqual(len(files), 4)

    def test_failure_after_the_link_is_still_saved(self):
        d, root = make_root("post-link")
        orig = exportfs.full_sync
        calls = {"n": 0}

        def flaky(fd):
            calls["n"] += 1
            if calls["n"] == 4:            # the directory sync right after the link
                raise OSError("sync failed")
            return orig(fd)

        with exports.ExportSession(target(root), {}) as s:
            exportfs.full_sync = flaky
            try:
                r = s.publish([req("k1", M.PDF)])[0]
            finally:
                exportfs.full_sync = orig
        self.assertEqual(r.state, "saved")
        e = manifest(d)["entries"]["k1"]
        self.assertEqual(e["state"], "complete")

    def test_unexpected_produce_error_fails_only_that_item(self):
        d, root = make_root("produce-boom")

        def boom(fd):
            raise KeyError("malformed DevTools reply")

        bad = exports.Request("bad", "pdf", "views", req("x", b"x").plan, boom, {})
        with exports.ExportSession(target(root), {}) as s:
            rs = s.publish([req("good", M.PDF), bad])
        self.assertEqual([(r.state, r.code) for r in rs], [("saved", "ok"), ("failed", "produce-failed")])


class ViewReviewFixes(unittest.TestCase):
    def test_repeated_cid_references_stop_at_the_budget(self):
        big = M.PNG_1x1 + b"\x00" * 100_000
        html = "".join("<img src='cid:x@y'>" for _ in range(3000))
        raw = M.related_html(html, [(big, "png", "x@y", "x.png")])
        t0 = time.monotonic()
        with self.assertRaises(htmlview.ViewError) as cm:
            htmlview.build_view(raw)
        self.assertEqual(cm.exception.code, "html-too-large")
        self.assertLess(time.monotonic() - t0, 10)

    def test_unmatched_end_tags_are_linear(self):
        n = 100_000
        html = "<b>" * n + "</i>" * n + "<p>tail</p>"
        raw = M.with_attachments([], html=html)
        t0 = time.monotonic()
        v = htmlview.build_view(raw)
        self.assertLess(time.monotonic() - t0, 15)
        self.assertIn("tail", v.page.decode())

    def test_part_count_cap(self):
        parts = "".join(f"--b\nContent-Type: text/plain\n\np{i}\n" for i in range(600))
        raw = M.raw_message(f"From: a@example.test\nSubject: s\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n{parts}--b--\n")
        with self.assertRaises(htmlview.ViewError) as cm:
            htmlview.build_view(raw)
        self.assertEqual(cm.exception.code, "mime-too-many-parts")


class JournalReviewFixes(unittest.TestCase):
    def setUp(self):
        wipe_journal()

    def tearDown(self):
        wipe_journal()

    def _seed(self):
        with journal.AdminSession() as s:
            op = journal.new_op_id()
            s.append("PREPARED", op, kind="update", label_id="Label_1", account_id="a" * 64)
            return op

    def test_crash_during_segment_creation_never_wedges_the_journal(self):
        op = self._seed()
        d = runtime.private_dir("label-journal")
        code = ("from tests import support; import journal, os\n"
                "journal._checkpoint = lambda st: os._exit(97) if st == 'journal-segment-before-link' else None\n"
                "journal.SEGMENT_MAX = 10\n"
                "s = journal.AdminSession().__enter__()\n"
                "s.append('APPLIED', %r, observed={})\n" % op)
        self.assertEqual(subprocess.run([sys.executable, "-c", code], cwd=support.REPO, timeout=60).returncode, 97)
        self.assertTrue(any(n.endswith(".tmp") for n in os.listdir(d)))     # interrupted creation
        with journal.AdminSession() as s:                                  # cleaned up, still usable
            s.append("APPLIED", op, observed={})
        self.assertFalse(any(n.endswith(".tmp") for n in os.listdir(d)))

    def test_empty_or_headerless_final_segment_is_sealed_not_fatal(self):
        op = self._seed()
        d = runtime.private_dir("label-journal")
        for content in (b"", b'{"v":1,"seq":3,"ty'):
            names_ = sorted(n for n in os.listdir(d) if n.startswith("seg-"))
            nxt = d / f"seg-{len(names_) + 1:06d}.jsonl"
            nxt.write_bytes(content)
            os.chmod(nxt, 0o600)
            with journal.AdminSession() as s:
                self.assertTrue(s.sealed_on_entry)
                s.append("UNKNOWN_OUTCOME", op, error="x")
            with journal.AdminSession() as s:
                self.assertFalse(s.sealed_on_entry)


class LabelReviewFixes(unittest.TestCase):
    def setUp(self):
        wipe_journal()
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        wipe_journal()

    def test_parent_label_delete_is_refused(self):
        self.f.add_label("Parent")
        self.f.add_label("Parent/Child")
        out = self.s.delete_label("alpha", "Parent", confirm_name="Parent")
        self.assertIn("error=unsupported-cascade", out)
        self.assertIn("state=applied", self.s.delete_label("alpha", "Parent/Child", confirm_name="Parent/Child"))

    def test_third_state_after_definitive_error_does_not_wedge_the_label(self):
        lid = self.f.add_label("Wedge", labelListVisibility="labelShow", messageListVisibility="show")
        orig_patch, orig_get = self.f._labels_patch, self.f._labels_get

        def patch(userId, id, body):
            self.f.labels[id]["name"] = "Somebody Else"          # a concurrent outside rename
            raise http_error(400)

        self.f._labels_patch = patch
        out = self.s.update_label("alpha", "Wedge", new_name="Mine")
        self.assertIn("state=unknown-outcome", trusted_part(out))
        self.f._labels_patch = orig_patch
        later = self.s.update_label("alpha", "Somebody Else", label_list_visibility="labelHide")
        self.assertIn("state=applied", trusted_part(later))       # reconciled, no longer blocking

    def test_color_added_then_undone_returns_to_absent(self):
        lid = self.f.add_label("Plain", labelListVisibility="labelShow", messageListVisibility="show")
        op = OP_RE.search(self.s.update_label("alpha", "Plain", color={"backgroundColor": "#16a766",
                                                                        "textColor": "#ffffff"})).group(1)
        u = self.s.undo_label_change("alpha", op)
        self.assertIn("state=undone outcome=restored", trusted_part(u))
        self.assertIsNone(self.f.labels[lid].get("color"))

    def test_op_id_is_reported_on_failure_and_listed(self):
        lid = self.f.add_label("Gone", labelListVisibility="labelShow", messageListVisibility="show")
        orig = journal.AdminSession.append
        calls = {"n": 0}

        def flaky(self_, type_, op, **kw):
            if type_ == "APPLIED":
                raise journal.JournalError("journal-write-failed")
            return orig(self_, type_, op, **kw)

        journal.AdminSession.append = flaky
        try:
            out = self.s.delete_label("alpha", "Gone", confirm_name="Gone")
        finally:
            journal.AdminSession.append = orig
        self.assertIn("error=outcome-not-recorded", out)
        op = OP_RE.search(trusted_part(out)).group(1)
        listing = self.s.list_label_operations("alpha")
        self.assertIn(f"op={op} kind=delete label={lid} outcome=pending undo=none", trusted_part(listing))
        self.assertIn("Gone", fenced_part(listing))
        self.assertIn("state=undone", trusted_part(self.s.undo_label_change("alpha", op)))  # reconciled, then undone
        log = (runtime.root() / "audit.log").read_text()
        self.assertIn(f'"op": "{op}"', log)

    def test_modify_labels_never_picks_one_of_two_case_colliding_names(self):
        self.f.ci_names = False
        self.f.add_label("Bills")
        self.f.add_label("bills")
        mid = self.f.add_message(M.plain())
        out = self.s.modify_labels("alpha", message_id=mid, add_labels=["BILLS"])
        self.assertIn("error=invalid-argument", out)
        self.assertIn("Ambiguous", fenced_part(out))
        self.assertIn("Updated labels", self.s.modify_labels("alpha", message_id=mid, add_labels=["Bills"]))


class AuthReviewFixes(unittest.TestCase):
    def test_not_authorized_has_its_own_code_and_instruction(self):
        h = support.ServerHarness()
        try:
            def nope(alias, scopes):
                raise auth.NotAuthorizedError("Account 'alpha' is not authorized yet.")
            auth.get_credentials = nope
            out = h.server.list_labels("alpha")
        finally:
            h.close()
        self.assertIn("error=not-authorized", out)
        self.assertIn("python authenticate.py alpha", trusted_part(out))


if __name__ == "__main__":
    unittest.main()
