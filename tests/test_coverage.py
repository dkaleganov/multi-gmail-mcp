"""The coverage rule (owner decisions, 2026-10-05): every leaf part is body text, embedded by
the export view, or listed and saved by default; a part is inline (skipped by default) only
when the view embeds it; when the view would fail or cannot be predicted, no part is inline;
listing depends only on the MIME structure, so indexes never move."""
from tests import support  # noqa: F401

import email
import email.policy
import re
import unittest
from unittest import mock

import htmlview
import mime
from tests import coverage_shapes as C
from tests import messages as M
from tests.fakegmail import FakeGmail
from tests.test_legacy_contract import fenced_part, trusted_part


def payload_of(raw: bytes, **kw) -> dict:
    f = FakeGmail(**kw)
    return f.messages[f.add_message(raw)]["payload"]


def listing(parts) -> list:
    return [(p.name, p.inline) for p in parts]


class EveryCase(unittest.TestCase):
    def test_each_case_lists_the_expected_parts(self):
        for name, (make, want) in C.CASES.items():
            parts, why = mime.enumerate_message(payload_of(make()), size_estimate=support.SIZE)
            self.assertIsNone(why, name)
            self.assertEqual(listing(parts), want, name)

    def test_view_shows_exactly_the_inline_parts(self):
        # the cases where the view embeds something, and what it shows
        v = htmlview.build_view(C.CASES["reference differs only in case"][0]())
        self.assertEqual((v.cid_used, v.warnings), (1, []))
        self.assertIn(b'src="data:image/png;base64,', v.page)
        v = htmlview.build_view(C.CASES["second part sharing a Content-ID"][0]())
        self.assertEqual([".".join(map(str, x)) for x in v.embedded], ["1.1"])
        self.assertIn("duplicate-cid", v.warnings)
        for name in ("image/jpg label", "pdf from an img", "cid in CSS", "cid in a background attribute",
                     "reference outside the related scope"):
            v = htmlview.build_view(C.CASES[name][0]())
            self.assertEqual(v.embedded, [], name)
            self.assertNotIn(b"data:image", v.page, name)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def test_defaults_save_every_listed_part_that_is_not_inline(self):
        for name, (make, want) in C.CASES.items():
            mid = self.f.add_message(make())
            listed = re.findall(r"^\[(\d+)\] (.+)$", fenced_part(self.s.read_email("alpha", mid)), re.M)
            self.assertEqual([i for i, _ in listed], [str(i) for i in range(1, len(want) + 1)], name)
            out = self.s.save_attachments("alpha", mid)
            body = fenced_part(out)
            for i, (part_name, inline) in enumerate(want, 1):
                state = "skipped reason=inline-excluded" if inline else "saved"
                shown = re.escape(part_name) if not part_name.startswith("part-") else \
                    rf"\(none\) \[generated: {re.escape(part_name)}\]"
                self.assertRegex(body, rf"\[{i}\] state={state}\n    original name: {shown}", name)
            n_inline = sum(1 for _, inline in want if inline)
            self.assertIn(f"saved={len(want) - n_inline} already-present=0 skipped={n_inline}", trusted_part(out), name)

    def test_when_the_view_would_fail_no_part_is_inline_in_either_tool(self):
        raw = C.related('<img src="cid:big@x">', C.part("image/png", b"\x89PNG" + b"\x00" * 30000, cid="big@x",
                                                         disp="inline", name="big.png"))
        mid = self.f.add_message(raw)
        with mock.patch.object(htmlview, "MAX_PAGE_BYTES", 30000):
            with self.assertRaises(htmlview.ViewError) as cm:
                htmlview.build_view(raw)
            self.assertEqual(cm.exception.code, "html-too-large")
            read = fenced_part(self.s.read_email("alpha", mid))
            saved = self.s.save_attachments("alpha", mid)
        self.assertIn("big.png (image/png, ", read)
        self.assertIn(", attachment)", read)
        self.assertIn(mime.inline_note("html-too-large"), read)
        self.assertIn("saved=1 already-present=0 skipped=0", trusted_part(saved))
        self.assertIn(mime.inline_note("html-too-large"), fenced_part(saved))


class PredictionLimits(unittest.TestCase):
    def test_a_close_call_counts_as_failure(self):
        # predict() lowers the size limit (5% plus a header bound), so near the limit the view
        # may still render while the enumerator already treats the images as not shown
        raw = C.related('<img src="cid:e@x">', C.part("image/png", b"\x89PNG" + b"\x00" * 9000, cid="e@x"))
        size = len(htmlview.build_view(raw).page)
        with mock.patch.object(htmlview, "MAX_PAGE_BYTES", size + 64):
            htmlview.build_view(raw)                                   # the view still fits
            pred = mime.predict_view(payload_of(raw), size_estimate=support.SIZE)
        self.assertEqual((pred.ok, pred.reason, pred.embedded), (False, "html-too-large", []))

    def test_too_slow_means_no_inline_and_the_same_indexes(self):
        raw = C.related("<p>x</p>" * 400 + '<img src="cid:e@x">', C.part("image/png", C.PNG, cid="e@x"),
                        C.part("application/pdf", M.PDF, disp="attachment", name="a.pdf"))
        payload = payload_of(raw)
        before, why = mime.enumerate_message(payload, size_estimate=support.SIZE)
        self.assertEqual((listing(before), why), ([("part-1.1.png", True), ("a.pdf", False)], None))
        with mock.patch.object(htmlview, "PREDICT_SECONDS", -1):
            after, why = mime.enumerate_message(payload, size_estimate=support.SIZE)
        self.assertEqual(why, "view-too-slow")
        self.assertEqual([(p.index, p.name, p.path) for p in after], [(p.index, p.name, p.path) for p in before])
        self.assertEqual([p.inline for p in after], [False, False])

    def test_unreadable_section_keeps_the_indexes(self):
        raw = C.related('<img src="cid:e@x">', C.part("image/png", C.PNG, cid="e@x"))
        payload = payload_of(raw)
        html = payload["parts"][1]["parts"][0]
        html["body"]["attachmentId"] = "ANGjdJsection"
        data = html["body"].pop("data")
        ok, why_ok = mime.enumerate_message(payload, lambda att: data, size_estimate=support.SIZE)
        failed, why = mime.enumerate_message(payload, lambda att: (_ for _ in ()).throw(OSError("network")), size_estimate=support.SIZE)
        self.assertEqual((why_ok, why), (None, "body-unavailable"))
        self.assertEqual([(p.index, p.name) for p in ok], [(p.index, p.name) for p in failed])
        self.assertEqual(([p.inline for p in ok], [p.inline for p in failed]), ([True], [False]))


class AttachedMessages(unittest.TestCase):
    def test_parts_of_an_attached_message_without_its_octets_are_listed(self):
        inner = C.mixed("<p>inner body</p>", C.part("image/png", C.PNG, b="B"))
        raw = M.with_attached_message(inner)
        opaque = mime.enumerate_message(payload_of(raw, rfc822_mode="opaque"), size_estimate=support.SIZE)[0]
        self.assertEqual([p.name for p in opaque], ["forwarded.eml"])      # saved whole: covers its parts
        parsed = mime.enumerate_message(payload_of(raw, rfc822_mode="parsed"), size_estimate=support.SIZE)[0]
        self.assertEqual([(p.name, p.parsed_container) for p in parsed],
                         [("forwarded.eml", True), ("part-1.0.0.html", False), ("part-1.0.1.png", False)])


class CidMatching(unittest.TestCase):
    def test_exact_match_first_then_case_insensitive_first_part(self):
        def view(ref):
            raw = C.related(f'<img src="cid:{ref}">',
                            C.part("image/png", C.PNG, cid="Logo@x", disp="inline", name="upper.png"),
                            C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="lower.png"))
            return [".".join(map(str, x)) for x in htmlview.build_view(raw).embedded], raw

        self.assertEqual(view("logo@x")[0], ["1.2"])        # exact
        self.assertEqual(view("Logo@x")[0], ["1.1"])        # exact
        got, raw = view("LOGO@X")
        self.assertEqual(got, ["1.1"])                      # no exact match: the first part, ignoring case
        parts = mime.enumerate_message(payload_of(raw), size_estimate=support.SIZE)[0]
        self.assertEqual(listing(parts), [("upper.png", True), ("lower.png", False)])

    def test_no_resolution_outside_the_sections_related_scope(self):
        raw = C.CASES["reference outside the related scope"][0]()
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertEqual([sel.scope_path for sel in htmlview.select_body(msg, [])], [None])
        self.assertIn("missing-cid", htmlview.build_view(raw).warnings)


if __name__ == "__main__":
    unittest.main()
