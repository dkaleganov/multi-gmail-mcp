"""Fixes from the independent code and security reviews of the D16 commits (2026-10-05):
hostile structural headers never break read_email or save_attachments; the prediction that
now runs on every read is bounded (header caps, a fast-charset allowlist, an input cap, a short
deadline checked per section and per attribute, and no work at all when nothing can be
embedded); a prediction is reused per account and message; a successful prediction implies
the view succeeds even with a huge Authentication-Results header."""
from tests import support  # noqa: F401

import email
import email.policy
import itertools
import re
import time
import unittest
from unittest import mock

import htmlview
import mime
from tests import coverage_shapes as C
from tests import messages as M
from tests.fakegmail import FakeGmail
from tests.test_legacy_contract import fenced_part, trusted_part


def payload_of(raw: bytes) -> dict:
    f = FakeGmail()
    return f.messages[f.add_message(raw)]["payload"]


def with_receipt(content_type: str, extra_headers: str = "") -> bytes:
    """A text body and a receipt PDF under a top-level Content-Type the test chooses."""
    return M.raw_message(
        C.HEAD + extra_headers + f"Content-Type: {content_type}\n\n"
        "--B\nContent-Type: text/plain\n\nBODY TEXT HERE\n"
        + C.part("application/pdf", M.PDF, disp="attachment", name="receipt.pdf", b="B") + "--B--\n")


def logo_message(html: str = '<img src="cid:e@x">', charset: str = "utf-8", extra_headers: str = "") -> bytes:
    return M.raw_message(
        C.HEAD + extra_headers + 'Content-Type: multipart/related; boundary="R"\n\n'
        f"--R\nContent-Type: text/html; charset={charset}\n\n{html}\n"
        + C.part("image/png", C.PNG, cid="e@x", disp="inline", name="logo.png") + "--R--\n")


class HostileHeaders(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def test_both_tools_survive_a_header_the_parser_rejects(self):
        for ctype in ('multipart/mixed; boundary="B"; x*',                         # IndexError in the parser
                      "multipart/mixed " + "(" * 600 + ")" * 600 + '; boundary="B"'):  # RecursionError
            mid = self.f.add_message(with_receipt(ctype))
            read = fenced_part(self.s.read_email("alpha", mid))
            self.assertIn("BODY TEXT HERE", read, ctype[:30])
            self.assertIn("receipt.pdf (application/pdf, ", read, ctype[:30])
            self.assertIn(mime.inline_note("header-unreadable"), read, ctype[:30])
            out = self.s.save_attachments("alpha", mid)
            self.assertRegex(fenced_part(out), r"state=saved\n    original name: receipt\.pdf", ctype[:30])

    def test_header_caps(self):
        long_name = "x" * (mime.MAX_HEADER_VALUE + 10) + ".pdf"
        raw = with_receipt('multipart/mixed; boundary="B"').replace(b'filename="receipt.pdf"',
                                                                     f'filename="{long_name}"'.encode())
        parts, why = mime.enumerate_message(payload_of(raw), size_estimate=support.SIZE)
        self.assertEqual(why, "header-unreadable")
        # still listed and saved by default, and with a node unreadable no part counts as body
        self.assertEqual([p.name for p in parts], ["part-0.txt", long_name])
        many = "".join(C.part("image/png", C.PNG, disp="inline", name=f"n{i}-" + "y" * 1500 + ".png", b="B")
                       for i in range(30))
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="B"\n\n'
                            "--B\nContent-Type: text/plain\n\nhi\n" + many + "--B--\n")
        parts, why = mime.enumerate_message(payload_of(raw), size_estimate=support.SIZE)
        self.assertEqual((why, len(parts)), ("header-too-long", 31))   # the body text too: no selection


class Bounded(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def test_hostile_bodies_and_headers_cost_little_on_read(self):
        cases = {
            "punycode body": logo_message("<p>" + "a" * 512_000 + '</p><img src="cid:e@x">', charset="punycode"),
            "quadratic Content-Type": with_receipt('multipart/mixed; boundary="B"; charset=' + '"a"' * 16_000),
        }
        for name, raw in cases.items():
            mid = self.f.add_message(raw)
            t = time.monotonic()
            out = self.s.read_email("alpha", mid)
            self.assertLess(time.monotonic() - t, 2.0, name)
            self.assertIn("Attachments:", fenced_part(out), name)

    def test_slow_charsets_are_refused_by_the_view_too(self):
        v = htmlview.build_view(logo_message("<p>x</p>", charset="punycode"))
        self.assertIn("body-charset-refused", v.warnings)
        v = htmlview.build_view(logo_message("<p>x</p>", charset="shift_jis"))
        self.assertNotIn("body-charset-refused", v.warnings)

    def test_deadline_is_checked_inside_one_huge_tag(self):
        raw = logo_message("<img src=\"cid:e@x\" " + " ".join(f"a{i}=1" for i in range(2000)) + ">")
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        with mock.patch.object(htmlview.time, "monotonic", side_effect=itertools.count()):
            pred = htmlview.predict(msg)
        self.assertEqual((pred.ok, pred.reason), (False, "view-too-slow"))

    def test_input_cap(self):
        with mock.patch.object(htmlview, "PREDICT_MAX_INPUT", 10):
            pred = mime.predict_view(payload_of(logo_message()), size_estimate=support.SIZE)
        self.assertEqual((pred.ok, pred.reason, len(pred.sections)), (False, "too-large-to-predict", 1))

    def test_prediction_ok_implies_the_view_succeeds_with_a_huge_auth_header(self):
        # 2,000 distinct results (each shown in the page's authentication line) and one 40 KB
        # token (over the 32-letter cap, so never shown; the value stays under the view's 64 KB
        # Authentication-Results bound); the prediction counts the header
        tokens = ("".join(t) for t in itertools.product("abcdefghijklmnopqrstuvwxyz", repeat=4))
        auth = ("Authentication-Results: mx.google.com; "
                + "; ".join(f"dkim={next(tokens)}" for _ in range(2000)) + "; spf=" + "a" * 40_000 + "\n")
        raw = logo_message("<p>" + "w " * 20_000 + '</p><img src="cid:e@x">', extra_headers=auth)
        page = len(htmlview.build_view(raw).page)
        self.assertGreater(page, 40_000 + 2000 * 10)                  # the results are in the page
        payload = payload_of(raw)
        checked = 0
        for limit in range(page // 2, page + 6_000_000, 100_000):
            with mock.patch.object(htmlview, "MAX_PAGE_BYTES", limit):
                pred = mime.predict_view(payload, size_estimate=support.SIZE)
                if pred.ok:
                    checked += 1
                    htmlview.build_view(raw)            # must not raise
        self.assertGreater(checked, 0)


class ReusedPrediction(unittest.TestCase):
    def test_read_and_save_agree_when_a_fetch_fails_in_between(self):
        payload = payload_of(logo_message())
        html = payload["parts"][0]
        data = html["body"].pop("data")
        html["body"]["attachmentId"] = "ANGjdJsection"
        key = ("alpha@example.test", "reused-0001")

        def broken(att):
            raise OSError("network")

        first = mime.enumerate_message(payload, broken, cache_key=key, size_estimate=support.SIZE)
        again = mime.enumerate_message(payload, lambda att: data, cache_key=key, size_estimate=support.SIZE)
        self.assertEqual(first[1], "body-unavailable")
        self.assertEqual(([p.inline for p in again[0]], again[1]), ([False], "body-unavailable"))
        with mock.patch.object(mime, "PREDICTION_TTL", -1):
            fresh = mime.enumerate_message(payload, lambda att: data, cache_key=key, size_estimate=support.SIZE)
        self.assertEqual(([p.inline for p in fresh[0]], fresh[1]), ([True], None))


class RepeatedAttributes(unittest.TestCase):
    def test_the_first_src_wins_in_the_page(self):
        v = htmlview.build_view(C.CASES["repeated src attribute"][0]())
        tags = re.findall(r"<img[^>]*>", v.page.decode())
        self.assertEqual([t.count(" src=") for t in tags], [1])
        self.assertEqual(v.cid_used, 1)


if __name__ == "__main__":
    unittest.main()
