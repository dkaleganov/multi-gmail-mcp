"""export_email's header work is bounded (owner decision on addendum 3): the view parses each
structural header value once, within VIEW_HEADER_VALUE and VIEW_HEADER_TOTAL, never parses
into an attached message, shows long From/To/Cc/Subject unparsed (encoded words decoded), and reads
Authentication-Results raw; when it refuses, the .eml still saves and the result says why;
and the attachment enumerator's prediction checks the same headers with headroom, so a
successful prediction implies the view parses the message."""
from tests import support  # noqa: F401

import base64
import email
import email.policy
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

QUOTED = '"a"'


def payload_of(raw: bytes) -> dict:
    f = FakeGmail()
    return f.messages[f.add_message(raw)]["payload"]


def message(top_ctype='multipart/mixed; boundary="B"', extra="", parts=None) -> bytes:
    parts = parts if parts is not None else [
        "--B\nContent-Type: text/plain\n\nBODY TEXT HERE\n",
        C.part("application/pdf", M.PDF, disp="attachment", name="receipt.pdf", b="B")]
    return M.raw_message("From: Store <store@example.test>\nTo: alpha@example.test\nSubject: Crafted\n"
                         "Date: Mon, 5 Oct 2026 10:00:00 +0000\nMIME-Version: 1.0\n" + extra
                         + f"Content-Type: {top_ctype}\n\n" + "".join(parts) + "--B--\n")


def timed(fn):
    t = time.monotonic()
    try:
        return fn(), time.monotonic() - t
    except htmlview.ViewError as e:
        return e.code, time.monotonic() - t


class ViewHeaderBounds(unittest.TestCase):
    def test_structural_headers_over_the_caps_refuse_fast(self):
        long_ctype = 'multipart/mixed; boundary="B"; charset=' + QUOTED * 16_000          # 48 KB
        nested = "multipart/mixed " + "(" * 600 + ")" * 600 + '; boundary="B"'            # RecursionError
        for raw, want in ((message(long_ctype), "header-too-long"), (message(nested), "header-unreadable")):
            got, dt = timed(lambda: htmlview.build_view(raw))
            self.assertEqual(got, want)
            self.assertLess(dt, 0.5)
            self.assertEqual(htmlview.subject_of(raw), "Crafted")    # the file name still has the Subject

    def test_long_display_headers_are_shown_unparsed(self):
        for kb in (6, 12, 24):
            to = QUOTED * (kb * 1024 // 3) + " <x@y.test>"
            raw = message(extra=f"Cc: {to}\n")
            v, dt = timed(lambda: htmlview.build_view(raw))
            self.assertIsInstance(v, htmlview.View, kb)
            self.assertLess(dt, 1.0, kb)
            self.assertEqual("header-shown-unparsed-cc" in v.warnings, kb * 1024 > htmlview.ADDRESS_HEADER_PARSE, kb)

    def test_attached_message_headers_are_never_parsed(self):
        inner = message('multipart/mixed; boundary="B"; charset=' + QUOTED * 16_000).decode()
        raw = M.raw_message(                     # built as text: no parse of the crafted inner message
            "From: Store <store@example.test>\nTo: alpha@example.test\nSubject: Forward\n"
            'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="O"\n\n'
            "--O\nContent-Type: text/plain\n\nForwarding the original.\n"
            '--O\nContent-Type: message/rfc822\nContent-Disposition: attachment; filename="fwd.eml"\n\n'
            + inner.replace("\r\n", "\n") + "\n--O--\n")
        v, dt = timed(lambda: htmlview.build_view(raw))
        self.assertIsInstance(v, htmlview.View)
        self.assertLess(dt, 0.5)
        pred = mime.predict_view(payload_of(raw), size_estimate=len(raw))
        self.assertTrue(pred.ok, pred.reason)                       # the inner headers do not count

    def test_the_view_parses_only_the_headers_it_must(self):
        fetched = set()
        real = htmlview._ViewPolicy.header_fetch_parse

        def spy(self, name, value):
            fetched.add(name.lower())
            return real(self, name, value)

        with mock.patch.object(htmlview._ViewPolicy, "header_fetch_parse", spy):
            for make, _ in C.CASES.values():
                htmlview.build_view(make())
            htmlview.build_view(message(extra="Authentication-Results: mx.google.com; dkim=pass\nCc: c@d.test\n"))
        self.assertLessEqual(fetched, set(htmlview.STRUCTURAL_HEADERS) | {"from", "to", "cc", "subject"})
        self.assertIn("content-type", fetched)

    def test_each_value_is_parsed_once(self):
        parses = []
        real = type(htmlview._VIEW_POLICY.header_factory).__call__

        def counting(self, name, value):
            parses.append((name.lower(), value))
            return real(self, name, value)

        with mock.patch.object(type(htmlview._VIEW_POLICY.header_factory), "__call__", counting):
            htmlview.build_view(C.CASES["second part sharing a Content-ID"][0]())
        structural = [x for x in parses if x[0] in htmlview.STRUCTURAL_HEADERS]
        self.assertGreater(len(structural), 3)
        self.assertEqual(len(structural), len(set(structural)))     # no value parsed twice


class ExportRefusalSavesTheEml(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def test_refused_view_still_saves_the_eml_and_says_why(self):
        raw = message('multipart/mixed; boundary="B"; charset=' + QUOTED * 16_000)
        mid = self.f.add_message(raw)
        out, dt = timed(lambda: self.s.export_email("alpha", mid, formats=["eml", "html"]))
        self.assertLess(dt, 2.0)
        self.assertIn("saved=1 already-present=0 skipped=0 refused=1", trusted_part(out))
        body = fenced_part(out)
        self.assertIn("html: state=refused reason=header-too-long", body)
        eml = re.search(r"path: (.+\.eml)", body).group(1)
        with open(eml, "rb") as fh:
            self.assertEqual(fh.read(), raw)

    def test_default_export_without_a_view_is_bounded(self):
        raw = message('multipart/mixed; boundary="B"; charset=' + QUOTED * 16_000,
                      extra="Cc: " + QUOTED * 8000 + " <x@y.test>\n")
        mid = self.f.add_message(raw)
        out, dt = timed(lambda: self.s.export_email("alpha", mid))           # pdf (unavailable) and eml
        self.assertLess(dt, 2.0)
        self.assertIn("saved=1", trusted_part(out))


class PredictionImpliesView(unittest.TestCase):
    def assertImplies(self, raw, payload=None):
        pred = mime.predict_view(payload if payload is not None else payload_of(raw), size_estimate=len(raw))
        if pred.ok:
            try:
                htmlview.build_view(raw)
            except htmlview.ViewError as e:
                self.fail(f"prediction ok but the view refused: {e.code}")
        return pred.ok

    def test_sweep_over_header_sizes_and_counts(self):
        accepted = refused = 0
        with mock.patch.object(htmlview, "VIEW_HEADER_VALUE", 1024), \
                mock.patch.object(htmlview, "VIEW_HEADER_TOTAL", 8192):
            for length in (100, 400, 500, 600, 1000, 1100):
                for count in (1, 4, 8, 16):
                    imgs = [C.part("image/png", C.PNG, cid=f"i{i}@x", disp="inline",
                                   name=f"i{i}-" + "n" * max(1, length - 40) + ".png") for i in range(count)]
                    html = "".join(f'<img src="cid:i{i}@x">' for i in range(count))
                    raw = C.related(html, *imgs)
                    if self.assertImplies(raw):
                        accepted += 1
                    else:
                        refused += 1
        self.assertGreater(accepted, 0)
        self.assertGreater(refused, 0)

    def test_gmail_showing_encoded_filenames_decoded(self):
        # RAW carries an RFC 2047 filename; this Gmail payload shows it decoded (shorter)
        name = "日本語の長いファイル名" * 30
        encoded = "=?UTF-8?B?" + base64.b64encode(name.encode()).decode() + "?="
        raw = C.related('<img src="cid:j@x">', C.part("image/png", C.PNG, cid="j@x", disp="inline", name=encoded))
        payload = payload_of(raw)
        for node in payload["parts"][1]["parts"]:
            for h in node.get("headers") or []:
                h["value"] = h["value"].replace(encoded, name)
        with mock.patch.object(htmlview, "VIEW_HEADER_VALUE", 1500):
            self.assertImplies(raw, payload)


if __name__ == "__main__":
    unittest.main()
