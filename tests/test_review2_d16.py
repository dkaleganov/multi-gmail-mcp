"""Fixes from the second code and security reviews (2026-10-05): header parsing no longer
depends on the caller's stack depth (one linear comment-depth check, shared by the view and the
enumerator's adapter, before any structured parse), the adapter parses every structural header
the view can parse (a superset: all four on every node), each value once, the view's whole build
has one deadline (the MIME parse is fed in
chunks and refused past the enumerator's nesting limit), display headers are bounded on the
parser's real input, and "prediction ok implies the view succeeds and embeds the same parts"
holds for every structural header at every position."""
from tests import support  # noqa: F401

import base64
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


def comments(n: int) -> str:
    return "(" * n + ")" * n


def at_depth(n: int, fn):
    """Call fn with n more frames on the stack."""
    return fn() if n <= 0 else at_depth(n - 1, fn)


def nested(inner: str, levels: int, hostile_ctype: str | None = None) -> str:
    """`inner` (a complete part, headers and body, boundary R) wrapped in `levels` multipart/mixed
    containers; the innermost container's Content-Type may carry a hostile suffix."""
    out = inner
    for i in range(levels):                  # boundaries N0z, N1z, ...: none a prefix of another
        ctype = f'multipart/mixed; boundary="N{i}z"'
        if i == 0 and hostile_ctype is not None:
            ctype += hostile_ctype
        out = f"Content-Type: {ctype}\n\n--N{i}z\n{out}--N{i}z--\n"
    return out


def logo_related(html_ctype="text/html; charset=utf-8", html_cte=None, img_ctype="image/png", img_cd="inline",
                 img_cid="<logo@x>", img_cte="base64", related_extra="") -> str:
    """A related part (headers and body) whose HTML embeds a logo; every structural header can
    be replaced."""
    html_hdr = f"Content-Type: {html_ctype}\n" + (f"Content-Transfer-Encoding: {html_cte}\n" if html_cte else "")
    body = "<p>receipt</p><img src=\"cid:logo@x\">" if not html_cte else (
        base64.encodebytes(b'<p>receipt</p><img src="cid:logo@x">').decode() if html_cte.startswith("base64") else
        '<p>receipt</p><img src="cid:logo@x">')
    return (f'Content-Type: multipart/related; boundary="R"{related_extra}\n\n'
            f"--R\n{html_hdr}\n{body}\n"
            f"--R\nContent-Type: {img_ctype}\nContent-Disposition: {img_cd}; filename=\"logo.png\"\n"
            f"Content-ID: {img_cid}\nContent-Transfer-Encoding: {img_cte}\n\n{base64.encodebytes(C.PNG).decode()}"
            "--R--\n")


def message(part: str) -> bytes:
    return M.raw_message(C.HEAD.rstrip("\n") + "\n" + part)


class StackDepthDoesNotMatter(unittest.TestCase):
    def test_listing_is_the_same_at_any_stack_depth(self):
        parts = "".join(f"--B\nContent-Type: text/plain; charset=utf-8 {comments(470 + i)}\n\npart {i}\n"
                        for i in range(30))
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="B"\n\n' + parts
                            + C.part("application/pdf", M.PDF, disp="attachment", name="receipt.pdf", b="B")
                            + "--B--\n")
        payload = payload_of(raw)
        seen = {at_depth(n, lambda: tuple((p.index, p.name) for p in mime.enumerate_message(payload, size_estimate=support.SIZE)[0]))
                for n in (0, 1, 5, 50, 300)}
        self.assertEqual(len(seen), 1)
        self.assertEqual(dict(next(iter(seen)))[31], "receipt.pdf")

    def test_prediction_is_the_same_at_any_stack_depth(self):
        raw = message(nested(logo_related(img_ctype="image/png " + comments(481)), 17))
        payload = payload_of(raw)
        results = {at_depth(n, lambda: (mime.predict_view(payload, size_estimate=support.SIZE).ok, mime.predict_view(payload, size_estimate=support.SIZE).reason))
                   for n in (0, 10, 100, 400)}
        self.assertEqual(results, {(False, "header-unreadable")})


class PredictionImpliesTheView(unittest.TestCase):
    """For every structural header at every position and a set of hostile values: when the
    prediction says ok, the view must parse the message and embed exactly what was predicted."""

    VALUES = {"ok": "", "depth 32": " " + comments(32), "depth 33": " " + comments(33),
              "depth 480": " " + comments(480), "param x*": "; x*", "quotes 1900": "; q=" + '"a"' * 633,
              "quotes 2100": "; q=" + '"a"' * 700}

    def shapes(self, value):
        yield "image Content-Type", message(logo_related(img_ctype="image/png" + value))
        yield "image Content-Disposition", message(logo_related(img_cd="inline" + value))
        yield "image Content-ID", message(logo_related(img_cid="<logo@x>" + value))
        yield "image Content-Transfer-Encoding", message(logo_related(img_cte="base64" + value))
        yield "html Content-Type", message(logo_related(html_ctype="text/html; charset=utf-8" + value))
        yield "html Content-Transfer-Encoding", message(logo_related(html_cte="base64" + value))
        yield "related Content-Type", message(logo_related(related_extra=value))
        for depth in (1, 10, 18):
            yield f"container at depth {depth}", message(nested(logo_related(), depth, hostile_ctype=value))

    def test_every_header_every_position(self):
        accepted = refused = 0
        for label, value in self.VALUES.items():
            for where, raw in self.shapes(value):
                pred = mime.predict_view(payload_of(raw), size_estimate=len(raw))
                try:
                    view = htmlview.build_view(raw)
                except htmlview.ViewError as e:
                    view = e.code
                if pred.ok:
                    accepted += 1
                    self.assertIsInstance(view, htmlview.View, f"{where} / {label}: prediction ok, view {view}")
                    # every part predicted embedded is embedded by the view (the safety property).
                    # The prediction may find fewer when the payload was parsed differently: the
                    # fake builds it with compat32, which leaves a body undecoded or a boundary
                    # unsplit when a comment sits in the header, where Python's parser handles
                    # it. That only means an extra image saved.
                    self.assertLessEqual(set(pred.embedded), set(view.embedded), f"{where} / {label}")
                    if label == "ok" or (label == "quotes 1900" and "Transfer" not in where):
                        self.assertEqual(set(pred.embedded), set(view.embedded), f"{where} / {label}")
                else:
                    refused += 1
        self.assertGreater(accepted, 10)
        self.assertGreater(refused, 10)


class ContentTransferEncodingGap(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def test_an_unreadable_transfer_encoding_never_hides_the_image(self):
        mid = self.f.add_message(message(logo_related(img_cte="base64 " + comments(600))))
        read = fenced_part(self.s.read_email("alpha", mid))
        self.assertIn("logo.png (image/png, ", read)
        self.assertIn(", attachment)", read)
        self.assertIn(mime.inline_note("header-unreadable"), read)
        # the logo, and the HTML too (with a node unreadable, no part counts as body)
        self.assertIn("saved=2", trusted_part(self.s.save_attachments("alpha", mid)))
        out = fenced_part(self.s.export_email("alpha", mid, formats=["eml", "html"]))
        self.assertIn("html: state=refused reason=header-unreadable", out)


class AdapterDetails(unittest.TestCase):
    def test_unfolding_matches_the_view(self):
        for ref in ("abc%20def@x", "abc%20%20def@x"):
            raw = message(logo_related(img_cid="<abc\n def@x>").replace('cid:logo@x', f"cid:{ref}"))
            pred = mime.predict_view(payload_of(raw), size_estimate=support.SIZE)
            self.assertTrue(pred.ok, ref)
            self.assertEqual(set(pred.embedded), set(htmlview.build_view(raw).embedded), ref)

    def test_no_part_is_parsed_on_demand(self):
        payload = payload_of(message(nested(logo_related(), 1)))
        payload["mimeType"] = "message/rfc822"         # Gmail labels it a message; its headers disagree
        t = time.monotonic()
        pred = mime.predict_view(payload, size_estimate=support.SIZE)
        self.assertEqual((pred.ok, pred.reason, pred.sections), (False, "structure-ambiguous", []))
        self.assertLess(time.monotonic() - t, 0.5)

    def test_ambiguous_structure_is_unavailable(self):
        for extra in ('; boundary*0="R2"', '; BOUNDARY="R3"'):
            pred = mime.predict_view(payload_of(message(logo_related(related_extra=extra))), size_estimate=support.SIZE)
            self.assertEqual((pred.ok, pred.reason), (False, "header-unreadable"), extra)
        raw = message(logo_related()).replace(b'Content-Type: multipart/related; boundary="R"',
                                              b'Content-Type: multipart/related; boundary="R"\r\n'
                                              b'Content-Type: multipart/related; boundary="Z"')
        self.assertEqual(mime.predict_view(payload_of(raw), size_estimate=support.SIZE).reason, "header-unreadable")

    def test_a_cached_read_parses_no_header(self):
        payload = payload_of(message(logo_related()))
        key = ("alpha@example.test", "cached-0001")
        mime.enumerate_message(payload, cache_key=key, size_estimate=support.SIZE)
        with mock.patch.object(htmlview, "parse_header", side_effect=AssertionError("parsed")):
            parts, why = mime.enumerate_message(payload, cache_key=key, size_estimate=support.SIZE)
        self.assertEqual(([p.inline for p in parts], why), ([True], None))

    def test_read_path_header_work_is_parsed_once(self):
        imgs = [C.part(f"image/png; q=" + '"a"' * 600 + f"; n={i}", C.PNG, cid=f"i{i}@x", disp="inline",
                       name=f"i{i}.png") for i in range(31)]
        raw = C.related("".join(f'<img src="cid:i{i}@x">' for i in range(31)), *imgs)
        payload = payload_of(raw)
        calls = []
        real = htmlview.parse_header

        def counting(name, flat):
            calls.append((name.lower(), flat))
            return real(name, flat)

        with mock.patch.object(htmlview, "parse_header", counting):
            t = time.monotonic()
            pred = mime.predict_view(payload, size_estimate=support.SIZE)
            dt = time.monotonic() - t
        self.assertTrue(pred.ok, pred.reason)
        self.assertEqual(len(calls), len(set(calls)))                 # each value parsed once
        self.assertLess(dt, 2.0)


class ViewBounds(unittest.TestCase):
    def test_display_headers_are_measured_on_the_parsers_input(self):
        for to, raw_shown in (('"' + "a" * 1500 + '" <x@y.z>', False), ("(a)" * 2000 + " <x@y.z>", True),
                              ("a\n" + " " * 1_000_000 + "\n <x@y.z>", True)):
            raw = message(logo_related()).replace(b"To: alpha@example.test", b"To: " + to.encode())
            t = time.monotonic()
            v = htmlview.build_view(raw)
            self.assertLess(time.monotonic() - t, 1.0)
            self.assertEqual("header-shown-unparsed-to" in v.warnings, raw_shown, to[:20])

    def test_nesting_past_the_enumerators_limit_is_refused_while_parsing(self):
        raw = message(nested(logo_related(), mime.MAX_DEPTH + 2))
        with self.assertRaises(htmlview.ViewError) as cm:
            htmlview.build_view(raw)
        self.assertEqual(cm.exception.code, "mime-too-deep")
        htmlview.build_view(message(nested(logo_related(), mime.MAX_DEPTH - 2)))   # within the limit

    def test_the_parse_has_the_views_deadline(self):
        lines = "x\n" * 400_000
        raw = message(nested(f"Content-Type: text/plain\n\n{lines}", 15))
        with mock.patch.object(htmlview, "VIEW_SECONDS", 0.05):
            t = time.monotonic()
            with self.assertRaises(htmlview.ViewError) as cm:
                htmlview.build_view(raw)
            self.assertEqual(cm.exception.code, "view-too-slow")
            self.assertLess(time.monotonic() - t, 2.0)

    def test_subject_of_reads_only_the_header_block(self):
        raw = message(f"Content-Type: text/plain\n\n" + "x" * 40_000_000)
        t = time.monotonic()
        self.assertEqual(htmlview.subject_of(raw), "Coverage")
        self.assertLess(time.monotonic() - t, 0.5)

    def test_a_nul_in_the_charset_falls_back(self):
        raw = message(logo_related(html_ctype="text/html; charset*=us-ascii''utf-8%00"))
        v = htmlview.build_view(raw)
        self.assertIn("body-charset-fallback", v.warnings)
        pred = mime.predict_view(payload_of(raw), size_estimate=support.SIZE)
        self.assertEqual((pred.ok, set(pred.embedded)), (True, set(v.embedded)))


if __name__ == "__main__":
    unittest.main()
