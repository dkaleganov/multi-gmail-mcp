"""Fixes from the seventh code and security reviews (2026-10-05).

- A header the view keeps is cut while parsing once it is longer than the view reads (the
  length counted exactly as the view reads it: leading blanks stripped, CR and LF dropped), so
  a header folded over millions of lines costs no more than its first few thousand; a cut
  structural header is refused exactly as the whole one would be, a cut From/To/Cc/Date/Subject
  (over 2 MiB, which no prediction accepts) is refused as header-too-long.
- Lengths are counted before unfolding; the clock is read between the header block's steps;
  a page over the size cap is refused before it is assembled (its escaped length counted).
- svg and math honor "/>" (HTML's foreign content), so a self-closing raw-text tag inside them
  hides nothing after them.
- A uuencoded text part is never selected as body: a readable alternative is shown instead.
- The attached-message check walks a forward inside a forward, and caps the values it reads."""
from tests import support  # noqa: F401

import base64
import email.feedparser
import email.policy
import random
import time
import unittest
from unittest import mock

import htmlview
import mime
from tests import coverage_shapes as C
from tests import messages as M
from tests.fakegmail import FakeGmail
from tests.test_review5_d16 import logo_related


def fake_of(raw: bytes, **kw):
    f = FakeGmail(**kw)
    mid = f.add_message(raw)
    return f, mid, f.messages[mid]["payload"]


def predict(raw: bytes, payload=None, **kw):
    f, mid, own = fake_of(raw, **kw)
    return mime.predict_view(payload if payload is not None else own,
                             lambda att: f._messages_attachments_get("me", mid, att)["data"], size_estimate=len(raw))


def build(raw):
    try:
        v = htmlview.build_view(raw)
        return (v.page, v.warnings, v.embedded, v.headers)
    except htmlview.ViewError as e:
        return e.code


class FoldedHeaders(unittest.TestCase):
    def timed(self, raw):
        t = time.monotonic()
        out = build(raw)
        return out, time.monotonic() - t

    def test_a_part_header_folded_over_many_lines(self):
        folds = "Content-Type: text/html;" + "\n " * 2_000_000 + "charset=utf-8\n"
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="B"\n\n--B\n' + folds
                            + "\n<p>hi</p>\n--B--\n")
        out, dt = self.timed(raw)
        self.assertEqual(out, "header-too-long")
        self.assertLess(dt, 3.0)

    def test_a_subject_folded_past_what_the_view_reads(self):
        raw = M.raw_message("From: a@example.test\nSubject: s" + "\n x" * 1_200_000
                            + "\nContent-Type: text/plain\n\nbody\n")
        out, dt = self.timed(raw)
        self.assertEqual(out, "header-too-long")
        self.assertLess(dt, 3.0)

    def test_leading_blank_folds_still_read_the_value(self):
        raw = M.raw_message("From: a@example.test\nSubject:" + "\n " * 300_000 + "\n real subject\n"
                            "Content-Type:" + "\n\t" * 300_000 + "\n text/html\n\n<p>hi</p>\n")
        out = build(raw)
        self.assertIsInstance(out, tuple, out)
        page, warnings, embedded, headers = out
        self.assertEqual(headers["Subject"], "real subject")
        self.assertIn(b"<p>hi</p>", page)                   # read as text/html

    def test_the_cut_gives_the_whole_header_s_answer(self):
        # structural headers: the cut never changes what the view does (patched cap, random folds)
        rng = random.Random(71)
        stock = email.feedparser.FeedParser._parse_headers
        with mock.patch.object(htmlview, "VIEW_HEADER_VALUE", 48):
            for _ in range(600):
                pieces = [rng.choice([" ", "\t", "x", "y=1", ";", "\n ", "\n\t", "\r\n "]) for _ in range(rng.randrange(0, 60))]
                value = "image/png" + "".join(pieces)
                raw = C.related('<img src="cid:logo@x">', C.part("image/png", C.PNG, cid="logo@x", disp="inline",
                                                                   name="l.png")).replace(
                    b"Content-Type: image/png", ("Content-Type: " + value).replace("\n", "\r\n").encode())
                ours = build(raw)
                with mock.patch.object(htmlview._ViewFeedParser, "_parse_headers", stock):
                    whole = build(raw)
                self.assertEqual(ours, whole, value)

    def test_the_length_is_the_one_the_guard_reads(self):
        rng = random.Random(72)
        for _ in range(3000):
            first = "".join(rng.choice([" ", "\t", "a", "\r\n", ""]) for _ in range(rng.randrange(0, 6)))
            rest = ["".join(rng.choice([" ", "\t", "b", "c"]) for _ in range(rng.randrange(1, 5))) + "\n"
                    for _ in range(rng.randrange(0, 6))]
            lines = ["Subject:" + first + "\n"] + rest
            flat = htmlview._flat_after(-1, lines[0][len("Subject:"):])
            for line in lines[1:]:
                flat = htmlview._flat_after(flat, line)
            value = email.policy.default.header_source_parse(lines)[1]
            self.assertEqual(max(flat, 0), len(value.replace("\r", "").replace("\n", "")), lines)


class ThePageIsMeasuredFirst(unittest.TestCase):
    def test_an_oversized_page_is_never_assembled(self):
        raw = M.raw_message("From: a@example.test\nTo: " + '"' * 1_000_000 + " <x@example.test>\nSubject: "
                            + "&" * 2_000_000 + "\nContent-Type: text/plain\n\nbody\n")
        t = time.monotonic()
        self.assertEqual(build(raw), "html-too-large")
        self.assertLess(time.monotonic() - t, 3.0)

    def test_the_counted_length_is_html_escape_s(self):
        import html
        rng = random.Random(73)
        for _ in range(5000):
            s = "".join(rng.choice("ab&<>\"' é😀") for _ in range(rng.randrange(0, 40)))
            for quote in (True, False):
                self.assertEqual(htmlview._escaped_len(s, quote), len(html.escape(s, quote=quote)))


class ForeignContent(unittest.TestCase):
    def test_svg_and_math_honor_self_closing(self):
        for doc in ("<svg><title/></svg><p>VISIBLE</p>", "<svg><style/></svg><p>VISIBLE</p>",
                    "<math><script/></math><p>VISIBLE</p>", '<svg><textarea a="1"/></svg><p>VISIBLE</p>'):
            out, _ = htmlview.sanitize_html(doc, htmlview.CidScope({}), {}, [])
            self.assertIn("<p>VISIBLE</p>", out, doc)
        out, _ = htmlview.sanitize_html("<title/>hidden</title><p>after</p>", htmlview.CidScope({}), {}, [])
        self.assertEqual(out, "<p>after</p>")                     # in HTML context the slash is ignored


class UuencodedAlternatives(unittest.TestCase):
    def test_the_readable_alternative_is_shown(self):
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/alternative; boundary="A"\n\n'
                            "--A\nContent-Type: text/plain\n\nthe plain body\n"
                            "--A\nContent-Type: text/html\nContent-Transfer-Encoding: x-uuencode (old)\n\n"
                            "begin 644 x\nM\n`\nend\n--A--\n")
        page, warnings, embedded, headers = build(raw)
        self.assertIn(b"the plain body", page)
        self.assertIn("section-encoding-unsupported", warnings)
        self.assertNotIn("no-displayable-body", warnings)


class AttachedMessagesInside(unittest.TestCase):
    def test_a_forward_inside_a_forward(self):
        innermost = ("From: b@example.test\nSubject: older\nMIME-Version: 1.0\n"
                     'Content-Type: multipart/mixed; boundary="Q"\n\n--Q\nContent-Type: text/plain\n\nold\n--Q--\n')
        inner = ("From: a@example.test\nSubject: fwd\nMIME-Version: 1.0\nContent-Type: message/rfc822\n\n" + innermost)
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/related; boundary="X"\n\n--X\nContent-Type: text/html\n\n'
                            '<img src="cid:logo@x">\n--X\nContent-Type: message/rfc822\n\n' + inner
                            + C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="logo.png", b="X") + "--X--\n")
        for mode in ("parsed", "opaque"):
            pred = predict(raw, rfc822_mode=mode)
            self.assertEqual((pred.ok, pred.embedded), (True, [(2,)]), mode)

    def test_many_inner_values_count_like_any_others(self):
        inner_parts = "".join(f'--Y\nContent-Type: multipart/mixed; boundary="Z{i}"; x="' + "a" * 1900
                              + f'"\n\n--Z{i}\nContent-Type: text/plain\n\nt\n--Z{i}--\n' for i in range(40))
        inner = ("From: a@example.test\nSubject: fwd\nMIME-Version: 1.0\n"
                 'Content-Type: multipart/mixed; boundary="Y"\n\n' + inner_parts + "--Y--\n")
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/related; boundary="X"\n\n--X\nContent-Type: text/html\n\n'
                            '<img src="cid:logo@x">\n--X\nContent-Type: message/rfc822\n\n' + inner
                            + C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="logo.png", b="X") + "--X--\n")
        pred = predict(raw, rfc822_mode="parsed")
        self.assertEqual((pred.ok, pred.reason, pred.sections), (False, "structure-ambiguous", []))


if __name__ == "__main__":
    unittest.main()
