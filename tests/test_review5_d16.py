"""Fixes from the fifth code and security reviews (2026-10-05).

- A boundary must use RFC 2046 characters only (an 8-bit one reads decoded in the header and
  escaped in the body lines, so the view never splits on it); a Content-ID or a multipart's
  Content-Type must be ASCII.
- When Gmail's tree and the view's could differ (a mislabeled or mis-split node, nested
  boundaries, a boundary inside an attached message that matches an enclosing one), the
  prediction is "structure-ambiguous" with no sections: every part is listed and saved.
- The view never uudecodes (a Python loop whose output can be twenty times its input), decodes
  a single-byte charset in steps with the deadline checked between them, charges an unfinished
  start tag by all the text it rescans, keeps an over-cost tag's raw-text mode whatever its
  ending, and normalizes decimal character references that Python could not convert.
- A missing stdlib symbol turns the view off; it never breaks the import."""
from tests import support  # noqa: F401

import base64
import binascii
import codecs
import email
import html
import random
import subprocess
import sys
import time
import unittest
from unittest import mock

import htmlview
import mime
from tests import coverage_shapes as C
from tests import messages as M
from tests.fakegmail import FakeGmail


def fake_of(raw: bytes, **kw):
    f = FakeGmail(**kw)
    mid = f.add_message(raw)
    return f, mid, f.messages[mid]["payload"]


def predict(raw: bytes, payload=None, **kw):
    f, mid, own = fake_of(raw, **kw)
    return mime.predict_view(payload if payload is not None else own,
                             lambda att: f._messages_attachments_get("me", mid, att)["data"], size_estimate=len(raw))


def logo_related(b="R") -> str:
    return (f'Content-Type: multipart/related; boundary="{b}"\n\n--{b}\nContent-Type: text/html\n\n'
            '<p>receipt</p><img src="cid:logo@x">\n'
            + C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="logo.png", b=b) + f"--{b}--\n")


def set_header(node: dict, name: str, value: str) -> None:
    for h in node["headers"]:
        if h["name"].lower() == name.lower():
            h["value"] = value


class EightBitStructure(unittest.TestCase):
    def test_an_8bit_boundary(self):
        raw = M.raw_message(C.HEAD + logo_related())
        _, _, payload = fake_of(raw)
        self.assertTrue(predict(raw, payload).ok)
        set_header(payload, "Content-Type", 'multipart/related; boundary="Ré"')     # as Gmail shows UTF-8
        pred = predict(raw, payload)
        self.assertEqual((pred.ok, pred.reason, pred.embedded), (False, "header-unreadable", []))
        for value in ('multipart/related; boundary="R1 "', 'multipart/related; boundary="R1\t2"',
                      'multipart/related; boundary="R1"; name="é.txt"'):
            set_header(payload, "Content-Type", value)
            self.assertFalse(predict(raw, payload).ok, value)

    def test_the_view_cannot_split_on_one(self):
        raw = (C.HEAD + logo_related("Ré")).replace("\n", "\r\n").encode("utf-8")
        v = htmlview.build_view(raw)
        self.assertIn("no-displayable-body", v.warnings)

    def test_an_8bit_content_id(self):
        raw = M.raw_message(C.HEAD + logo_related())
        _, _, payload = fake_of(raw)
        set_header(payload["parts"][1], "Content-ID", "<logoé@x>")
        self.assertFalse(predict(raw, payload).ok)


class StructureAmbiguous(unittest.TestCase):
    def test_a_boundary_inside_an_attached_message(self):
        inner = ("From: a@example.test\nSubject: fwd\nMIME-Version: 1.0\n"
                 'Content-Type: multipart/mixed; boundary="Y"\n\n--Y\nContent-Type: text/plain\n\nold\n--Y--\n')
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/related; boundary="X"\n\n--X\nContent-Type: text/html\n\n'
                            '<img src="cid:logo@x">\n--X\nContent-Type: message/rfc822\n\n' + inner
                            + C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="logo.png", b="X") + "--X--\n")
        _, _, payload = fake_of(raw, rfc822_mode="parsed")
        self.assertTrue(predict(raw, payload, rfc822_mode="parsed").ok)
        message = payload["parts"][1]
        inner_root = next(n for n in message["parts"] if n.get("parts")) if message.get("parts") else None
        self.assertIsNotNone(inner_root)
        for value in ('multipart/mixed; boundary="X"', 'multipart/mixed; boundary="X--"', "multipart/mixed; boundary=?"):
            set_header(inner_root, "Content-Type", value)
            pred = predict(raw, payload, rfc822_mode="parsed")
            self.assertEqual((pred.ok, pred.reason, pred.sections), (False, "structure-ambiguous", []), value)

    def test_every_part_is_listed(self):
        # nested equal boundaries: the view may read another tree than Gmail's
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="X"\n\n--X\n' + logo_related("X")
                            + "--X\nContent-Type: text/plain\n\nIMPORTANT terms\n--X--\n")
        f, mid, payload = fake_of(raw)
        parts, why = mime.enumerate_message(payload, size_estimate=len(raw))
        self.assertEqual(why, "structure-ambiguous")
        listed = {p.path for p in parts}
        leaves = set()
        stack = [(payload, ())]
        while stack:
            node, path = stack.pop()
            kids = node.get("parts") or []
            if not kids and (node.get("body") or {}).get("size"):
                leaves.add(path)
            stack.extend((k, path + (i,)) for i, k in enumerate(kids))
        self.assertEqual(listed, leaves)                 # nothing counts as body, nothing is inline
        self.assertFalse(any(p.inline for p in parts))


class DecodingIsBounded(unittest.TestCase):
    def test_uuencoded_sections_are_never_decoded(self):
        # every spelling Message.get_payload reads as uuencode (it reads the parsed token)
        small = b"begin 644 x\n" + b"M\n" * 2_000 + b"`\nend\n"
        for cte in ("x-uuencode", "X-UUencode", "x-uuencode ", "x-uuencode (legacy)", "(c) x-uuencode",
                    "x-uuencode;", "uue (old)", "uuencode\t(c)", "x-uue x"):
            for ctype in ("text/html", "text/plain"):
                raw = M.raw_message(C.HEAD + f"Content-Type: {ctype}\nContent-Transfer-Encoding: {cte}\n\n") + small
                parsed = email.message_from_bytes(raw, policy=htmlview.view_policy())
                self.assertIn(htmlview._transfer_encoding(parsed), htmlview._UUENCODE, cte)    # the decoder's reading
                v = htmlview.build_view(raw)
                self.assertIn("section-encoding-unsupported", v.warnings, cte)
                self.assertIn("no-displayable-body", v.warnings, cte)
        big = b"begin 644 x\n" + b"M\n" * 3_000_000 + b"`\nend\n"              # 45 bytes out per 2 in
        raw = M.raw_message(C.HEAD + "Content-Type: text/html\nContent-Transfer-Encoding: x-uuencode (legacy)\n\n") + big
        t = time.monotonic()
        v = htmlview.build_view(raw)
        self.assertLess(time.monotonic() - t, 3.0)
        self.assertNotIn(b"\x00" * 45, v.page)

    def test_a_uuencoded_image_is_not_embedded(self):
        uu = ("begin 644 l.png\n" + "".join(binascii.b2a_uu(C.PNG[i:i + 45]).decode() for i in range(0, len(C.PNG), 45))
              + "`\nend\n")
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/related; boundary="R"\n\n--R\nContent-Type: text/html\n\n'
                            '<img src="cid:logo@x">\n--R\nContent-Type: image/png\nContent-ID: <logo@x>\n'
                            f"Content-Transfer-Encoding: x-uuencode\n\n{uu}--R--\n")
        v = htmlview.build_view(raw)
        self.assertEqual(v.embedded, [])
        self.assertIn("cid-encoding-unsupported", v.warnings)
        self.assertFalse(predict(raw).ok)                     # the prediction calls the encoding unreadable

    def test_a_slow_charset_stops_at_the_deadline(self):
        for charset, body in (("iso-8859-6", b"\xa1" * (18 << 20)), ("utf-16-le", b"\x41\xd8" * (9 << 20)),
                              ("utf-16", b"\xff\xfe" + b"\x41\xd8" * (9 << 20))):
            raw = M.raw_message(C.HEAD + f"Content-Type: text/plain; charset={charset}\n\n") + body
            with mock.patch.object(htmlview, "VIEW_SECONDS", 0.6):
                t = time.monotonic()
                with self.assertRaises(htmlview.ViewError) as cm:
                    htmlview.build_view(raw)
                self.assertEqual(cm.exception.code, "view-too-slow", charset)
                self.assertLess(time.monotonic() - t, 1.8, charset)

    def test_an_oversized_section_is_refused_before_decoding(self):
        raw = M.raw_message(C.HEAD + "Content-Type: text/plain; charset=iso-8859-6\n\n") + b"\xa1" * (24 << 20)
        t = time.monotonic()
        with self.assertRaises(htmlview.ViewError) as cm:
            htmlview.build_view(raw)
        self.assertEqual(cm.exception.code, "html-too-large")
        self.assertLess(time.monotonic() - t, 2.5)

    def test_wide_unicode_steps_give_the_one_shot_text(self):
        rng = random.Random(16)
        with mock.patch.object(htmlview, "_DECODE_CHUNK", 3):
            for name in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"):
                for _ in range(400):
                    data = bytes(rng.randrange(256) for _ in range(rng.randrange(4, 60)))
                    if rng.random() < 0.4:
                        data = rng.choice([codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE, codecs.BOM_UTF32_LE,
                                           codecs.BOM_UTF32_BE]) + data
                    self.assertEqual(htmlview._decode_bounded(data, name, time.monotonic() + 60),
                                     data.decode(name, errors="replace"), (name, data))

    def test_base64_bodies_decode_as_get_payload_does(self):
        rng = random.Random(23)
        for _ in range(300):
            body = base64.b64encode(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 90))))
            cut = bytearray()
            for b in body:                      # random line breaks and stray bytes, as hostile mail has
                cut.append(b)
                if rng.random() < 0.2:
                    cut += rng.choice([b"\r\n", b"\n", b"\r", b"\x0b", b"\x0c", b"\x1c", b" ", b"*", b"="])
            raw = M.raw_message(C.HEAD + "Content-Type: text/plain\nContent-Transfer-Encoding: base64\n\n") + bytes(cut) + b"\r\n"
            a = email.message_from_bytes(raw, policy=htmlview.view_policy())
            b2 = email.message_from_bytes(raw, policy=htmlview.view_policy())
            self.assertEqual(htmlview._payload_bytes(a), b2.get_payload(decode=True))
            self.assertEqual([type(d) for d in a.defects], [type(d) for d in b2.defects])

    def test_stepwise_decoding_is_the_same_text(self):
        rng = random.Random(77)
        with mock.patch.object(htmlview, "_DECODE_CHUNK", 7):
            for name in ("iso8859-6", "cp1253", "cp874", "koi8-r", "mac-roman", "tis-620", "hp-roman8", "cp437"):
                self.assertTrue(htmlview._single_byte(codecs.lookup(name).name), name)
                for _ in range(100):
                    data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
                    self.assertEqual(htmlview._decode_bounded(data, codecs.lookup(name).name, time.monotonic() + 60),
                                     data.decode(name, errors="replace"), name)
        for name in ("utf-8", "shift_jis", "iso2022_jp", "utf-16", "gb18030"):
            self.assertFalse(htmlview._single_byte(codecs.lookup(name).name), name)


class SanitizerSteps(unittest.TestCase):
    def test_an_unfinished_start_tag_is_scanned_once_per_pass(self):
        doc = "<p>x</p><x" + " a" * 3_000_000                    # 6 MB, no ">"
        budget = htmlview._budget(10**9, deadline=time.monotonic() - 1)
        t = time.monotonic()
        with self.assertRaises(htmlview.ViewError):
            htmlview.sanitize_html(doc, htmlview.CidScope({}), {}, [], budget)
        self.assertLess(time.monotonic() - t, 0.6)
        out, _ = htmlview.sanitize_html("<p>x</p><img src=x alt=y", htmlview.CidScope({}), {}, [])
        self.assertEqual(out, "<p>x</p>")                          # html.parser's own answer: dropped

    def test_an_over_cost_tag_keeps_raw_text_mode_whatever_its_ending(self):
        # an over-cost start tag renders exactly as the same tag without attributes: its content
        # stays raw text (dropped with script, textarea, title; CSS text inside style)
        many = "/ " * 260_000
        rest = 'var s = "<b>shown</b>"; <img src="cid:logo@x"></{tag}><p>after</p>'
        cids = htmlview.CidScope({"logo@x": htmlview.CidImage("logo@x", "image/png", (1,), 66, b"x")})
        for tag in ("script", "style", "textarea", "title"):
            plain_embedded = set()
            plain, _ = htmlview.sanitize_html(f"<{tag}>" + rest.format(tag=tag), cids, {}, [], embedded=plain_embedded)
            self.assertNotIn("<b>", plain, tag)
            for ending in ("a=b/>", "a=/>", "/>", ">"):
                embedded = set()
                out, _ = htmlview.sanitize_html(f"<{tag}{many}{ending}" + rest.format(tag=tag), cids, {}, [],
                                                embedded=embedded)
                self.assertEqual((out, embedded), (plain, plain_embedded), (tag, ending))
                self.assertIn("<p>after</p>", out, (tag, ending))


class LongCharacterReferences(unittest.TestCase):
    def test_the_view_builds_what_the_prediction_accepted(self):
        long_ref = "&#" + "0" * 4400 + "65;"
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="B"\n\n'
                            f'--B\nContent-Type: text/html\n\n<p title="{long_ref}">Total: {long_ref}</p>\n'
                            + C.part("application/pdf", M.PDF, disp="attachment", name="invoice.pdf", b="B") + "--B--\n")
        self.assertTrue(predict(raw).ok)
        v = htmlview.build_view(raw)
        self.assertIn(b'<p title="A">Total: A</p>', v.page)

    def test_normalizing_keeps_html_unescape_s_reading(self):
        refs = ["&#0065;", "&#00000000000065", "&#1114111;", "&#1114112;", "&#99999999;", "&#0;", "&#000;", "&#0000x",
                "&#12345678901234567890;", "&#x0041;", "&#65", "&#065a", "&#00000065;b", "&#", "&#;", "&#00000000"]
        for ref in refs:
            norm = htmlview._LONG_DECIMAL_REF.sub("&#65533", htmlview._DECIMAL_REF_ZEROS.sub("&#", ref))
            self.assertEqual(html.unescape(norm), html.unescape(ref), ref)


class TheGuardNeverBreaksTheImport(unittest.TestCase):
    def test_missing_symbols_turn_the_view_off(self):
        script = ("import html.parser, email.feedparser\n"
                  "del html.parser.locatetagend\n"
                  "del html.parser.HTMLParser.check_for_whole_start_tag\n"
                  "del email.feedparser.BufferedSubFile.readline\n"
                  "import htmlview, mime\n"
                  "print(sorted(htmlview.STDLIB_CHANGED))\n")
        r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60,
                           cwd=str(support.REPO))
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        for name in ("html.parser.locatetagend", "html.parser.HTMLParser.check_for_whole_start_tag",
                     "email.feedparser.BufferedSubFile.readline"):
            self.assertIn(name, r.stdout)


if __name__ == "__main__":
    unittest.main()
