"""Fixes from the sixth code and security reviews (2026-10-05).

- The view reads a part's transfer encoding exactly as Message.get_payload does, so no spelling
  of uuencode reaches the decoder; a uuencoded body section is left out with a warning.
- Two regular expressions that kept backtracking state per repetition over attacker-sized
  input are replaced by equivalents that keep none: the tag-name match (html.parser's
  tagfind_tolerant has a loop over separators) and the data: image check (its parameters).
- UTF-16 and UTF-32 bodies decode in steps; a section over the size budget is refused before
  any charset decoding; base64 line breaks are removed in one step (tests in test_review5_d16).
- A raw-text element written self-closing keeps its raw text, as HTML (and the over-cost path)
  does.
- Any refusal of the prediction leaves no section counted as body, so every part is listed.
- The attached-message boundary check unfolds and caps the values it reads.
- A missing stdlib base class only turns the view off."""
from tests import support  # noqa: F401

import base64
import html.parser
import random
import re
import subprocess
import sys
import time
import unittest

import htmlview
import mime
from tests import coverage_shapes as C
from tests import messages as M
from tests.fakegmail import FakeGmail
from tests.test_review5_d16 import logo_related, set_header

STOCK_DATA_IMAGE = re.compile(
    r"^data:image/(png|jpeg|jpg|gif|webp|bmp|svg\+xml)(;[a-z0-9._=-]+)*;base64,[A-Za-z0-9+/=]*$", re.I)


def fake_of(raw: bytes, **kw):
    f = FakeGmail(**kw)
    mid = f.add_message(raw)
    return f, mid, f.messages[mid]["payload"]


def predict(raw: bytes, payload=None, **kw):
    f, mid, own = fake_of(raw, **kw)
    return mime.predict_view(payload if payload is not None else own,
                             lambda att: f._messages_attachments_get("me", mid, att)["data"], size_estimate=len(raw))


class PatternsKeepNoState(unittest.TestCase):
    def test_the_data_image_check_matches_the_old_one(self):
        rng = random.Random(61)
        atoms = list("ab;=,.-_09+/") + [";base64,", ";base64", "base64,", ";charset=utf-8", "AAAA", "%", " "]
        for _ in range(50_000):
            s = "data:image/" + rng.choice(["png", "PNG", "jpeg", "svg+xml", "gif", "x"]) + "".join(
                rng.choice(atoms) for _ in range(rng.randrange(0, 12)))
            self.assertEqual(bool(htmlview._DATA_IMAGE_RE.match(s)), bool(STOCK_DATA_IMAGE.match(s)), s)

    def test_the_tag_name_matches_html_parser_s(self):
        rng = random.Random(62)
        for _ in range(50_000):
            s = "<" + rng.choice("aZx") + "".join(rng.choice(list("ab \t\n/>=\"'xyz-:")) for _ in range(rng.randrange(15)))
            self.assertEqual(htmlview._TAGNAME.match(s, 1).group(0), html.parser.tagfind_tolerant.match(s, 1).group(1), s)

    def test_long_runs_are_quick(self):
        cases = ['<x' + "/ " * 2_000_000 + ">x", "<p>a</p></x" + "\t" * 4_000_000 + ">",
                 '<img src="data:image/png' + ";a" * 2_000_000 + ';base64,AAAA">']
        for doc in cases:
            t = time.monotonic()
            htmlview.sanitize_html(doc, htmlview.CidScope({}), {}, [])
            self.assertLess(time.monotonic() - t, 3.0, doc[:12])


class RawTextWrittenSelfClosing(unittest.TestCase):
    def test_it_keeps_its_raw_text(self):
        cids = htmlview.CidScope({"logo@x": htmlview.CidImage("logo@x", "image/png", (1,), 66, b"x")})
        for tag in ("script", "style", "textarea", "title", "xmp", "noembed"):
            for written in (f"<{tag}/>", f"<{tag} />", f'<{tag} a="1" />'):
                rest = f'var s = "<b>shown</b>"; <img src="cid:logo@x"></{tag}><p>after</p>'
                plain_embedded, embedded = set(), set()
                plain, _ = htmlview.sanitize_html(f"<{tag}>" + rest, cids, {}, [], embedded=plain_embedded)
                out, _ = htmlview.sanitize_html(written + rest, cids, {}, [], embedded=embedded)
                self.assertEqual((out, embedded), (plain, plain_embedded), written)
                self.assertNotIn("<b>", out, written)


class EveryRefusalListsEverything(unittest.TestCase):
    def test_a_refused_node_with_a_nested_equal_boundary(self):
        # round 6's shape: the related part is refused for its own headers, and nests an equal boundary
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="X"\n\n--X\n'
                            + logo_related("X").replace("Content-Type: multipart/related;",
                                                        "Content-Disposition: inline (c)\nContent-Type: multipart/related;")
                            + "--X\nContent-Type: text/plain\n\nIMPORTANT terms\n--X--\n")
        f, mid, payload = fake_of(raw)
        parts, why = mime.enumerate_message(payload, size_estimate=len(raw))
        self.assertIn(why, ("header-unreadable", "structure-ambiguous"))
        leaves = set()
        stack = [(payload, ())]
        while stack:
            node, path = stack.pop()
            kids = node.get("parts") or []
            if not kids and (node.get("body") or {}).get("size"):
                leaves.add(path)
            stack.extend((k, path + (i,)) for i, k in enumerate(kids))
        self.assertEqual({p.path for p in parts}, leaves)
        self.assertFalse(any(p.inline for p in parts))

    def test_header_unreadable_counts_no_body(self):
        raw = C.related('<img src="cid:logo@x">',
                        C.part("image/png", C.PNG, cid="logo@x", disp="inline (c)", name="logo.png"))
        pred = predict(raw)
        self.assertEqual((pred.ok, pred.reason, pred.sections, pred.alternatives), (False, "header-unreadable", [], []))


class AttachedMessages(unittest.TestCase):
    def forwarded(self, inner_ctype: str) -> bytes:
        inner = ("From: a@example.test\nSubject: fwd\nMIME-Version: 1.0\n"
                 f"Content-Type: {inner_ctype}\n\n--Y\nContent-Type: text/plain\n\nold\n--Y--\n")
        return M.raw_message(C.HEAD + 'Content-Type: multipart/related; boundary="X"\n\n--X\nContent-Type: text/html\n\n'
                             '<img src="cid:logo@x">\n--X\nContent-Type: message/rfc822\n\n' + inner
                             + C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="logo.png", b="X") + "--X--\n")

    def inner_root(self, payload):
        return next(n for n in payload["parts"][1]["parts"] if n.get("parts"))

    def test_a_folded_inner_content_type_is_read_unfolded(self):
        raw = self.forwarded('multipart/alternative;\n\tboundary="Y"')
        pred = predict(raw, rfc822_mode="parsed")
        self.assertEqual((pred.ok, pred.embedded), (True, [(2,)]))

    def test_a_repeated_or_oversized_inner_content_type(self):
        raw = self.forwarded('multipart/mixed; boundary="Y"')
        _, _, payload = fake_of(raw, rfc822_mode="parsed")
        node = self.inner_root(payload)
        node["headers"].append({"name": "Content-Type", "value": 'multipart/mixed; boundary="Y"'})
        self.assertEqual(predict(raw, payload, rfc822_mode="parsed").reason, "structure-ambiguous")
        node["headers"].pop()
        set_header(node, "Content-Type", 'multipart/mixed; boundary="Y"; x="' + "a" * 3000 + '"')
        self.assertEqual(predict(raw, payload, rfc822_mode="parsed").reason, "structure-ambiguous")


class MissingBaseClasses(unittest.TestCase):
    def test_the_import_survives(self):
        # (BytesFeedParser is imported by the stdlib's own email.parser, so without it the
        # email package itself would not import; these two only the view relies on)
        script = ("import html.parser, email.feedparser\n"
                  "del email.feedparser.BufferedSubFile\n"
                  "del html.parser.HTMLParser\n"
                  "import htmlview, mime\n"
                  "print(len(htmlview.STDLIB_CHANGED) > 0)\n")
        r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60,
                           cwd=str(support.REPO))
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "True"), r.stderr[-800:])


if __name__ == "__main__":
    unittest.main()
