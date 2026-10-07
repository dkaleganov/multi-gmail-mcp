"""Fixes from the fourth code and security reviews (2026-10-05).

- A multipart's boundary must be written plainly and read the same way by the view's parser;
  Gmail must split exactly the parts whose headers say multipart; nested boundaries may not
  equal or prefix each other; a structural header may not appear twice. Otherwise Gmail and
  the view may build different trees, so the prediction is unavailable (nothing inline).
- The sanitizer reads the clock by work done (a long construct counts per KiB), so many large
  tags cannot run past the deadline between checks; a start tag over MAX_TAG_COST keeps its
  element and the element's raw-text handling, losing only its attributes.
- Single steps over attacker-sized input are capped: a cid: reference, an Authentication-Results
  value.
- The view refuses to run when the stdlib internals it copies have changed."""
from tests import support  # noqa: F401

import base64
import random
import time
import unittest
from unittest import mock

import htmlview
import mime
from tests import coverage_shapes as C
from tests import messages as M
from tests.fakegmail import FakeGmail
from tests.test_legacy_contract import fenced_part, trusted_part


def fake_of(raw: bytes):
    f = FakeGmail()
    mid = f.add_message(raw)
    return f, mid, f.messages[mid]["payload"]


def predict(raw: bytes, payload=None):
    f, mid, own = fake_of(raw)
    return mime.predict_view(payload if payload is not None else own,
                             lambda att: f._messages_attachments_get("me", mid, att)["data"], size_estimate=len(raw))


def related_with(param: str, delimiter: str) -> bytes:
    """A related part whose Content-Type ends `; boundary<param>`, split on `--<delimiter>`."""
    d = delimiter
    return M.raw_message(
        C.HEAD + f"Content-Type: multipart/related{'; boundary' + param}\n\n"
        f"--{d}\nContent-Type: text/html\n\n<p>receipt</p><img src=\"cid:logo@x\">\n"
        f"--{d}\nContent-Type: image/png\nContent-ID: <logo@x>\nContent-Disposition: inline; filename=\"logo.png\"\n"
        f"Content-Transfer-Encoding: base64\n\n{base64.encodebytes(C.PNG).decode()}--{d}--\n")


# (the parameter as written, the delimiter compat32, the fake's stand-in for Gmail, splits on)
SPELLINGS = [
    ('="=?utf-8?q?R1?="', "=?utf-8?q?R1?="),
    ('="R\\1"', "R\\1"),
    ('="R1"x', '"R1"x'),
    ("=R1 R2", "R1 R2"),
    ('="R1""R2"', 'R1""R2'),
    ("=R1\\", "R1\\"),
    ("*=unicode_escape''R\\x31", "R1"),
    ("='R1'", "'R1'"),
    ("=----=_Part_0_1.2", "----=_Part_0_1.2"),
]


class BoundariesReadTheSame(unittest.TestCase):
    def assertUnavailable(self, raw, payload=None, reason="header-unreadable"):
        pred = predict(raw, payload)
        self.assertEqual((pred.ok, pred.reason, pred.embedded), (False, reason, []))
        if reason == "structure-ambiguous":
            self.assertEqual((pred.sections, pred.alternatives), ([], []))    # every part listed

    def test_every_hostile_spelling(self):
        for param, delimiter in SPELLINGS:
            with self.subTest(param):
                raw = related_with(param, delimiter)
                self.assertTrue(predict(related_with('="R1"', "R1")).ok)
                self.assertUnavailable(raw)

    def test_ordinary_spellings_still_predict(self):
        for param, delimiter in (('="000000000000a1b2c30605f1d2e3"', "000000000000a1b2c30605f1d2e3"),
                                 ('="----=_NextPart_000_0012_01D9A1B2.C3D4E5F0"', "----=_NextPart_000_0012_01D9A1B2.C3D4E5F0"),
                                 ('="Apple-Mail=_A1B2C3D4-E5F6"', "Apple-Mail=_A1B2C3D4-E5F6"),
                                 ("=simple_boundary-1.2", "simple_boundary-1.2"),
                                 ('="===============1234567890=="', "===============1234567890=="),
                                 ('="a b c"', "a b c")):
            with self.subTest(param):
                pred = predict(related_with(param, delimiter))
                self.assertEqual((pred.ok, pred.embedded), (True, [(1,)]))

    def test_the_tools_save_the_logo(self):
        h = support.ServerHarness()
        try:
            f = h.fake("alpha")
            mid = f.add_message(related_with(*SPELLINGS[0]))
            read = fenced_part(h.server.read_email("alpha", mid))
            self.assertNotIn(", inline)", read)
            self.assertIn(mime.inline_note("header-unreadable"), read)
            out = h.server.save_attachments("alpha", mid)
            # the related node reads as an attachment, so its HTML is listed and saved as well
            self.assertIn("saved=2 already-present=0 skipped=0 refused=0 failed=0", trusted_part(out))
            self.assertNotIn("inline-excluded", fenced_part(out))
        finally:
            h.close()
            support.assert_isolated(self)

    def test_a_multipart_gmail_shows_as_one_part(self):
        # the reviewers' reverse case: Gmail keeps a leaf where the view splits
        raw = M.raw_message(
            C.HEAD + 'Content-Type: multipart/mixed; boundary="O"\n\n--O\n'
            'Content-Type: multipart/related; boundary="R"\n\n--R\nContent-Type: text/html\n\n<img src="cid:logo@x">\n'
            + C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="logo.png") + "--R--\n"
            '--O\nContent-Type: multipart/mixed; boundary="Q\\1"\n\n--Q1\nContent-Type: text/plain\n\nx\n--Q1--\n--O--\n')
        self.assertUnavailable(raw)

    def test_gmail_and_the_headers_disagree_on_a_split(self):
        raw = C.related('<img src="cid:logo@x">', C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="l.png"))
        _, _, payload = fake_of(raw)
        self.assertTrue(predict(raw, payload).ok)
        related = payload["parts"][1]
        kids = related.pop("parts")                 # a multipart Gmail shows as one part
        related["body"] = {"size": 10, "data": "eA"}
        self.assertUnavailable(raw, payload, "structure-ambiguous")
        related["parts"] = kids
        payload["parts"][0]["parts"] = [dict(kids[0])]    # parts under a text/plain node
        self.assertUnavailable(raw, payload, "structure-ambiguous")

    def test_nested_boundaries_that_match_each_other(self):
        for outer, inner in (("X", "X"), ("X", "X--"), ("X", "XY"), ("XY", "X")):
            with self.subTest((outer, inner)):
                raw = M.raw_message(
                    C.HEAD + f'Content-Type: multipart/mixed; boundary="{outer}"\n\n--{outer}\n'
                    f'Content-Type: multipart/related; boundary="{inner}"\n\n--{inner}\nContent-Type: text/html\n\n'
                    '<img src="cid:logo@x">\n' + C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="l.png",
                                                        b=inner) + f"--{inner}--\n--{outer}--\n")
                self.assertFalse(predict(raw).ok)

    def test_a_structural_header_twice(self):
        for extra in ("Content-Transfer-Encoding: quoted-printable\n", "Content-ID: <other@x>\n",
                      "Content-Disposition: attachment\n"):
            with self.subTest(extra):
                img = C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="l.png").replace(
                    "Content-Transfer-Encoding: base64\n", "Content-Transfer-Encoding: base64\n" + extra)
                self.assertUnavailable(C.related('<img src="cid:logo@x">', img))


class TheSanitizerCountsWork(unittest.TestCase):
    def test_many_large_tags_stop_at_the_deadline(self):
        for unit in ("<x" + " a" * 99_999 + ">", "<script" + " a" * 99_999 + "></script>"):
            budget = htmlview._budget(10**9, deadline=time.monotonic() - 1)
            t = time.monotonic()
            with self.assertRaises(htmlview.ViewError) as cm:
                htmlview.sanitize_html(unit * 120, htmlview.CidScope({}), {}, [], budget)
            self.assertEqual(cm.exception.code, "view-too-slow")
            self.assertLess(time.monotonic() - t, 0.6, unit[:8])

    def test_text_and_comments_count_by_length(self):
        for doc in ("<p>" + "x" * 400_000 + "</p>", "<!--" + "x" * 400_000 + "-->"):
            budget = htmlview._budget(10**9, deadline=time.monotonic() - 1)
            with self.assertRaises(htmlview.ViewError):
                htmlview.sanitize_html(doc * 2, htmlview.CidScope({}), {}, [], budget)

    def test_an_element_keeps_its_rules_without_its_attributes(self):
        many = "/ " * 260_000                       # over MAX_TAG_COST, within PREDICT_MAX_INPUT
        cases = {
            "script": f'<script{many}>var secret = "<b>shown</b>";</script><p>after</p>',
            "textarea": f"<textarea{many}><b>hidden</b></textarea><p>after</p>",
            "style": f'<style{many}>p{{color:red}} <img src="cid:logo@x"></style><p>after</p>',
        }
        cids = htmlview.CidScope({"logo@x": htmlview.CidImage("logo@x", "image/png", (1,), 66, b"x")})
        for name, doc in cases.items():
            warnings, embedded = [], set()
            out, _ = htmlview.sanitize_html(doc, cids, {}, warnings, embedded=embedded)
            self.assertIn("html-attributes-dropped", warnings, name)
            self.assertIn("<p>after</p>", out, name)
            self.assertNotIn("shown", out, name)
            self.assertNotIn("hidden", out, name)
            self.assertEqual(embedded, set(), name)

    def test_a_large_data_image_still_renders(self):
        data = base64.b64encode(bytes(range(256)) * 20_000).decode()      # 6.8 MB: about 107,000 "/"
        doc = f'<p>x</p><img src="data:image/png;base64,{data}">'
        warnings = []
        out, _ = htmlview.sanitize_html(doc, htmlview.CidScope({}), {}, warnings)
        self.assertNotIn("html-attributes-dropped", warnings)
        self.assertIn('<img src="data:image/png;base64,', out)

    def test_a_cid_reference_longer_than_any_content_id(self):
        cids = htmlview.CidScope({"logo@x": htmlview.CidImage("logo@x", "image/png", (1,), 66, b"x")})
        warnings, embedded = [], set()
        t = time.monotonic()
        htmlview.sanitize_html('<img src="cid:' + "%" * 2_000_000 + '">', cids, {}, warnings, embedded=embedded)
        self.assertLess(time.monotonic() - t, 1.0)
        self.assertIn("missing-cid", warnings)
        self.assertEqual(embedded, set())


class SingleStepsAreCapped(unittest.TestCase):
    def test_a_huge_authentication_results_value(self):
        raw = M.raw_message("From: a@example.test\nSubject: s\nAuthentication-Results: mx.google.com;"
                            + ";" * 3_000_000 + "\nContent-Type: text/plain\n\nx\n")
        t = time.monotonic()
        v = htmlview.build_view(raw)
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertIn("unavailable (malformed)", v.page.decode())


class TheStdlibGuard(unittest.TestCase):
    def test_this_python_matches_the_copies(self):
        self.assertEqual(htmlview.STDLIB_CHANGED, [])

    def test_a_changed_stdlib_turns_the_view_off(self):
        raw = C.related('<img src="cid:logo@x">', C.part("image/png", C.PNG, cid="logo@x", disp="inline", name="l.png"))
        before = predict(raw)
        with mock.patch.object(htmlview, "STDLIB_CHANGED", ["html.parser.HTMLParser.goahead"]):
            with self.assertRaises(htmlview.ViewError) as cm:
                htmlview.build_view(raw)
            self.assertEqual(cm.exception.code, "stdlib-changed")
            after = predict(raw)
        self.assertEqual((after.ok, after.reason, after.embedded), (False, "stdlib-changed", []))
        self.assertEqual((after.sections, after.alternatives), (before.sections, before.alternatives))


class RandomBoundaries(unittest.TestCase):
    """Random trees with random boundary spellings: whenever the prediction succeeds, the view
    builds the message and embeds exactly the predicted parts."""

    def make(self, rng) -> bytes:
        n = [0]

        def spelled():
            n[0] += 1
            name = f"B{n[0]}x{rng.randrange(10**6)}"
            kind = rng.choice(["plain"] * 6 + ["token", "hostile"])
            if kind == "plain":
                return f'="{name}"', name
            if kind == "token":
                return f"={name}", name
            param, delim = rng.choice(SPELLINGS)
            return param.replace("R1", name), delim.replace("R1", name)

        def node(depth):
            kind = rng.choice(["related", "related", "mixed", "alternative"] if depth < 3 else ["leaf"])
            if kind == "leaf":
                return "Content-Type: text/plain\n\nleaf\n"
            param, d = spelled()
            if kind == "related":
                kids = ['Content-Type: text/html\n\n<p>hi</p><img src="cid:logo@x">\n',
                        "Content-Type: image/png\nContent-ID: <logo@x>\nContent-Disposition: inline\n"
                        "Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(C.PNG).decode()]
            else:
                kids = [node(depth + 1) for _ in range(rng.randrange(1, 3))]
            body = "".join(f"--{d}\n{k}" for k in kids)
            return f"Content-Type: multipart/{kind}; boundary{param}\n\n{body}--{d}--\n"

        return M.raw_message(C.HEAD + node(0))

    def test_prediction_ok_implies_the_same_view(self):
        rng = random.Random(41005)
        accepted = embedded = 0
        for i in range(600):
            raw = self.make(rng)
            pred = predict(raw)
            if not pred.ok:
                continue
            accepted += 1
            try:
                view = htmlview.build_view(raw)
            except htmlview.ViewError as e:
                self.fail(f"case {i}: prediction ok, view refused: {e.code}\n{raw[:500]!r}")
            self.assertEqual(set(pred.embedded), set(view.embedded), f"case {i}\n{raw[:500]!r}")
            embedded += bool(pred.embedded)
        self.assertGreater(accepted, 150)
        self.assertGreater(embedded, 100)


if __name__ == "__main__":
    unittest.main()
