"""Fixes from the third code and security reviews (2026-10-05).

- "Prediction ok implies the view succeeds" holds through time: the prediction bounds the
  view's parse by Gmail's sizeEstimate and the deepest part, and a message in which nothing can
  be embedded must still fit the view's body budget.
- The view's deadline is hard: it is checked inside a header block, parts keep only the headers
  the view reads, parts are counted while parsing, the sanitizer counts every construct (and
  drops a start tag with too many attributes), and character references are capped.
- The adapter refuses what Gmail and the view's parser may read differently: a comment in a
  structural value, a second boundary however written, a nonstandard transfer encoding, too
  many structural headers, and a node Gmail labels message/* that its headers do not.
- Long recipient lists show their encoded words decoded."""
from tests import support  # noqa: F401

import base64
import email.feedparser
import time
import unittest
from unittest import mock

import htmlview
import mime
from tests import coverage_shapes as C
from tests import messages as M
from tests import test_split_sections as S
from tests.fakegmail import FakeGmail
from tests.test_legacy_contract import fenced_part, trusted_part
from tests.test_review2_d16 import logo_related, message, nested


def payload_of(raw: bytes) -> dict:
    f = FakeGmail()
    return f.messages[f.add_message(raw)]["payload"]


def deep_message(levels: int = 19, filler: str = "") -> bytes:
    """The reviewers' shape: a related HTML body with an inline logo, beside `levels` nested
    containers holding a non-body part (`filler` is its body)."""
    leaf = f"Content-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"data.bin\"\n\n{filler}x\n"
    return M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="O"\n\n--O\n' + logo_related()
                         + "--O\n" + nested(leaf, levels) + "--O--\n")


def timed(fn):
    t = time.monotonic()
    try:
        return fn(), time.monotonic() - t
    except htmlview.ViewError as e:
        return e.code, time.monotonic() - t


class ThePredictionBoundsTheParse(unittest.TestCase):
    def test_a_large_deep_message_is_not_predicted(self):
        raw = deep_message()
        payload = payload_of(raw)
        small = mime.enumerate_message(payload, size_estimate=len(raw))
        large = mime.enumerate_message(payload, size_estimate=20_000_000)    # the reviewers' 20 MB
        self.assertEqual([(p.index, p.name) for p in small[0]], [(p.index, p.name) for p in large[0]])
        self.assertEqual(([p.inline for p in small[0]], small[1]), ([True, False], None))
        self.assertEqual(([p.inline for p in large[0]], large[1]), ([False, False], "too-large-to-predict"))

    def test_the_bound_grows_with_depth(self):
        def fits(size, depth):
            return htmlview.parse_cost_failure(size, depth) is None
        mib = 1024 * 1024
        self.assertTrue(fits(21 * mib, 3) and not fits(22 * mib, 3))
        self.assertTrue(fits(10 * mib, 20) and not fits(11 * mib, 20))
        for bad in (None, -1, "123", True, 1.5):
            self.assertEqual(htmlview.parse_cost_failure(bad, 1), "size-unknown")

    def test_nothing_embeddable_still_needs_a_body_the_view_can_build(self):
        for size, ok in ((400_000, True), (2_000_000, False)):
            raw = M.raw_message(C.HEAD + "Content-Type: text/plain; charset=utf-8\n\n" + "a" * size + "\n")
            pred = mime.predict_view(payload_of(raw), size_estimate=len(raw))
            self.assertEqual((pred.ok, pred.reason, pred.sections), (ok, None if ok else "too-large-to-predict", [()]))

    def test_without_a_size_nothing_is_inline(self):
        payload = payload_of(deep_message(2))
        pred = mime.predict_view(payload, size_estimate=None)
        self.assertEqual((pred.ok, pred.reason, pred.embedded), (False, "size-unknown", []))
        self.assertEqual(pred.sections, mime.predict_view(payload, size_estimate=support.SIZE).sections)


class TheToolsPassTheSize(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def test_a_message_too_large_to_predict_saves_the_logo(self):
        mid = self.f.add_message(deep_message())
        with mock.patch.object(htmlview, "PARSE_SHARE", 1e-9):     # this small message counts as large
            read = fenced_part(self.s.read_email("alpha", mid))
            self.assertIn("logo.png (image/png, ", read)
            self.assertNotIn(", inline)", read)
            self.assertIn(mime.inline_note("too-large-to-predict"), read)
            out = self.s.save_attachments("alpha", mid)
        self.assertIn("saved=2", trusted_part(out))
        self.assertNotIn("inline-excluded", fenced_part(out))

    def test_gmail_without_a_size_estimate(self):
        mid = self.f.add_message(deep_message(2))
        real = FakeGmail._messages_get

        def no_size(fake, *a, **kw):
            out = real(fake, *a, **kw)
            out.pop("sizeEstimate", None)
            return out

        with mock.patch.object(FakeGmail, "_messages_get", no_size):
            read = fenced_part(self.s.read_email("alpha", mid))
        self.assertIn(mime.inline_note("size-unknown"), read)
        self.assertNotIn(", inline)", read)

    def test_an_ordinary_message_still_marks_the_logo_inline(self):
        mid = self.f.add_message(deep_message(2))
        read = fenced_part(self.s.read_email("alpha", mid))
        self.assertIn(", inline)", read)
        self.assertNotIn("Inline classification", read)


class TheDeadlineIsHard(unittest.TestCase):
    """Each shape takes seconds without the deadline; with VIEW_SECONDS at 0.3 s the view stops
    within a small overshoot."""
    LIMIT = 0.3

    def assertStopsInTime(self, raw, label):
        with mock.patch.object(htmlview, "VIEW_SECONDS", self.LIMIT):
            got, dt = timed(lambda: htmlview.build_view(raw))
        self.assertEqual(got, "view-too-slow", label)
        self.assertLess(dt, self.LIMIT + 1.0, label)

    def test_a_huge_header_block(self):
        for label, line in (("missing names", ":\n"), ("unread headers", "a:\n"), ("continuations", " \n"),
                            ("read headers", "Content-ID: <x@y>\n"), ("dash names", "--:\n")):
            lead = "X-A: a\n" if line == " \n" else ""
            block = lead + line * (16_000_000 // len(line))
            raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="B"\n\n'
                                "--B\nContent-Type: text/html\n\n<p>hello</p>\n"
                                f"--B\n{block}Content-Type: application/octet-stream\n\nx\n--B--\n")
            self.assertStopsInTime(raw, label)

    def test_the_header_loop_checks_the_deadline(self):
        parser = htmlview._ViewFeedParser(time.monotonic() - 1)
        parser._new_message()
        with self.assertRaises(htmlview.ViewError) as cm:
            parser._parse_headers(["a: b\n"] * 100_000)
        self.assertEqual(cm.exception.code, "view-too-slow")

    def test_markup_without_handlers(self):
        for label, unit in (("comments", "<!---->"), ("declarations", "<!x>"), ("processing", "<?x>"),
                            ("empty end tags", "</>"), ("cdata", "<![CDATA[x]]>")):
            raw = M.raw_message(C.HEAD + "Content-Type: text/html\n\n" + unit * (12_000_000 // len(unit)) + "\n")
            self.assertStopsInTime(raw, label)

    def test_a_start_tag_with_too_many_attributes_loses_them(self):
        tag = "<img" + "/ " * 260_000 + ' src="cid:e@x">'        # cost over MAX_TAG_COST, within 1 MiB
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/related; boundary="R"\n\n'
                            f"--R\nContent-Type: text/html\n\n<p>before</p>{tag}<p>after</p>\n"
                            + C.part("image/png", C.PNG, cid="e@x", disp="inline", name="logo.png") + "--R--\n")
        v, dt = timed(lambda: htmlview.build_view(raw))
        self.assertIsInstance(v, htmlview.View)
        self.assertLess(dt, 2.0)
        self.assertIn("html-attributes-dropped", v.warnings)
        self.assertIn(b"before</p><img><p>after", v.page)            # the element stays, without its attributes
        self.assertEqual(v.embedded, [])
        pred = mime.predict_view(payload_of(raw), size_estimate=len(raw))
        self.assertEqual((pred.ok, pred.embedded), (True, []))      # predicted the same way

    def test_too_many_character_references(self):
        raw = M.raw_message(C.HEAD + "Content-Type: text/html\n\n<p>" + "&amp;" * 2000 + "</p>\n")
        with mock.patch.object(htmlview, "MAX_ENTITIES", 1000):
            self.assertEqual(timed(lambda: htmlview.build_view(raw))[0], "html-too-complex")
        self.assertGreater(htmlview.MAX_ENTITIES, 2 * htmlview.PREDICT_MAX_INPUT)   # never under a prediction

    def test_parts_are_counted_while_parsing(self):
        parts = "--B\n\n" * 200_000
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="B"\n\n' + parts + "--B--\n")
        got, dt = timed(lambda: htmlview.build_view(raw))
        self.assertEqual(got, "mime-too-many-parts")
        self.assertLess(dt, 1.0)


class TheParserIsTheStdlibs(unittest.TestCase):
    """The fast path and the header loop change nothing the view shows: every shape builds the
    same page with the stdlib's line buffer and header loop patched back in."""

    SHAPES = {
        "envelope lines": "From someone\nFrom: Store <store@example.test>\nSubject: s\nFrom x\n"
                          "Content-Type: text/html\n\n<p>a</p>\n",
        "continuation first": " folded\nFrom: a@example.test\nSubject: s\nContent-Type: text/plain\n\nx\n",
        "missing names": "From: a@example.test\n: x\nSubject: s\n:\nContent-Type: text/plain\n\nx\n",
        "folded structural": 'From: a@example.test\nSubject: s\nContent-Type: multipart/mixed;\n boundary="B"\n\n'
                             "--B\nContent-Type: text/html;\n\tcharset=utf-8\n\n<p>a</p>\n--B--\n",
        "dash lines": 'From: a@example.test\nSubject: s\nContent-Type: multipart/mixed; boundary="B"\n\n'
                      "--\n--B-\n--Bx\n--B\nContent-Type: text/plain\n\n--\n--B \n-- x\n--B--\n--\n",
        "prefix boundaries": 'From: a@example.test\nSubject: s\nContent-Type: multipart/mixed; boundary="B"\n\n'
                             '--B\nContent-Type: multipart/mixed; boundary="BB"\n\n--BB\nContent-Type: text/plain\n\n'
                             "--BBx\n--Bx\nend\n--BB--\n--B--\n",
        "duplicates": "From: a@example.test\n" + "Cc: c@example.test\n" * 70 + "Subject: s\nSubject: t\n"
                      "Content-Type: text/plain\nContent-Type: text/html\n\nx\n",
        "delivery status": 'From: a@example.test\nSubject: s\nContent-Type: multipart/report; boundary="B"\n\n'
                           "--B\nContent-Type: text/plain\n\nbounced\n--B\nContent-Type: message/delivery-status\n\n"
                           "Reporting-MTA: dns; mx.example.test\n\nFinal-Recipient: rfc822; x@example.test\n--B--\n",
    }

    def stock(self, raw):
        with mock.patch.object(htmlview._ViewSubFile, "readline", email.feedparser.BufferedSubFile.readline), \
                mock.patch.object(htmlview._ViewFeedParser, "_parse_headers", email.feedparser.FeedParser._parse_headers):
            return self.build(raw)

    @staticmethod
    def build(raw):
        try:
            v = htmlview.build_view(raw)
            return (v.page, v.warnings, v.embedded, v.headers)
        except htmlview.ViewError as e:
            return e.code

    def test_same_view_for_every_shape(self):
        raws = [make() for make, _ in C.CASES.values()] + [make() for make in S.ALL_SHAPES.values()]
        raws += [M.raw_message(text) for text in self.SHAPES.values()]
        for raw in raws:
            self.assertEqual(self.build(raw), self.stock(raw), raw[:300])

    def test_the_sanitizer_matches_html_parser(self):
        # the constant-memory tag end and the copied end-tag parser give the stock answers
        import html.parser as hp
        import random
        random.seed(11)
        atoms = ["<a", "<img", "</a", "</", "<p", ">", "/>", " ", "\t", "\n", "=", '"', "'", "b", "src", "x=y",
                 'href="https://e.test/?a=1&amp;b=2"', '"<>"', "'>'", "<!--", "-->", "<!x>", "<?x>", "&amp;",
                 "&#65;", "<style>", "</style>", "<script>", "</script>", "<b>", "</b>", "cid:e@x", "<", "</>"]
        docs = [make().decode("utf-8", "replace") for make, _ in C.CASES.values()]
        docs += ["".join(random.choice(atoms) for _ in range(random.randrange(1, 60))) for _ in range(4000)]

        def run(doc):
            warnings, embedded = [], set()
            try:
                out = htmlview.sanitize_html(doc, htmlview.CidScope({}), {}, warnings, embedded=embedded)
            except htmlview.ViewError as e:
                return e.code
            return out, warnings, embedded

        stock = {"check_for_whole_start_tag": hp.HTMLParser.check_for_whole_start_tag,
                 "parse_endtag": hp.HTMLParser.parse_endtag}
        for doc in docs:
            mine = run(doc)
            with mock.patch.multiple(htmlview._Sanitizer, **stock):
                self.assertEqual(mine, run(doc), doc[:200])

    def test_more_authentication_results_than_kept(self):
        auth = "Authentication-Results: mx.google.com; dkim=pass\n"
        for n, want in ((htmlview._HEADER_COPIES, "mx.google.com dkim=pass"), (htmlview._HEADER_COPIES + 1, "unavailable")):
            v = htmlview.build_view(M.raw_message("From: a@example.test\nSubject: s\n" + auth * n
                                                  + "Content-Type: text/plain\n\nx\n"))
            self.assertIn(want, v.page.decode(), n)


class TheAdapterRefusesAmbiguity(unittest.TestCase):
    def assertUnavailable(self, raw, reason="header-unreadable", payload=None):
        pred = mime.predict_view(payload if payload is not None else payload_of(raw), size_estimate=len(raw))
        self.assertEqual((pred.ok, pred.reason, pred.embedded), (False, reason, []))

    def test_a_comment_or_a_second_boundary(self):
        for extra in ('; (c) boundary="R1"', '; boundary*="R2"', '; boundary ="R2"'):
            with self.subTest(extra):
                self.assertUnavailable(message(logo_related(related_extra=extra)))
        self.assertUnavailable(message(logo_related(img_cd="inline (c)")))
        ok = mime.predict_view(payload_of(raw := message(logo_related(img_cd='inline; filename="a (1).png"'))),
                               size_estimate=len(raw))
        self.assertTrue(ok.ok)                                      # a parenthesis in quotes is no comment

    def test_nonstandard_transfer_encodings(self):
        for cte in ('"base64"', "x-base64", "base64 ", "base-64"):
            self.assertUnavailable(message(logo_related(html_cte=cte)))
        pred = mime.predict_view(payload_of(raw := message(logo_related(html_cte="BASE64"))), size_estimate=len(raw))
        self.assertTrue(pred.ok)

    def test_too_many_structural_headers(self):
        self.assertUnavailable(message(logo_related(img_cid="<logo@x>\nContent-ID: <z@x>" * 64)))   # one node
        many = "".join("--R\nContent-Type: text/plain\n" + "Content-ID: <d@x>\n" * 60 + "\nx\n" for _ in range(34))
        raw = M.raw_message(C.HEAD + 'Content-Type: multipart/related; boundary="R"\n\n'
                            '--R\nContent-Type: text/html\n\n<img src="cid:e@x">\n' + many
                            + C.part("image/png", C.PNG, cid="e@x", disp="inline", name="logo.png") + "--R--\n")
        self.assertUnavailable(raw, "too-many-headers")

    def test_gmail_labels_a_container_as_a_message(self):
        for child in ("Content-Type: text/plain " + "(" * 33 + ")" * 33 + "\n\nx\n", "Content-Type: text/plain\n\nx\n"):
            raw = M.raw_message(C.HEAD + 'Content-Type: multipart/mixed; boundary="O"\n\n--O\n' + logo_related()
                                + '--O\nContent-Type: multipart/mixed; boundary="Z"\nContent-Disposition: attachment\n\n'
                                + f"--Z\n{child}--Z--\n--O--\n")
            payload = payload_of(raw)
            payload["parts"][1]["mimeType"] = "message/rfc822"
            self.assertUnavailable(raw, "structure-ambiguous", payload=payload)


class RandomMessages(unittest.TestCase):
    """Random MIME trees with varied structural headers: whenever the prediction succeeds, the
    view builds the message and embeds exactly the parts predicted."""

    def make(self, rng) -> bytes:
        cids = [f"img{i}@x" for i in range(4)]
        n = [0]
        hostile = rng.random() < 0.3      # a third of the messages carry hostile values

        def pick(common, rare):
            return rng.choice(rare) if hostile and rng.random() < 0.2 else rng.choice(common)

        def ctype(base):
            return pick([base, base + "; charset=utf-8", base + '; name="a (1).png"'],
                        [base.upper(), base + " (c)", base + "; x*=utf-8''%41"])

        def image():
            cid = rng.choice(cids)
            cid_hdr = pick([f"<{cid}>", cid, f"<{cid.upper()}>"], [f" <{cid}> ", f"<{cid}> (c)"])
            disp = pick([None, "inline", 'inline; filename="l.png"', "attachment"], ["inline (c)", "attachment (c)"])
            out = f"Content-Type: {ctype('image/png')}\nContent-ID: {cid_hdr}\n"
            out += f"Content-Disposition: {disp}\n" if disp else ""
            cte = pick(["base64", "BASE64"], ["base64 ", '"base64"', "x-base64"])
            return out + f"Content-Transfer-Encoding: {cte}\n\n" + base64.encodebytes(C.PNG).decode()

        def html():
            refs = "".join(f'<img src="cid:{rng.choice(cids)}">' for _ in range(rng.randrange(0, 4)))
            return f"Content-Type: {ctype('text/html')}\n\n<p>hi</p>{refs}\n"

        def node(depth):
            kind = (rng.choice(["related", "related", "related", "alternative", "mixed", "html", "image", "pdf"])
                    if depth < 4 else rng.choice(["html", "image", "pdf"]))
            if kind == "html":
                return html()
            if kind == "image":
                return image()
            if kind == "pdf":
                return ("Content-Type: application/pdf\nContent-Disposition: attachment; filename=\"r.pdf\"\n"
                        "Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(M.PDF).decode())
            n[0] += 1
            b = f"Z{n[0]}"
            extra = pick(["", '; type="text/html"'], ["; (c) x=1", f'; boundary="{b}x"'])
            if kind == "related":
                kids = [html()] + [image() for _ in range(rng.randrange(1, 4))]
                kids += [node(depth + 1) for _ in range(rng.randrange(0, 2))]
            else:
                kids = [node(depth + 1) for _ in range(rng.randrange(1, 4))]
            body = "".join(f"--{b}\n{k}" for k in kids)
            return f'Content-Type: multipart/{kind}; boundary="{b}"{extra}\n\n{body}--{b}--\n'

        return M.raw_message(C.HEAD + node(0))

    def test_prediction_ok_implies_the_same_view(self):
        import random
        rng = random.Random(20261005)
        accepted = embedded = 0
        for i in range(800):
            raw = self.make(rng)
            f = FakeGmail()
            mid = f.add_message(raw)
            pred = mime.predict_view(f.messages[mid]["payload"], lambda att: f._messages_attachments_get("me", mid, att)["data"],
                                     size_estimate=len(raw))
            if not pred.ok:
                continue
            accepted += 1
            try:
                view = htmlview.build_view(raw)
            except htmlview.ViewError as e:
                self.fail(f"case {i}: prediction ok, view refused: {e.code}\n{raw[:600]!r}")
            self.assertEqual(set(pred.embedded), set(view.embedded), f"case {i}\n{raw[:600]!r}")
            embedded += bool(pred.embedded)
        self.assertGreater(accepted, 500)
        self.assertGreater(embedded, 150)


class SmallerFixes(unittest.TestCase):
    def test_long_recipient_lists_are_decoded(self):
        names = "".join(f"=?utf-8?q?J=C3=BCrgen_M=C3=BCller_{i}?= <user{i}@example.test>, " for i in range(45))
        v = htmlview.build_view(M.raw_message(C.HEAD + f"Cc: {names}\nContent-Type: text/plain\n\nx\n"))
        self.assertIn("header-shown-unparsed-cc", v.warnings)
        self.assertIn("Jürgen Müller 0", v.headers["Cc"])
        longer = names * 8                                          # over DECODE_WORDS_MAX: shown as supplied
        v = htmlview.build_view(M.raw_message(C.HEAD + f"Cc: {longer}\nContent-Type: text/plain\n\nx\n"))
        self.assertIn("=?utf-8?q?J=C3=BCrgen", v.headers["Cc"])

    def test_an_escaped_parenthesis_outside_a_comment_counts(self):
        self.assertEqual(htmlview._paren_depth("\\(" + "(" * 32 + ")" * 33), 33)
        self.assertEqual(htmlview._paren_depth("(" + "\\(" * 40 + ")"), 1)        # escaped inside a comment
        with self.assertRaises(htmlview.ViewError):
            htmlview.parse_header("content-type", "text/plain; a=\\(" + "(" * 32 + ")" * 33)


if __name__ == "__main__":
    unittest.main()
