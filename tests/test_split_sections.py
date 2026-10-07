"""Owner decision 2 (2026-10-05): every top-level body section is the body. Apple Mail splits
one HTML body into several sections around inline attachments.
(a) The D16 check scans every HTML section for cid: references, not only the first.
(b) The views render every text section of a multipart/mixed body in order, each sanitized
    separately with the same policy. multipart/alternative and multipart/related keep their rules.
The enumerator runs the view's own code over Gmail's FULL payload (mime.predict_view); for
every shape here and in coverage_shapes it must pick the same sections and alternatives, and
embed the same parts, as the view does on the RAW bytes; its inline set must be exactly the
embedded parts the sender did not mark `attachment`; and every leaf part must be covered."""
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
from tests import coverage_shapes
from tests import messages as M
from tests.fakegmail import FakeGmail
from tests.test_d16_inline import apple_mail_mixed, apple_mail_related
from tests.test_legacy_contract import fenced_part, trusted_part


def b64(data: bytes) -> str:
    return base64.encodebytes(data).decode()


SIG = ("--{b}\nContent-Transfer-Encoding: base64\nContent-Disposition: inline; filename=signature.png\n"
       'Content-Type: image/png; name="signature.png"\nContent-Id: <sig-42@apple.example>\n\n' + b64(M.PNG_1x1) + "\n")
PDF_INLINE = ("--{b}\nContent-Transfer-Encoding: base64\nContent-Disposition: inline; filename=Invoice.pdf\n"
              'Content-Type: application/pdf; name="Invoice.pdf"\n\n' + b64(M.PDF) + "\n")
SECTION_TWO = ('<html><body><div>SECTION TWO</div><img src="cid:sig-42@apple.example"></body></html>\n')


def head(subject="Invoice") -> str:
    return ("From: Store <store@example.test>\nTo: alpha@example.test\nSubject: " + subject + "\n"
            "Date: Mon, 5 Oct 2026 10:00:00 +0000\nMime-Version: 1.0 (Mac OS X Mail 16.0)\n")


def split_related_inside(first="<div>SECTION ONE</div>") -> bytes:
    """alternative[text, mixed[html 1, inline PDF, related[html 2 -> cid:sig, signature.png]]]:
    the second section is the root of its own related part."""
    return M.raw_message(
        head() + 'Content-Type: multipart/alternative; boundary="A"\n\n'
        "--A\nContent-Type: text/plain\n\nSECTION ONE plain\n"
        '--A\nContent-Type: multipart/mixed; boundary="B"\n\n'
        f"--B\nContent-Type: text/html; charset=utf-8\n\n<html><body>{first}</body></html>\n"
        + PDF_INLINE.format(b="B")
        + '--B\nContent-Type: multipart/related; type="text/html"; boundary="C"\n\n'
        + "--C\nContent-Type: text/html; charset=utf-8\n\n" + SECTION_TWO
        + SIG.format(b="C") + "--C--\n--B--\n--A--\n")


def split_related_outside() -> bytes:
    """alternative[text, related[mixed[html 1, inline PDF, html 2 -> cid:sig], signature.png]]:
    both sections share the related scope."""
    return M.raw_message(
        head() + 'Content-Type: multipart/alternative; boundary="A"\n\n'
        "--A\nContent-Type: text/plain\n\nSECTION ONE plain\n"
        '--A\nContent-Type: multipart/related; type="text/html"; boundary="R"\n\n'
        '--R\nContent-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/html; charset=utf-8\n\n<html><body><div>SECTION ONE</div></body></html>\n"
        + PDF_INLINE.format(b="B")
        + "--B\nContent-Type: text/html; charset=utf-8\n\n" + SECTION_TWO + "--B--\n"
        + SIG.format(b="R") + "--R--\n--A--\n")


def html_with_plain_footer() -> bytes:
    """mixed[html, text/plain footer], as mailing-list software appends one."""
    return M.raw_message(
        head("List post") + 'Content-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/html\n\n<p>HTML BODY</p>\n"
        "--B\nContent-Type: text/plain\n\n-- \nLIST FOOTER <unsubscribe>\n--B--\n")


SHAPES = {
    "split, related inside": split_related_inside,
    "split, related outside": split_related_outside,
    "plain footer": html_with_plain_footer,
    "apple related": apple_mail_related,
    "apple mixed": apple_mail_mixed,
    "related html": lambda: M.related_html('<img src="cid:logo@x">', [(M.PNG_1x1, "png", "logo@x", "logo.png")]),
    "html with attachment": lambda: M.with_attachments([(M.PDF, "application", "pdf", "a.pdf", "attachment")], html="<p>x</p>"),
    "plain": lambda: M.plain(),
    "attached message": lambda: M.with_attached_message(M.plain(text="INNER")),
    "alternative of plain and mixed": lambda: M.raw_message(
        head() + 'Content-Type: multipart/alternative; boundary="A"\n\n'
        "--A\nContent-Type: text/plain\n\nplain\n"
        '--A\nContent-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nintro\n--B\nContent-Type: text/html\n\n<p>rich</p>\n--B--\n--A--\n"),
    "related start": lambda: M.raw_message(
        head() + 'Content-Type: multipart/related; boundary=b; start="<root@x>"\n\n'
        "--b\nContent-Type: text/html\nContent-ID: <decoy@x>\n\n<p>decoy</p>\n"
        "--b\nContent-Type: text/html\nContent-ID: <root@x>\n\n<p>root</p>\n--b--\n"),
    "signed": lambda: M.raw_message(
        head() + 'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; boundary="S"\n\n'
        '--S\nContent-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/html\n\n<p>one</p>\n" + PDF_INLINE.format(b="B")
        + "--B\nContent-Type: text/html\n\n<p>two</p>\n--B--\n"
        "--S\nContent-Type: application/pkcs7-signature; name=smime.p7s\n"
        "Content-Disposition: attachment; filename=smime.p7s\n\nAAAA\n--S--\n"),
}


def payload_of(raw: bytes) -> dict:
    f = FakeGmail()
    return f.messages[f.add_message(raw)]["payload"]


ALL_SHAPES = {**SHAPES, **{name: make for name, (make, _) in coverage_shapes.CASES.items()}}


def raw_part(msg, path):
    for i in path:
        msg = list(msg.iter_parts())[i]
    return msg


def leaves(node, path=()):
    kids = node.get("parts") or []
    if not kids:
        yield path, node
    for i, k in enumerate(kids):
        yield from leaves(k, path + (i,))


def saved_whole(payload) -> set:
    """Paths of attached messages saved whole (their parts are covered by that file)."""
    out, stack = set(), [(payload, ())]
    while stack:
        node, path = stack.pop()
        body = node.get("body") or {}
        if (node.get("mimeType") or "").lower() == "message/rfc822" and (body.get("attachmentId") or body.get("data")):
            out.add(path)
        stack.extend((k, path + (i,)) for i, k in enumerate(node.get("parts") or []))
    return out


class SameSectionsInBothModules(unittest.TestCase):
    def test_enumerator_matches_the_view_and_covers_every_leaf(self):
        self.assertEqual(len(SHAPES), 12)
        for name, make in ALL_SHAPES.items():
            raw = make()
            payload = payload_of(raw)
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            alts = []
            sections = [sel.path for sel in htmlview.select_body(msg, [], alts)]
            view = htmlview.build_view(raw)
            pred = mime.predict_view(payload, size_estimate=support.SIZE)
            parts, why = mime.enumerate_message(payload, size_estimate=support.SIZE)
            self.assertTrue(pred.ok, name)
            self.assertIsNone(why, name)
            self.assertEqual(pred.sections, sections, name)
            self.assertEqual(sorted(pred.alternatives), sorted(alts), name)
            self.assertEqual(set(pred.embedded), set(view.embedded), name)
            # inline set == the parts the view embedded, less those the sender marked `attachment`
            inline = {p.path for p in parts if p.inline}
            self.assertEqual(inline, {x for x in view.embedded if not raw_part(msg, x).is_attachment()}, name)
            # every leaf: body text, or embedded and listed inline, or listed and saved by default
            listed = {p.path: p for p in parts}
            body = set(sections) | set(alts)
            whole = saved_whole(payload)
            for path, node in leaves(payload):
                if path in body or any(path[:len(w)] == w and path != w for w in whole):
                    continue
                b = node.get("body") or {}
                if not (b.get("attachmentId") or b.get("data") or b.get("size")):
                    continue                                          # an empty part holds nothing
                self.assertIn(path, listed, f"{name}: leaf {path} is not covered")
                p = listed[path]
                if p.inline:
                    self.assertIn(path, set(view.embedded), name)
                else:
                    self.assertFalse(p.parsed_container, name)        # saved by default

    def test_section_lists(self):
        ids = lambda make: [".".join(map(str, x)) for x in mime.predict_view(payload_of(make()), size_estimate=support.SIZE).sections]  # noqa: E731
        self.assertEqual(ids(split_related_inside), ["1.0", "1.2.0"])
        self.assertEqual(ids(split_related_outside), ["1.0.0", "1.0.2"])
        self.assertEqual(ids(html_with_plain_footer), ["0", "1"])
        self.assertEqual(ids(SHAPES["alternative of plain and mixed"]), ["1.0", "1.1"])
        self.assertEqual(ids(SHAPES["signed"]), ["0.0", "0.2"])


class SplitBodyTools(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def test_second_section_reference_makes_the_image_inline(self):
        for make in (split_related_inside, split_related_outside):
            mid = self.f.add_message(make())
            lst = re.findall(r"^\[(\d+)\] (.+)$", fenced_part(self.s.read_email("alpha", mid)), re.M)
            self.assertEqual([i for i, _ in lst], ["1", "2"], make.__name__)
            self.assertTrue(lst[0][1].startswith("Invoice.pdf (application/pdf, ") and lst[0][1].endswith(", attachment)"), lst)
            self.assertTrue(lst[1][1].startswith("signature.png (image/png, ") and lst[1][1].endswith(", inline)"), lst)
            out = self.s.save_attachments("alpha", mid)
            t, body = trusted_part(out), fenced_part(out)
            self.assertIn("saved=1 already-present=0 skipped=1", t)
            self.assertRegex(body, r"\[1\] state=saved\n    original name: Invoice\.pdf")
            self.assertRegex(body, r"\[2\] state=skipped reason=inline-excluded\n    original name: signature\.png")

    def test_export_email_html_shows_both_sections_in_order(self):
        mid = self.f.add_message(split_related_inside())
        out = self.s.export_email("alpha", mid, formats=["html"])
        self.assertIn("saved=1", trusted_part(out))
        self.assertNotIn("view warnings", fenced_part(out))
        html_path = re.findall(r"path: (.+\.html)", fenced_part(out))[0]
        with open(html_path, encoding="utf-8") as fh:
            page = fh.read()
        one, two = page.index("SECTION ONE</div>"), page.index("SECTION TWO</div>")
        self.assertLess(one, two)
        self.assertGreater(page.index('src="data:image/png;base64,'), two)
        self.assertNotIn("SECTION ONE plain", page)


class SplitBodyView(unittest.TestCase):
    def test_view_renders_both_sections_in_order(self):
        for make, scopes in ((split_related_inside, [None, "1.2"]), (split_related_outside, ["1", "1"])):
            v = htmlview.build_view(make())
            page = v.page.decode()
            self.assertEqual(len(re.findall(r'<div class="gmcp[0-9a-f]{10}-section">', page)), 2)
            one, two = page.index("SECTION ONE</div>"), page.index("SECTION TWO</div>")
            img = page.index('src="data:image/png;base64,')
            self.assertLess(one, two)
            self.assertLess(two, img)
            self.assertNotIn("SECTION ONE plain", page)        # alternative still prefers HTML
            self.assertEqual(v.warnings, [])                    # no missing-cid, no dropped sections
            self.assertEqual(v.cid_used, 1)
            self.assertEqual([x["content_type"] for x in v.body_part["sections"]], ["text/html", "text/html"])
            self.assertEqual([x["related_scope"] for x in v.body_part["sections"]], scopes)

    def test_sections_are_sanitized_separately(self):
        # an unclosed <b> and an unclosed <title> in section one cannot reach section two
        v = htmlview.build_view(split_related_inside(first="<b>BOLD ONE<title>swallowed"))
        page = v.page.decode()
        self.assertRegex(page, r'<b>BOLD ONE</b></div><div class="gmcp[0-9a-f]{10}-section"><div>SECTION TWO</div>')
        self.assertNotIn("swallowed", page)
        self.assertIn('src="data:image/png;base64,', page)

    def test_plain_footer_section_is_rendered_escaped(self):
        v = htmlview.build_view(html_with_plain_footer())
        page = v.page.decode()
        self.assertLess(page.index("<p>HTML BODY</p>"), page.index("LIST FOOTER &lt;unsubscribe&gt;"))
        self.assertRegex(page, r'<div class="gmcp[0-9a-f]{10}-plain">-- \r?\nLIST FOOTER')
        self.assertEqual([x["content_type"] for x in v.body_part["sections"]], ["text/html", "text/plain"])

    def test_one_output_and_time_budget_across_sections(self):
        with mock.patch.object(htmlview, "sanitize_html", wraps=htmlview.sanitize_html) as m:
            htmlview.build_view(split_related_outside())
        budgets = [c.args[4] for c in m.call_args_list]
        self.assertEqual(len(budgets), 2)
        self.assertIs(budgets[0], budgets[1])
        # the budget is cumulative: two sections that each fit can still exceed it together
        budget = htmlview._budget(100, 60)
        none = htmlview.CidScope({})
        htmlview.sanitize_html("<p>" + "a" * 60 + "</p>", none, {}, [], budget)
        with self.assertRaises(htmlview.ViewError) as cm:
            htmlview.sanitize_html("<p>" + "b" * 60 + "</p>", none, {}, [], budget)
        self.assertEqual(cm.exception.code, "html-too-large")

    def test_inputs_key_covers_every_section(self):
        a = htmlview.build_view(split_related_outside())
        b = htmlview.build_view(split_related_outside().replace(b"SECTION TWO", b"SECTION 2!!"))
        self.assertNotEqual(a.inputs_key, b.inputs_key)


class SplitBodyReferences(unittest.TestCase):
    def test_every_html_section_is_scanned(self):
        for make in (split_related_inside, split_related_outside):
            parts, why = mime.enumerate_message(payload_of(make()), size_estimate=support.SIZE)
            self.assertIsNone(why)
            self.assertEqual([(p.name, p.inline) for p in parts], [("Invoice.pdf", False), ("signature.png", True)])

    def test_fetch_budget(self):
        # related[mixed[html sections stored behind attachment ids], signature.png]
        sections = "".join(f"--B\nContent-Type: text/html\n\n<p>s{i}</p>\n" for i in range(mime.MAX_SECTION_FETCHES + 1))
        raw = M.raw_message(head() + 'Content-Type: multipart/related; boundary="R"\n\n'
                            '--R\nContent-Type: multipart/mixed; boundary="B"\n\n' + sections + "--B--\n"
                            + SIG.format(b="R") + "--R--\n")
        payload = payload_of(raw)
        mixed = payload["parts"][0]["parts"]
        for n in mixed:
            n["body"].pop("data")
            n["body"]["attachmentId"] = "ANGjdJ" + n["partId"]
        calls = []
        parts, why = mime.enumerate_message(payload, lambda att: calls.append(att) or "", size_estimate=support.SIZE)
        self.assertEqual((why, calls, [p.inline for p in parts]), ("too-many-sections-to-fetch", [], [False]))
        del mixed[0]                     # exactly MAX_SECTION_FETCHES sections: all fetched
        parts, why = mime.enumerate_message(payload, lambda att: calls.append(att) or "", size_estimate=support.SIZE)
        self.assertEqual((why, len(calls)), (None, mime.MAX_SECTION_FETCHES))

    def test_nothing_to_embed_means_nothing_fetched(self):
        # the same sections without an embeddable image in scope: no fetch at all
        sections = "".join(f"--B\nContent-Type: text/html\n\n<p>s{i}</p>\n" for i in range(3))
        raw = M.raw_message(head() + 'Content-Type: multipart/mixed; boundary="B"\n\n' + sections
                            + SIG.format(b="B") + "--B--\n")
        payload = payload_of(raw)
        for n in payload["parts"][:-1]:
            n["body"].pop("data")
            n["body"]["attachmentId"] = "ANGjdJ" + n["partId"]
        calls = []
        parts, why = mime.enumerate_message(payload, lambda att: calls.append(att) or "", size_estimate=support.SIZE)
        self.assertEqual((why, calls, [p.name for p in parts]), (None, [], ["signature.png"]))


if __name__ == "__main__":
    unittest.main()
