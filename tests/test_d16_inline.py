"""Owner amendment D16 and decisions (2026-10-05): a part is inline only when the export
view embeds it, and an explicit `Content-Disposition: attachment` wins. Apple Mail marks
real PDF attachments `Content-Disposition: inline`; those are attachments and are saved
by default. read_email and save_attachments use the same enumerator, so their indexes and
inline flags agree. Split bodies are in test_split_sections; every coverage case is in
test_coverage."""
from tests import support  # noqa: F401

import base64
import re
import unittest

import mime
from tests import messages as M
from tests.test_legacy_contract import fenced_part, trusted_part


def b64(data: bytes) -> str:
    return base64.encodebytes(data).decode()


def apple_mail_related(html_refs_logo=True, html_extra="") -> bytes:
    """Apple Mail style: alternative[text, related[html, inline logo (cid), inline PDF]].
    The PDF carries a Content-ID too, but the HTML never references it."""
    logo_ref = '<img apple-inline="yes" src="cid:LOGO-1234@apple.example">' if html_refs_logo else ""
    return M.raw_message(
        "From: Store <store@example.test>\nTo: alpha@example.test\nSubject: Your receipt\n"
        "Date: Mon, 5 Oct 2026 10:00:00 +0000\nMime-Version: 1.0 (Mac OS X Mail 16.0)\n"
        "Content-Type: multipart/alternative; boundary=\"Apple-Mail=_A\"\n\n"
        "--Apple-Mail=_A\nContent-Transfer-Encoding: 7bit\nContent-Type: text/plain; charset=us-ascii\n\n"
        "Receipt attached.\n\n"
        "--Apple-Mail=_A\nContent-Type: multipart/related; type=\"text/html\"; boundary=\"Apple-Mail=_B\"\n\n"
        "--Apple-Mail=_B\nContent-Transfer-Encoding: 7bit\nContent-Type: text/html; charset=us-ascii\n\n"
        f"<html><body><div>Receipt attached.</div>{logo_ref}{html_extra}</body></html>\n"
        "--Apple-Mail=_B\nContent-Transfer-Encoding: base64\nContent-Disposition: inline; filename=logo.png\n"
        "Content-Type: image/png; x-unix-mode=0644; name=\"logo.png\"\nContent-Id: <logo-1234@apple.example>\n\n"
        f"{b64(M.PNG_1x1)}\n"
        "--Apple-Mail=_B\nContent-Transfer-Encoding: base64\nContent-Disposition: inline; filename=Receipt.pdf\n"
        "Content-Type: application/pdf; x-unix-mode=0644; name=\"Receipt.pdf\"\nContent-Id: <pdf-5678@apple.example>\n\n"
        f"{b64(M.PDF)}\n"
        "--Apple-Mail=_B--\n\n--Apple-Mail=_A--\n")


def apple_mail_mixed() -> bytes:
    """Apple Mail's other shape: the PDF sits between two HTML segments, without a Content-ID."""
    return M.raw_message(
        "From: Store <store@example.test>\nTo: alpha@example.test\nSubject: Invoice\nMime-Version: 1.0\n"
        "Content-Type: multipart/alternative; boundary=A\n\n"
        "--A\nContent-Type: text/plain\n\nInvoice attached.\n"
        "--A\nContent-Type: multipart/mixed; boundary=B\n\n"
        "--B\nContent-Type: text/html\n\n<html><body>Invoice attached.</body></html>\n"
        "--B\nContent-Transfer-Encoding: base64\nContent-Disposition: inline; filename=Invoice.pdf\n"
        f"Content-Type: application/pdf; name=Invoice.pdf\n\n{b64(M.PDF)}\n"
        "--B\nContent-Type: text/html\n\n<html><body>Thanks.</body></html>\n--B--\n--A--\n")


class D16Tests(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def listing(self, mid):
        return re.findall(r"^\[(\d+)\] (.+)$", fenced_part(self.s.read_email("alpha", mid)), re.M)

    def test_apple_mail_inline_pdf_is_saved_by_default_next_to_an_inline_image(self):
        mid = self.f.add_message(apple_mail_related())
        lst = self.listing(mid)
        self.assertEqual([i for i, _ in lst], ["1", "2"])
        self.assertTrue(lst[0][1].startswith("logo.png (image/png, ") and lst[0][1].endswith(", inline)"), lst)
        self.assertTrue(lst[1][1].startswith("Receipt.pdf (application/pdf, ") and lst[1][1].endswith(", attachment)"), lst)
        out = self.s.save_attachments("alpha", mid)
        t, body = trusted_part(out), fenced_part(out)
        self.assertIn("saved=1 already-present=0 skipped=1", t)
        self.assertRegex(body, r"\[1\] state=skipped reason=inline-excluded\n    original name: logo\.png")
        self.assertRegex(body, r"\[2\] state=saved\n    original name: Receipt\.pdf")
        pdf_path = re.search(r"path: (.+Receipt\.pdf)", body).group(1)
        with open(pdf_path, "rb") as f:
            self.assertEqual(f.read(), M.PDF)
        self.assertIn("qbo_compatible: true (ok)", body)

    def test_same_indexes_and_flags_in_both_tools(self):
        for raw in (apple_mail_related(), apple_mail_related(html_refs_logo=False), apple_mail_mixed()):
            mid = self.f.add_message(raw)
            lst = self.listing(mid)
            out = fenced_part(self.s.save_attachments("alpha", mid, include_inline=True))
            saved = re.findall(r"^\[(\d+)\] state=saved\n    original name: (\S+)", out, re.M)
            self.assertEqual([(i, n.split(" ")[0]) for i, n in lst], saved)

    def test_unreferenced_image_and_mixed_shape_are_attachments(self):
        mid = self.f.add_message(apple_mail_related(html_refs_logo=False))
        self.assertTrue(all(x.endswith(", attachment)") for _, x in self.listing(mid)))
        self.assertIn("saved=2 already-present=0 skipped=0", trusted_part(self.s.save_attachments("alpha", mid)))
        mid2 = self.f.add_message(apple_mail_mixed())
        self.assertIn("saved=1", trusted_part(self.s.save_attachments("alpha", mid2)))

    def test_attachment_marked_image_referenced_by_html_is_saved_by_default(self):
        # owner decision 1: the logo is referenced by cid: but marked `attachment` by the sender
        # (the reference uses the Content-ID's exact case so the view resolves it too; see
        # D16ReferenceRules.test_reference_forms for case-insensitive matching in the enumerator)
        raw = apple_mail_related().replace(b"Content-Disposition: inline; filename=logo.png",
                                           b"Content-Disposition: attachment; filename=logo.png")
        raw = raw.replace(b"cid:LOGO-1234@apple.example", b"cid:logo-1234@apple.example")
        mid = self.f.add_message(raw)
        lst = self.listing(mid)
        self.assertTrue(lst[0][1].startswith("logo.png (image/png, ") and lst[0][1].endswith(", attachment)"), lst)
        self.assertTrue(lst[1][1].endswith(", attachment)"), lst)
        out = self.s.save_attachments("alpha", mid)
        t, body = trusted_part(out), fenced_part(out)
        self.assertIn("saved=2 already-present=0 skipped=0", t)
        self.assertRegex(body, r"\[1\] state=saved\n    original name: logo\.png")
        with open(re.search(r"path: (.+logo\.png)", body).group(1), "rb") as f:
            self.assertEqual(f.read(), M.PNG_1x1)
        # the view still shows the referenced image (decision 1 changes saving, not rendering)
        import htmlview
        v = htmlview.build_view(raw)
        self.assertEqual(v.cid_used, 1)
        self.assertIn(b'src="data:image/png;base64,', v.page)

    def test_plain_text_body_references_nothing(self):
        raw = M.with_attachments([(M.PDF, "application", "pdf", "inline.pdf", "inline")])
        mid = self.f.add_message(raw)
        self.assertIn("saved=1", trusted_part(self.s.save_attachments("alpha", mid)))


class D16ReferenceRules(unittest.TestCase):
    def payload(self, raw):
        from tests.fakegmail import FakeGmail
        f = FakeGmail()
        mid = f.add_message(raw)
        return f, mid, f.messages[mid]["payload"]

    def test_reference_forms(self):
        # an <img> reference counts with an upper-case scheme, URL encoding, or a case-only
        # difference; a CSS url() reference and a reference to a non-image part do not (the
        # view embeds neither)
        cases = {'<img src="CID:logo-1234%40apple.example">': [True, False],
                 '<img src="cid:LOGO-1234@APPLE.EXAMPLE">': [True, False],
                 "<div style=\"background:url('cid:logo-1234@apple.example')\"></div>": [False, False],
                 '<img src="cid:pdf-5678@apple.example">': [False, False]}
        for extra, want in cases.items():
            f, mid, payload = self.payload(apple_mail_related(html_refs_logo=False, html_extra=extra))
            parts, why = mime.enumerate_message(payload, size_estimate=support.SIZE)
            self.assertIsNone(why)
            self.assertEqual([p.inline for p in parts], want, extra)

    def test_attachment_disposition_wins_over_a_reference(self):
        # owner decision 1: an embedded part the sender marked as an attachment is an attachment
        raw = apple_mail_related()
        f, mid, payload = self.payload(raw)
        self.assertEqual([p.inline for p in mime.enumerate_message(payload, size_estimate=support.SIZE)[0]], [True, False])
        raw = raw.replace(b"Content-Disposition: inline; filename=logo.png", b"Content-Disposition: attachment; filename=logo.png")
        f, mid, payload = self.payload(raw)
        self.assertEqual([p.inline for p in mime.enumerate_message(payload, size_estimate=support.SIZE)[0]], [False, False])

    def test_related_start_parameter_picks_the_referencing_root(self):
        raw = M.raw_message(
            "From: a@example.test\nSubject: s\nMIME-Version: 1.0\n"
            'Content-Type: multipart/related; boundary=b; start="<root@x>"\n\n'
            "--b\nContent-Type: text/html\nContent-ID: <decoy@x>\n\n<p>no refs</p>\n"
            "--b\nContent-Type: text/html\nContent-ID: <root@x>\n\n<img src=\"cid:img@x\">\n"
            "--b\nContent-Type: image/png\nContent-Disposition: inline; filename=i.png\nContent-ID: <img@x>\n"
            f"Content-Transfer-Encoding: base64\n\n{b64(M.PNG_1x1)}\n--b--\n")
        f, mid, payload = self.payload(raw)
        parts, _ = mime.enumerate_message(payload, size_estimate=support.SIZE)
        # the decoy HTML is neither rendered nor an alternative, so it is listed and saved
        self.assertEqual([(p.name, p.inline) for p in parts], [("part-0.html", False), ("i.png", True)])

    def test_html_body_stored_behind_an_attachment_id(self):
        f, mid, payload = self.payload(apple_mail_related())
        html = payload["parts"][1]["parts"][0]
        data = html["body"].pop("data")
        html["body"]["attachmentId"] = "ANGjdJhtml"
        fetched = []

        def fetch(att):
            fetched.append(att)
            return data

        parts, why = mime.enumerate_message(payload, fetch, size_estimate=support.SIZE)
        self.assertEqual((fetched, why, [p.inline for p in parts]), (["ANGjdJhtml"], None, [True, False]))

        def broken(att):
            raise OSError("network")

        parts, why = mime.enumerate_message(payload, broken, size_estimate=support.SIZE)
        self.assertEqual((why, [p.inline for p in parts]), ("body-unavailable", [False, False]))

    def test_unreadable_html_body_is_reported_in_both_tools(self):
        h = support.ServerHarness()
        try:
            f = h.fake("alpha")
            mid = f.add_message(apple_mail_related())
            html = f.messages[mid]["payload"]["parts"][1]["parts"][0]
            html["body"].pop("data")
            html["body"]["attachmentId"] = "ANGjdJmissing"   # not stored: attachments.get returns 404
            for out in (h.server.read_email("alpha", mid), h.server.save_attachments("alpha", mid)):
                self.assertIn(mime.inline_note("body-unavailable"), fenced_part(out))
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main()
