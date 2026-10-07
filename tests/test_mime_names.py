"""Shared MIME enumerator, strict base64url, C2 name rules, risk flags, and the qbo-attach
compatibility contract (PLAN-v4 5.1, 5.3, 7, 8.2 C2/C4, section 14 'names and writes')."""
from tests import support  # noqa: F401

import base64
import unittest

import mime
import names
from tests import messages as M
from tests.fakegmail import FakeGmail


def payload_of(raw: bytes, **kw) -> dict:
    f = FakeGmail(**kw)
    mid = f.add_message(raw)
    return f.messages[mid]["payload"], f, mid


class EnumeratorTests(unittest.TestCase):
    def test_stable_depth_first_indexes_and_eligibility(self):
        raw = M.with_attachments([
            (M.PDF, "application", "pdf", "invoice.pdf", "attachment"),
            (M.JPEG, "image", "jpeg", "photo.jpg", "inline"),
            (b"unnamed bytes", "application", "octet-stream", None, "attachment"),
        ], html="<p>hi</p>")
        payload, _, _ = payload_of(raw)
        parts, why = mime.enumerate_message(payload, size_estimate=support.SIZE)
        self.assertIsNone(why)
        self.assertEqual([p.index for p in parts], [1, 2, 3])
        self.assertEqual([p.name for p in parts][:2], ["invoice.pdf", "photo.jpg"])
        self.assertTrue(parts[2].generated_name)
        self.assertRegex(parts[2].name, r"^part-[0-9.]+\.bin$")
        self.assertFalse(parts[0].inline)
        self.assertFalse(parts[1].inline)   # inline disposition, but the view does not embed it
        # same payload twice -> identical numbering (read_email and save_attachments agree)
        self.assertEqual([(p.index, p.part_id) for p in parts],
                         [(p.index, p.part_id) for p in mime.enumerate_parts(payload)])

    def test_inline_by_cid_inside_related(self):
        raw = M.related_html('<img src="cid:logo@x">', [(M.PNG_1x1, "png", "logo@x", "logo.png")])
        payload, _, _ = payload_of(raw)
        parts, why = mime.enumerate_message(payload, size_estimate=support.SIZE)
        self.assertEqual((len(parts), why), (1, None))
        self.assertTrue(parts[0].inline)    # the export view embeds it
        self.assertEqual(parts[0].content_id, "logo@x")

    def test_attached_message_opaque_and_parsed(self):
        inner = M.plain(subject="Inner")
        raw = M.with_attached_message(inner)
        p_opaque, _, _ = payload_of(raw, rfc822_mode="opaque")
        p_parsed, _, _ = payload_of(raw, rfc822_mode="parsed")
        a = [p for p in mime.enumerate_parts(p_opaque) if p.is_message][0]
        b = [p for p in mime.enumerate_parts(p_parsed) if p.is_message][0]
        self.assertFalse(a.parsed_container)
        self.assertIsNotNone(a.attachment_id)
        self.assertTrue(b.parsed_container)

    def test_limits(self):
        node = {"mimeType": "multipart/mixed", "parts": []}
        cur = node
        for _ in range(25):
            nxt = {"mimeType": "multipart/mixed", "parts": []}
            cur["parts"].append(nxt)
            cur = nxt
        with self.assertRaises(mime.MimeLimitError) as cm:
            mime.enumerate_parts(node)
        self.assertEqual(cm.exception.code, "mime-too-deep")
        wide = {"mimeType": "multipart/mixed", "parts": [{"mimeType": "text/plain"}] * 600}
        with self.assertRaises(mime.MimeLimitError) as cm:
            mime.enumerate_parts(wide)
        self.assertEqual(cm.exception.code, "mime-too-many-parts")

    def test_attachment_lines(self):
        raw = M.with_attachments([(M.PDF, "application", "pdf", "a\u202eexe.pdf", "attachment")])
        payload, _, _ = payload_of(raw)
        lines = mime.attachment_lines(mime.enumerate_parts(payload), lambda s: s)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("[1] "))
        self.assertIn("(application/pdf, ", lines[0])
        self.assertIn(" bytes, attachment)", lines[0])


class Base64UrlTests(unittest.TestCase):
    def test_padding_optional_but_correct(self):
        for data in (b"", b"a", b"ab", b"abc", b"\xff\xfe\xfd\xfc"):
            enc = base64.urlsafe_b64encode(data)
            self.assertEqual(mime.b64url_decode(enc, 100), data)
            self.assertEqual(mime.b64url_decode(enc.rstrip(b"="), 100), data)

    def test_malformed_rejected(self):
        for bad in ("ab+c", "ab/c", "a===", "abc==", "abcde", "ab c", "ab=c", "\u00e9", "ab\ncd"):
            with self.assertRaises(mime.MalformedData, msg=bad):
                mime.b64url_decode(bad, 100)

    def test_bound_checked_before_decoding(self):
        with self.assertRaises(mime.DataTooLarge):
            mime.b64url_decode("A" * 4000, 100)


class NameRuleTests(unittest.TestCase):
    def test_regression_fixtures(self):
        cases = {
            "rep\x7fort.pdf": "report.pdf",                  # DEL
            "o'brien \"q\".pdf": "o_brien _q_.pdf",          # apostrophe and double quote
            "inv\u061coice.pdf": "invoice.pdf",              # ARABIC LETTER MARK (Cf)
            "in\u200bvo\u200dice.pdf": "invoice.pdf",        # zero-width (Cf)
            "a\u202egnp.exe": "agnp.exe",                    # RLO bidi override (Cf)
            "line\u2028sep\u2029.pdf": "linesep.pdf",        # LS / PS (Zl / Zp)
            "lone\ud800surrogate.pdf": "lonesurrogate.pdf",  # lone surrogate (Cs)
            "../../etc/passwd": "passwd",                    # traversal: last component only
            "C:\\Windows\\evil.bat": "evil.bat",
            "...hidden.": "hidden",                          # leading dots, trailing dots
            "a:b*c?d<e>f|g.txt": "a_b_c_d_e_f_g.txt",
        }
        for raw, want in cases.items():
            self.assertEqual(names.sanitize_component(names.basename_of(raw)), want, raw)

    def test_padding_cannot_hide_a_risky_extension(self):
        raw = "Invoice.pdf" + "\u3164" * 30 + "\u3000\u00a0" * 5 + ".terminal"
        clean = names.sanitize_component(raw)
        self.assertEqual(clean, "Invoice.pdf .terminal")
        reasons = names.risk_reasons(raw, clean, "application/octet-stream", b"")
        self.assertIn("disguised-name", reasons)
        self.assertIn("risky-extension", reasons)
        for ext in (".shortcut", ".mobileconfig", ".xip"):
            self.assertIn("risky-extension", names.risk_reasons("x" + ext, "x" + ext, "", b""), ext)

    def test_empty_names_get_generated_fallback(self):
        plan = names.plan_name("\u200b\u202e...", "part-1.bin", None)
        self.assertEqual(plan.candidate(1), "part-1.bin")

    def test_long_names_reserve_suffix_and_extension(self):
        plan = names.plan_name("\u00e9" * 300 + ".pdf", "x.pdf", "pdf")
        for n in (1, 2, 9999):
            cand = plan.candidate(n)
            self.assertLessEqual(len(cand.encode()), names.MAX_NAME_BYTES, cand)
            self.assertTrue(cand.endswith(".pdf"))
            cand.encode("utf-8")  # no split code point

    def test_long_extension_is_bounded(self):
        plan = names.plan_name("file." + "x" * 50, "x.bin", None)
        self.assertEqual(plan.ext, "")
        self.assertLessEqual(len(plan.candidate(9999).encode()), names.MAX_NAME_BYTES)

    def test_extension_correction(self):
        p = names.plan_name("receipt", "x.bin", "pdf")
        self.assertEqual(p.candidate(1), "receipt.pdf")
        self.assertTrue(p.extension_corrected)
        p = names.plan_name("photo.JPEG", "x.bin", "jpeg")
        self.assertEqual(p.candidate(1), "photo.JPEG")
        self.assertFalse(p.extension_corrected)
        p = names.plan_name("invoice.exe", "x.bin", "pdf")
        self.assertEqual(p.candidate(1), "invoice.pdf")
        self.assertIn("risky-extension", names.risk_reasons("invoice.exe", p.candidate(1), "application/pdf", M.PDF))

    def test_subfolder_rules(self):
        self.assertEqual(names.parse_subfolder("receipts/2026"), ["receipts", "2026"])
        self.assertEqual(names.parse_subfolder(None), [])
        for bad, code in (("/abs", "subfolder-absolute"), ("~/x", "subfolder-absolute"),
                          ("C:/x", "subfolder-absolute"), ("a/../b", "subfolder-dot-component"),
                          ("./a", "subfolder-dot-component"), ("a/\u200b/b", "subfolder-empty-component"),
                          ("a/b/c/d/e", "subfolder-too-deep"), ("x" * 70, "subfolder-component-too-long")):
            with self.assertRaises(ValueError, msg=bad) as cm:
                names.parse_subfolder(bad)
            self.assertEqual(str(cm.exception), code, bad)
        self.assertEqual(names.parse_subfolder(".hidden/ok"), ["hidden", "ok"])


class QboContractTests(unittest.TestCase):
    def test_signatures_and_extensions(self):
        self.assertEqual(names.qbo_check("a.pdf", 10, M.PDF), (True, "ok"))
        self.assertEqual(names.qbo_check("a.jpeg", 10, M.JPEG), (True, "ok"))
        self.assertEqual(names.qbo_check("a.JPG", 10, M.JPEG), (True, "ok"))
        self.assertEqual(names.qbo_check("a.png", 10, M.PNG), (True, "ok"))   # trailing PNG data passes
        self.assertEqual(names.qbo_check("a.pdf", 10, b"\n" + M.PDF), (False, "unsupported-type"))  # bytes before %PDF-
        self.assertEqual(names.qbo_check("a.png", 10, M.PDF), (False, "extension-mismatch"))
        self.assertEqual(names.qbo_check("a.docx", 10, b"PK\x03\x04"), (False, "unsupported-type"))
        self.assertEqual(names.qbo_check("a.pdf", 25 * 1024 * 1024 + 1, M.PDF), (False, "too-large"))
        self.assertEqual(names.qbo_check("a.pdf", 25 * 1024 * 1024, M.PDF), (True, "ok"))

    def test_name_contract(self):
        self.assertEqual(names.qbo_check("x" * 97 + ".pdf", 1, M.PDF)[1], "name-too-long")
        self.assertEqual(names.qbo_check("x" * 96 + ".pdf", 1, M.PDF), (True, "ok"))
        self.assertEqual(names.qbo_check("o'b.pdf", 1, M.PDF)[1], "name-quote")
        self.assertEqual(names.qbo_check("a\u202e.pdf", 1, M.PDF)[1], "name-control-or-bidi")
        self.assertEqual(names.qbo_check("a\\b.pdf", 1, M.PDF)[1], "name-slash")
        self.assertEqual(names.qbo_check("a.pdf", 1, M.PDF, regular=False)[1], "not-regular-file")
        self.assertEqual(names.qbo_check("", 1, M.PDF)[1], "no-usable-name")

    def test_every_sanitized_name_meets_the_name_contract(self):
        hostile = ["a\x00b.pdf", "\u202e\u2066x.pdf", "q'\"q.pdf", "/" * 5 + "x.pdf", "\u00e9" * 200 + ".pdf",
                   "con:aux*.pdf", "x\ud83d.pdf", "x\u2028y.pdf"]
        for h in hostile:
            plan = names.plan_name(h, "fallback.pdf", "pdf")
            for n in (1, 2, 50, 9999):
                ok, why = names.qbo_check(plan.candidate(n), 100, M.PDF)
                self.assertTrue(ok, f"{h!r} -> {plan.candidate(n)!r}: {why}")

    def test_risk_classification(self):
        self.assertIn("executable-content", names.risk_reasons("x.pdf", "x.pdf", "application/pdf", M.EXE))
        self.assertIn("risky-mime-type", names.risk_reasons("x.bin", "x.bin", "application/x-msdownload", b""))
        self.assertIn("risky-extension", names.risk_reasons("invoice.pdf.exe", "invoice.pdf.exe", "", b""))
        self.assertIn("active-content", names.risk_reasons("x.txt", "x.txt", "text/plain", b"  <html><script>"))
        self.assertIn("disguised-name", names.risk_reasons("a\u202egnp.exe", "agnp.exe", "", b""))
        self.assertEqual(names.risk_reasons("receipt.pdf", "receipt.pdf", "application/pdf", M.PDF), [])
        self.assertEqual(names.risk_reasons("r.docx", "r.docx", "application/vnd.openxmlformats", b"PK\x03\x04"), [])


if __name__ == "__main__":
    unittest.main()
