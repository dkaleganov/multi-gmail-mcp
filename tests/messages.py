"""Synthetic RFC 822 messages for tests (no real data)."""
from __future__ import annotations

import email.policy
from email.message import EmailMessage

PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32 + b"\xff\xd9"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"trailing-data-is-fine"
# 1x1 transparent PNG (valid image)
PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082")
EXE = b"MZ\x90\x00" + b"\x00" * 60


def base(subject="Synthetic receipt", sender="Store <store@example.test>", date="Mon, 5 Oct 2026 10:00:00 +0000",
         extra_headers=()) -> EmailMessage:
    m = EmailMessage(policy=email.policy.default)
    m["From"] = sender
    m["To"] = "alpha@example.test"
    m["Subject"] = subject
    m["Date"] = date
    m["Message-ID"] = "<synthetic-1@example.test>"
    for k, v in extra_headers:
        m[k] = v
    return m


def plain(text="Hello, plain body.", **kw) -> bytes:
    m = base(**kw)
    m.set_content(text)
    return m.as_bytes()


def with_attachments(atts, html=None, text="See attached.", **kw) -> bytes:
    """atts: list of (bytes, maintype, subtype, filename-or-None, disposition)"""
    m = base(**kw)
    m.set_content(text)
    if html is not None:
        m.add_alternative(html, subtype="html")
    for data, maintype, subtype, filename, disp in atts:
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename, disposition=disp)
        if filename is None:
            part = m.get_payload()[-1]
            # remove the filename parameter add_attachment may leave empty
            if part.get_filename() is not None:
                del part["Content-Disposition"]
                part["Content-Disposition"] = disp
    return m.as_bytes()


def related_html(html: str, images: list[tuple[bytes, str, str, str | None]], text="plain alt", **kw) -> bytes:
    """multipart/alternative[text, multipart/related[html, images...]]; images: (data, subtype, cid, filename)"""
    m = base(**kw)
    m.set_content(text)
    m.add_alternative(html, subtype="html")
    html_part = m.get_payload()[1]
    for data, subtype, cid, filename in images:
        html_part.add_related(data, maintype="image", subtype=subtype, cid=f"<{cid}>", filename=filename,
                              disposition="inline")
    return m.as_bytes()


def with_attached_message(inner: bytes, filename="forwarded.eml", **kw) -> bytes:
    m = base(**kw)
    m.set_content("Forwarding the original as an attachment.")
    inner_msg = email.message_from_bytes(inner, policy=email.policy.default)
    m.add_attachment(inner_msg, filename=filename)
    return m.as_bytes()


def raw_message(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode()
