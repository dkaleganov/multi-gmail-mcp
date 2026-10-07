"""Synthetic messages for the coverage rule (owner decisions, 2026-10-05): every leaf part is
body text (a rendered section or an alternative of one), embedded by the export view, or
listed and saved by default; a part is inline only when the view embeds it.

CASES maps a name to (builder, expected listing as [(name, inline)]). Each case is a part
the old rule skipped by default although the view did not show it, or one the old rule
never listed, plus the two cases from addendum 2 and decision 1."""
from __future__ import annotations

import base64

from tests import messages as M

HEIC = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 16
TIFF = b"II*\x00" + b"\x00" * 16
GIF = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;"
HEAD = ("From: Store <store@example.test>\nTo: alpha@example.test\nSubject: Coverage\n"
        "Date: Mon, 5 Oct 2026 10:00:00 +0000\nMIME-Version: 1.0\n")


def b64(data: bytes) -> str:
    return base64.encodebytes(data).decode()


def part(ctype: str, body: bytes, cid=None, disp=None, name=None, b="R") -> str:
    out = f"--{b}\nContent-Type: {ctype}" + (f'; name="{name}"' if name else "") + "\n"
    if cid:
        out += f"Content-ID: <{cid}>\n"
    if disp:
        out += f"Content-Disposition: {disp}" + (f'; filename="{name}"' if name else "") + "\n"
    return out + "Content-Transfer-Encoding: base64\n\n" + b64(body)


def related(html: str, *parts: str) -> bytes:
    """alternative[text/plain (0), related (1)[text/html (1.0), parts (1.1, 1.2, ...)]]"""
    return M.raw_message(
        HEAD + 'Content-Type: multipart/alternative; boundary="A"\n\n'
        "--A\nContent-Type: text/plain\n\nplain alternative\n"
        '--A\nContent-Type: multipart/related; type="text/html"; boundary="R"\n\n'
        f"--R\nContent-Type: text/html; charset=utf-8\n\n<html><body>{html}</body></html>\n"
        + "".join(parts) + "--R--\n--A--\n")


def mixed(html: str, *parts: str) -> bytes:
    """mixed[text/html (0), parts (1, 2, ...)]"""
    return M.raw_message(HEAD + 'Content-Type: multipart/mixed; boundary="B"\n\n'
                         f"--B\nContent-Type: text/html\n\n{html}\n" + "".join(parts) + "--B--\n")


def alternative(*members: tuple[str, str]) -> bytes:
    """alternative[members (0, 1, ...)], each (content type, body text)."""
    return M.raw_message(HEAD + 'Content-Type: multipart/alternative; boundary="A"\n\n'
                         + "".join(f"--A\nContent-Type: {ct}\n\n{body}\n" for ct, body in members) + "--A--\n")


def calendar_alternative() -> bytes:
    """alternative[text/plain (0), text/html (1), text/calendar (2)], as calendar invitations
    arrive: every text part of the alternative is an alternative of the body, so none is listed."""
    return alternative(("text/plain", "meeting"), ("text/html", "<p>meeting</p>"),
                       ("text/calendar; method=REQUEST", "BEGIN:VCALENDAR\nEND:VCALENDAR"))


PNG = M.PNG_1x1
CASES = {
    # not one of the view's six image types
    "image/jpg label": (lambda: related('<img src="cid:j@x">', part("image/jpg", M.JPEG, cid="j@x")),
                        [("part-1.1.jpg", False)]),
    "image/heic": (lambda: related('<img src="cid:h@x">', part("image/heic", HEIC, cid="h@x", disp="inline",
                                                                name="IMG_0001.HEIC")),
                   [("IMG_0001.HEIC", False)]),
    "image/tiff": (lambda: related('<img src="cid:t@x">', part("image/tiff", TIFF, cid="t@x")),
                   [("part-1.1.tif", False)]),
    "application/octet-stream": (lambda: related('<img src="cid:o@x">', part("application/octet-stream", PNG,
                                                                             cid="o@x", disp="inline", name="scan.png")),
                                 [("scan.png", False)]),
    # a non-image part referenced by cid:
    "pdf from a link": (lambda: related('<a href="cid:p@x">Invoice</a>', part("application/pdf", M.PDF, cid="p@x")),
                        [("part-1.1.pdf", False)]),
    "pdf from an img": (lambda: related('<img src="cid:p2@x">', part("application/pdf", M.PDF, cid="p2@x",
                                                                     disp="inline", name="Receipt.pdf")),
                        [("Receipt.pdf", False)]),
    # cid: outside <img src>
    "cid in CSS": (lambda: related('<div style="background:url(cid:bg@x);height:9px">x</div>',
                                   part("image/png", PNG, cid="bg@x")),
                   [("part-1.1.png", False)]),
    "cid in a background attribute": (lambda: related('<table background="cid:bg2@x"><tr><td>x</td></tr></table>',
                                                      part("image/gif", GIF, cid="bg2@x", disp="inline", name="bg.gif")),
                                      [("bg.gif", False)]),
    # the first part wins a shared Content-ID
    "second part sharing a Content-ID": (lambda: related('<img src="cid:dup@x">',
                                                         part("image/png", PNG, cid="dup@x", disp="inline", name="a.png"),
                                                         part("image/png", PNG, cid="dup@x", disp="inline", name="b.png")),
                                         [("a.png", True), ("b.png", False)]),
    # nameless parts: listed with a generated name; inline only when embedded
    "nameless pdf": (lambda: mixed("<p>see attached</p>", part("application/pdf", M.PDF, b="B")),
                     [("part-1.pdf", False)]),
    "nameless unreferenced image": (lambda: related("<p>no images</p>", part("image/png", PNG, cid="n@x")),
                                    [("part-1.1.png", False)]),
    "nameless embedded image": (lambda: related('<img src="cid:e@x">', part("image/png", PNG, cid="e@x")),
                                [("part-1.1.png", True)]),
    "single-part nameless pdf": (lambda: M.raw_message(HEAD + "Content-Type: application/pdf\n"
                                                       "Content-Transfer-Encoding: base64\n\n" + b64(M.PDF)),
                                 [("part-root.pdf", False)]),
    "text part beside the related root": (lambda: related("<p>root</p>", "--R\nContent-Type: text/plain\n\nnotes\n"),
                                          [("part-1.1.txt", False)]),
    # every text part under a non-chosen alternative child is an alternative of the body;
    # anything else there is listed
    "calendar alternative": (calendar_alternative, []),
    "AMP alternative": (lambda: alternative(("text/plain", "hi"), ("text/x-amp-html", "<html amp4email></html>"),
                                            ("text/html", "<p>hi</p>")), []),
    "watch-html alternative": (lambda: alternative(("text/plain", "hi"), ("text/watch-html", "<p>hi</p>"),
                                                   ("text/html", "<p>hi</p>")), []),
    "pdf inside an alternative not shown": (lambda: M.raw_message(
        HEAD + 'Content-Type: multipart/alternative; boundary="A"\n\n'
        '--A\nContent-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nplain\n'
        + part("application/pdf", M.PDF, b="B") + "--B--\n--A\nContent-Type: text/html\n\n<p>rich</p>\n--A--\n"),
        [("part-0.1.pdf", False)]),
    # a repeated src attribute: browsers keep the first, and so does the view
    "repeated src attribute": (lambda: related('<img src="cid:a@x" src="cid:b@x">',
                                               part("image/png", PNG, cid="a@x", disp="inline", name="a.png"),
                                               part("image/png", PNG, cid="b@x", disp="inline", name="b.png")),
                               [("a.png", True), ("b.png", False)]),
    # the first part wins a Content-ID whatever its type: here a PDF, so nothing is embedded
    "pdf first in a shared Content-ID": (lambda: related('<img src="cid:s@x">',
                                                         part("application/pdf", M.PDF, cid="s@x", disp="inline",
                                                              name="doc.pdf"),
                                                         part("image/png", PNG, cid="s@x", disp="inline", name="pic.png")),
                                         [("doc.pdf", False), ("pic.png", False)]),
    # the two cases from addendum 2
    "reference differs only in case": (lambda: related('<img src="cid:Logo@X">', part("image/png", PNG, cid="logo@x",
                                                                                     disp="inline", name="logo.png")),
                                       [("logo.png", True)]),
    "reference outside the related scope": (lambda: mixed('<img src="cid:out@x">', part("image/png", PNG, cid="out@x",
                                                                                       disp="inline", name="out.png", b="B")),
                                            [("out.png", False)]),
    # decision 1: embedded, but the sender marked it an attachment
    "attachment-marked embedded image": (lambda: related('<img src="cid:a@x">', part("image/png", PNG, cid="a@x",
                                                                                    disp="attachment", name="a.png")),
                                         [("a.png", False)]),
}
