"""Body selection, CID scope, the allowlist sanitizer, the header block, the
authentication line, and the wrapper (PLAN-v4 5.2, 9.2 steps 1-2)."""
from tests import support  # noqa: F401

import re
import unittest

import htmlview
from tests import messages as M


def view_of_html(html: str, **kw) -> htmlview.View:
    return htmlview.build_view(M.with_attachments([], html=html, **kw))


def body(v: htmlview.View) -> str:
    """The body fragment; a single section's wrapper is removed."""
    page = v.page.decode()
    inner = page[page.index('-body">') + 7: page.rindex("</div></body>")]
    m = re.fullmatch(r'<div class="gmcp[0-9a-f]{10}-section">(.*)</div>', inner, re.S)
    return m.group(1) if m and inner.count('-section">') == 1 else inner


class SanitizerTests(unittest.TestCase):
    def assertGone(self, html, *needles):
        b = body(view_of_html(html)).lower()
        for n in needles:
            self.assertNotIn(n.lower(), b, f"{n!r} survived in {b!r}")
        return b

    def test_scripts_handlers_and_js_urls_removed(self):
        b = self.assertGone(
            '<div id=x onclick="alert(1)">A</div><script>alert(2)</script><img src=x onerror=alert(3)>'
            '<a href="javascript:alert(4)">L</a><a href=" jav&#x61;script:alert(5)">M</a>'
            '<a href="java\tscript:alert(6)">N</a><iframe src="javascript:alert(7)"></iframe>'
            '<body onload="alert(8)">', "onclick", "alert", "onerror", "javascript", "<script", "<iframe", "onload")
        self.assertIn(">a</div>", b)
        self.assertIn(">l</a>", b)

    def test_meta_base_link_form_object_embed_svg_math_removed(self):
        self.assertGone(
            '<meta http-equiv="refresh" content="0;url=file:///etc/passwd"><base href="file:///">'
            '<link rel=stylesheet href="http://x/s.css"><form action="http://x"><input name=a></form>'
            '<object data="file:///x"></object><embed src="file:///x"><applet></applet>'
            '<svg><script>alert(1)</script><foreignObject><img src=x></foreignObject></svg>'
            '<math><mtext><script>alert(2)</script></mtext></math><noscript><img src=x></noscript>'
            '<frameset><frame src="file:///x"></frameset><template><img src=x></template>',
            "<meta", "<base", "<link", "<form", "<input", "<object", "<embed", "<applet", "<svg", "<math",
            "<noscript", "<frame", "<template", "file:", "alert", "http://x")

    def test_remote_and_relative_images_are_never_kept(self):
        v = view_of_html('<img src="https://tracker.example/p.gif"><img src="//x.example/a.png">'
                         '<img src="file:///etc/hosts"><img src="rel.png"><div style="x">t</div>')
        b = body(v)
        self.assertNotIn("src=", b)
        self.assertEqual(v.remote_images, 4)

    def test_style_cannot_break_out(self):
        b = body(view_of_html("<style>p{color:red}</style><p>x</p><style></style><script>alert(1)</script>"
                              "</style><p>y</p>"))
        self.assertNotIn("<script", b)
        b2 = body(view_of_html("<style>a{}</STYLE ><b>ok</b>"))
        self.assertIn("<b>ok</b>", b2)
        b3 = body(view_of_html("<style>x{content:'</style><img src=x onerror=alert(1)>'}</style>"))
        self.assertNotIn("onerror", b3)

    def test_malformed_and_entity_cases_are_escaped(self):
        b = body(view_of_html('<div title="a&quot; onmouseover=&quot;x">1</div><p>&lt;script&gt;</p>'
                              '<<img src=x>><a href="https://ok.example/?a=1&amp;b=2">ok</a></a></a><div'))
        self.assertIn('title="a&quot; onmouseover=&quot;x"', b)
        self.assertIn("&lt;script&gt;", b)
        self.assertNotIn("<script", b)
        self.assertIn('href="https://ok.example/?a=1&amp;b=2"', b)

    def test_only_allowlisted_attributes(self):
        b = body(view_of_html('<table background="http://x/b.png" cellpadding=2><tr><td colspan=2 '
                              'style="color:red" formaction=x data-x=1>c</td></tr></table>'
                              '<img src="data:image/png;base64,iVBORw0KGgo=" srcset="http://x 2x" name=fonts>'))
        self.assertNotIn("background", b)
        self.assertNotIn("formaction", b)
        self.assertNotIn("data-x", b)
        self.assertNotIn("srcset", b)
        self.assertNotIn("name=", b)
        self.assertIn('colspan="2"', b)
        self.assertIn('src="data:image/png;base64,iVBORw0KGgo="', b)

    def test_rawtext_elements_drop_content(self):
        b = body(view_of_html("<title>T</title><textarea><b>x</b></textarea><xmp><i>y</i></xmp>"
                              "<noembed><u>z</u></noembed><p>keep</p>"))
        self.assertEqual(b.strip(), "<p>keep</p>")

    def test_unknown_wrappers_keep_text(self):
        b = body(view_of_html("<html><body><o:p>Outlook</o:p><form><button>Btn</button></form></body></html>"))
        self.assertIn("Outlook", b)
        self.assertIn("Btn", b)


class SelectionAndCidTests(unittest.TestCase):
    def test_alternative_prefers_html(self):
        v = htmlview.build_view(M.with_attachments([], html="<p>HTML VERSION</p>", text="TEXT VERSION"))
        self.assertIn("HTML VERSION", body(v))
        self.assertEqual([x["content_type"] for x in v.body_part["sections"]], ["text/html"])

    def test_plain_text_is_escaped(self):
        v = htmlview.build_view(M.plain(text="<script>alert(1)</script>\n& more"))
        b = body(v)
        self.assertIn("&lt;script&gt;", b)
        self.assertIn("white-space:pre-wrap", v.page.decode())

    def test_cid_inside_scope_becomes_data_uri(self):
        v = htmlview.build_view(M.related_html('<img src="cid:logo@x"><img src="cid:missing@x">',
                                               [(M.PNG_1x1, "png", "logo@x", "logo.png")]))
        b = body(v)
        self.assertEqual(len(re.findall(r'src="data:image/png;base64,', b)), 1)
        self.assertIn("missing-cid", v.warnings)
        self.assertEqual(v.cid_used, 1)

    def test_cid_outside_related_scope_is_not_resolved(self):
        raw = M.with_attachments([(M.PNG_1x1, "image", "png", "logo.png", "inline")],
                                 html='<img src="cid:logo@x">')
        raw = raw.replace(b"Content-Disposition: inline", b"Content-ID: <logo@x>\nContent-Disposition: inline")
        v = htmlview.build_view(raw)
        self.assertNotIn("data:image", body(v))
        self.assertIn("missing-cid", v.warnings)

    def test_attachments_and_nested_messages_are_never_the_body(self):
        inner = M.plain(text="INNER BODY", subject="Inner")
        v = htmlview.build_view(M.with_attached_message(inner))
        self.assertNotIn("INNER BODY", body(v))
        raw = M.raw_message("From: a@example.test\nSubject: s\nMIME-Version: 1.0\n"
                            "Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/html\n"
                            "Content-Disposition: attachment; filename=a.html\n\nATTACHED HTML\n--b--\n")
        v2 = htmlview.build_view(raw)
        self.assertNotIn("ATTACHED HTML", body(v2))
        self.assertIn("no-displayable-body", v2.warnings)

    def test_related_start_parameter(self):
        raw = M.raw_message(
            "From: a@example.test\nSubject: s\nMIME-Version: 1.0\n"
            'Content-Type: multipart/related; boundary=b; start="<root@x>"\n\n'
            "--b\nContent-Type: text/html\nContent-ID: <decoy@x>\n\nDECOY\n"
            "--b\nContent-Type: text/html\nContent-ID: <root@x>\n\nREAL ROOT\n--b--\n")
        v = htmlview.build_view(raw)
        self.assertIn("REAL ROOT", body(v))
        self.assertNotIn("DECOY", body(v))


class HeaderAndWrapperTests(unittest.TestCase):
    def test_csp_and_charset_come_first(self):
        v = view_of_html("<p>x</p>", subject='<script>alert("s")</script>')
        page = v.page.decode()
        head = page[page.index("<head>") + 6:]
        self.assertTrue(head.startswith('<meta charset="utf-8"><meta http-equiv="Content-Security-Policy"'))
        self.assertIn("default-src &#x27;none&#x27;; img-src data:", page)
        self.assertNotIn('<script>alert("s")', page)
        self.assertIn("&lt;script&gt;", page[page.index("<title>"):page.index("</title>")])

    def test_header_values_escaped_and_date_is_message_text(self):
        v = htmlview.build_view(M.raw_message(
            'From: "Evil <b>bold</b>" <evil@example.test>\nSubject: s\n'
            "Date: Thu, 01 Jan 2026 00:00:00 +0000\n (made up)\n\nbody\n"))
        page = v.page.decode()
        self.assertNotIn("<b>bold</b>", page)
        self.assertIn("Thu, 01 Jan 2026 00:00:00 +0000 (made up)", page)

    def test_auth_line_rules(self):
        ar = "Authentication-Results"
        good = (ar, "mx.google.com; dkim=pass header.i=@example.test; spf=pass (google.com: ok) smtp.mailfrom=x; dmarc=pass")
        other = (ar, "evil.example; dkim=pass")
        conflict = (ar, "mx.google.com; dkim=fail")
        bad = (ar, "; = ;;")
        label = "Authentication-Results reported in message (not independently verified)"
        self.assertIn(f"{label}: mx.google.com dkim=pass dmarc=pass spf=pass",
                      htmlview.build_view(M.plain(extra_headers=[good])).page.decode())
        self.assertIn(f"{label}: unavailable", htmlview.build_view(M.plain(extra_headers=[other])).page.decode())
        self.assertIn("ambiguous", htmlview.build_view(M.plain(extra_headers=[good, conflict])).page.decode())
        self.assertIn("unavailable (malformed)", htmlview.build_view(M.plain(extra_headers=[bad])).page.decode())

    def test_inputs_key_tracks_inputs_not_output(self):
        a = htmlview.build_view(M.plain(text="one"))
        b = htmlview.build_view(M.plain(text="one"))
        c = htmlview.build_view(M.plain(text="two"))
        self.assertEqual(a.inputs_key, b.inputs_key)
        self.assertNotEqual(a.inputs_key, c.inputs_key)

    def test_size_bound(self):
        with self.assertRaises(htmlview.ViewError) as cm:
            htmlview.build_view(M.plain(text="x" * (htmlview.MAX_PAGE_BYTES + 10)))
        self.assertEqual(cm.exception.code, "html-too-large")


if __name__ == "__main__":
    unittest.main()
