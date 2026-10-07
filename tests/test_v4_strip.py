"""read_email's v4 HTML stripper: linear-time replacement with output identical to the v4
regexes (fuzzed), so a hostile email can no longer freeze the server."""
from tests import support  # noqa: F401

import html
import random
import re
import time
import unittest

import gmail


def v4_strip(html_text: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html_text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


TOKENS = ["<script>", "<SCRIPT a=1>", "<Script\n>", "</script>", "</SCRIPT>", "</sCrIpT>", "<style>", "<STYLE x>",
          "</style>", "</Style>", "<", ">", "<>", "a", "b ", " ", "\n", "<b>", "</b>", "<scriptx>", "<styles>",
          "</scripts>", "<sc", "ript>", "&amp;", "&lt;", "<p class='x'>", "</ p>", "<<", ">>", "<!-- c -->",
          "<script", "style>", "</script", "é", "<a\nhref=x>"]


class StripEquivalenceTests(unittest.TestCase):
    def test_fuzz_identical_to_v4(self):
        rnd = random.Random(20261004)
        for _ in range(30000):
            s = "".join(rnd.choice(TOKENS) for _ in range(rnd.randint(0, 30)))
            self.assertEqual(gmail._strip_html(s), v4_strip(s), repr(s))

    def test_pathological_inputs_are_fast(self):
        for s in ("<script>" * 200000, "<" * 400000, "<style a" * 100000, ("<script>x" * 50000) + "</script>"):
            t0 = time.monotonic()
            gmail._strip_html(s)
            self.assertLess(time.monotonic() - t0, 3.0)


if __name__ == "__main__":
    unittest.main()
