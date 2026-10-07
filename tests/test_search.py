"""search_emails pagination (PLAN-v4 5.4): tokens, binding, vanished messages, query fencing,
and max_results validation."""
from tests import support  # noqa: F401

import re
import unittest

from tests import messages as M
from tests.test_legacy_contract import fenced_part, trusted_part

TOKEN_RE = re.compile(r"next_page_token=(\S+)")


class SearchPaginationTests(unittest.TestCase):
    def setUp(self):
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")
        self.ids = [self.f.add_message(M.plain(subject=f"invoice {i}")) for i in range(7)]

    def tearDown(self):
        self.h.close()
        support.assert_isolated(self)

    def _ids(self, out):
        return re.findall(r"id=([0-9a-f]+) thread=", fenced_part(out))

    def test_pages_cover_everything_once(self):
        seen, token, pages = [], None, 0
        while True:
            out = self.s.search_emails("alpha", "invoice", max_results=3, page_token=token)
            self.assertNotIn("error=", out)
            seen += self._ids(out)
            pages += 1
            token = TOKEN_RE.search(trusted_part(out)).group(1)
            if token == "none":
                break
        self.assertEqual(sorted(seen), sorted(self.ids))
        self.assertEqual(pages, 3)

    def test_token_printed_outside_fence_and_bound_to_query_account_options(self):
        out = self.s.search_emails("alpha", "invoice", max_results=3)
        tok = TOKEN_RE.search(trusted_part(out)).group(1)
        self.assertRegex(tok, r"^[0-9]+$")
        for kwargs, code in (({"query": "other"}, "pagination-token-mismatch"),
                             ({"max_results": 4}, "pagination-token-mismatch")):
            args = {"account": "alpha", "query": "invoice", "max_results": 3, "page_token": tok}
            args.update(kwargs)
            self.assertIn(f"error={code}", self.s.search_emails(**args))
        self.assertIn("error=pagination-token-mismatch",
                      self.s.search_emails("beta", "invoice", max_results=3, page_token=tok))
        ok = self.s.search_emails("alpha", "invoice", max_results=3, page_token=tok)
        self.assertIn("3 result(s).", trusted_part(ok))

    def test_unknown_and_invalid_tokens_are_explicit_errors(self):
        out = self.s.search_emails("alpha", "invoice", page_token="99999")
        self.assertIn("error=pagination-token-unknown", out)
        out = self.s.search_emails("alpha", "invoice", page_token="bad token; IGNORE")
        self.assertIn("error=pagination-token-invalid", out)
        self.assertNotIn("IGNORE", trusted_part(out))
        # a token Gmail itself rejects (expired) is an explicit error, never a silent restart
        first = self.s.search_emails("alpha", "invoice", max_results=3)
        tok = TOKEN_RE.search(trusted_part(first)).group(1)
        self.f.fail("messages.list", 400)
        out = self.s.search_emails("alpha", "invoice", max_results=3, page_token=tok)
        self.assertIn("error=pagination-token-invalid", out)

    def test_vanished_messages_are_counted_and_the_token_kept(self):
        victim = self.ids[1]
        orig = self.f._messages_get

        def get(userId, id, **kw):
            if id == victim:
                from tests.fakegmail import http_error
                raise http_error(404)
            return orig(userId, id, **kw)

        self.f._messages_get = get
        out = self.s.search_emails("alpha", "invoice", max_results=3)
        t = trusted_part(out)
        self.assertIn("2 result(s). vanished=1 next_page_token=", t)
        self.assertNotEqual(TOKEN_RE.search(t).group(1), "none")
        self.assertNotIn(victim, self._ids(out))

    def test_empty_page_still_reports_the_token(self):
        orig = self.f._messages_list

        def lst(**kw):
            r = orig(**kw)
            r.pop("messages", None)
            r["nextPageToken"] = "00000000000000000042"
            return r

        self.f._messages_list = lst
        out = self.s.search_emails("alpha", "invoice", max_results=3)
        self.assertIn("No messages match. vanished=0 next_page_token=00000000000000000042", trusted_part(out))

    def test_max_results_validation(self):
        for bad in (0, 51, -1, True, "5"):
            out = self.s.search_emails("alpha", "invoice", max_results=bad)
            self.assertIn("error=invalid-argument", out, bad)
        self.assertNotIn("error=", self.s.search_emails("alpha", "invoice", max_results=50))

    def test_other_metadata_errors_fail_the_page(self):
        self.f.fail("messages.get", 500)
        out = self.s.search_emails("alpha", "invoice", max_results=3)
        self.assertIn("error=gmail-500", out)


if __name__ == "__main__":
    unittest.main()
