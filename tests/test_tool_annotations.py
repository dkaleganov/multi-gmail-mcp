"""Tool titles and MCP annotations: every tool carries a title and the hints that match it."""
from tests import support  # noqa: F401  (must be first: isolates the runtime root)

import json
import os
import subprocess
import sys
import unittest

READS = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
CHANGES_MAILBOX = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False}
WRITES_EXPORTS = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False}

# name: (title, hints, openWorldHint). Exports publish no-clobber, so they never replace a file.
EXPECTED = {
    "list_accounts": ("List Gmail accounts", READS, False),
    "search_emails": ("Search emails", READS, True),
    "read_email": ("Read one email", READS, True),
    "read_thread": ("Read an email thread", READS, True),
    "list_labels": ("List labels", READS, True),
    "list_label_operations": ("List recent label changes", READS, True),
    "modify_labels": ("Add or remove labels", CHANGES_MAILBOX, True),
    "create_draft": ("Create a draft", CHANGES_MAILBOX, True),
    "create_label": ("Create a label", CHANGES_MAILBOX, True),
    "update_label": ("Update a label", CHANGES_MAILBOX, True),
    "delete_label": ("Delete a label", CHANGES_MAILBOX, True),
    "undo_label_change": ("Undo a label change", CHANGES_MAILBOX, True),
    "send_email": ("Send an email", CHANGES_MAILBOX, True),
    "save_attachments": ("Save attachments to files", WRITES_EXPORTS, True),
    "export_email": ("Export an email to files", WRITES_EXPORTS, True),
}


class ToolAnnotationTests(unittest.TestCase):
    """Runs with send armed (both factors) and label admin on, so all 15 tools register."""

    @classmethod
    def setUpClass(cls):
        d = support.scratch("tool-annotations")
        cfg = support.default_config(support.EXPORTS_DIR)
        cfg["enable_send"] = True
        support.write_config(d / "accounts.json", cfg)
        env = dict(os.environ, GMAIL_MCP_CONFIG=str(d / "accounts.json"))
        # support clears GMAIL_MCP_ALLOW_SEND on import, so arm it afterwards
        code = ("import asyncio, json, os; from tests import support; "
                "os.environ['GMAIL_MCP_ALLOW_SEND'] = '1'; import server; "
                "tools = asyncio.run(server.mcp.list_tools()); "
                "print(json.dumps({t.name: {'title': t.title, 'annotations': None if t.annotations is None "
                "else t.annotations.model_dump(by_alias=True, exclude_none=True)} for t in tools}))")
        out = subprocess.run([sys.executable, "-c", code], cwd=support.REPO, env=env,
                             capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
        cls.tools = json.loads(out)

    def test_every_tool_is_covered(self):
        self.assertEqual(set(self.tools), set(EXPECTED))

    def test_every_tool_has_its_title_and_hints(self):
        for name, (title, hints, open_world) in EXPECTED.items():
            with self.subTest(name):
                tool = self.tools[name]
                self.assertEqual(tool["title"], title)
                self.assertEqual(tool["annotations"], {"title": title, **hints, "openWorldHint": open_world})

    def test_titles_are_unique_and_short(self):
        titles = [t["title"] for t in self.tools.values()]
        self.assertEqual(len(titles), len(set(titles)))
        for title in titles:
            self.assertTrue(0 < len(title) <= 40, title)

    def test_names_fit_the_64_character_limit(self):
        for name in self.tools:
            self.assertLessEqual(len(name), 64, name)


if __name__ == "__main__":
    unittest.main()
