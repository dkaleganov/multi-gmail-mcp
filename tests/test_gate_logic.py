"""The process-containment gate's decision, on synthetic process tables (no Chrome): it leaves
out new helpers of a browser that was already running, and it must still FAIL if the
renderer ever stopped starting Chrome in its own process group (the exemption relies on it)."""
from tests import support  # noqa: F401

import importlib.util
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location(
    "render_gates_under_test", pathlib.Path(__file__).resolve().parents[1] / "tools" / "render_gates.py")
rg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rg)

T0 = 1_800_000_000.0
RDIR = "/runtime/render-tmp/r-abc"
GATE_PID, GATE_PGID = 100, 90           # the gate process and its group (its shell leads it)
BROWSER = 200


def table(**over):
    """A normal render: the gate's shell and process, the render browser leading its own group,
    one helper, the crash handler re-parented to launchd, and your own Chrome with a helper
    that happened to start during the render."""
    procs = {
        90: (1, 90, T0 - 9000, "-zsh"),
        GATE_PID: (90, GATE_PGID, T0 - 600, "python3 tools/render_gates.py"),
        BROWSER: (GATE_PID, BROWSER, T0 + 1, f"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir={RDIR}/profile"),
        201: (BROWSER, BROWSER, T0 + 2, "Google Chrome Helper (Renderer) --type=renderer"),
        202: (1, 202, T0 + 2, f"chrome_crashpad_handler --database={RDIR}/crashpad --url=x"),
        300: (1, 300, T0 - 90000, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        301: (300, 300, T0 + 3, "Google Chrome Helper (Renderer) --type=renderer"),
    }
    procs.update(over)
    return procs


def verdict(procs):
    c = rg.classify_chrome_processes(procs, T0, BROWSER, BROWSER, RDIR, GATE_PID, GATE_PGID)
    return rg.containment_ok(c), c


class ContainmentGateLogic(unittest.TestCase):
    def test_normal_render_passes_and_leaves_out_your_own_browsers_helper(self):
        ok, c = verdict(table())
        self.assertTrue(ok)
        self.assertEqual((c["excluded"], len(c["rows"]), c["browser_own_group"]), (1, 3, True))

    def test_fails_if_chrome_joins_the_gates_process_group(self):
        # the renderer stops starting Chrome in its own group: browser and helper inherit the
        # gate's group; the browser's parent (the gate) and that group's leader (its shell)
        # both predate the gate, which is exactly what the exemption looks for
        procs = table()
        procs[BROWSER] = (GATE_PID, GATE_PGID) + procs[BROWSER][2:]
        procs[201] = (BROWSER, GATE_PGID) + procs[201][2:]
        ok, c = verdict(procs)
        self.assertFalse(ok)
        self.assertFalse(c["browser_own_group"])
        self.assertEqual(c["excluded"], 1)                  # only your own browser's helper is left out

    def test_fails_if_a_process_escapes_to_a_new_group(self):
        ok, c = verdict({**table(), 400: (1, 400, T0 + 2, "Google Chrome Helper --type=utility")})
        self.assertFalse(ok)
        self.assertEqual(len(rg.outside_rows(c)), 1)

    def test_fails_if_the_crash_handler_uses_another_database(self):
        procs = table()
        procs[202] = (1, 202, T0 + 2, "chrome_crashpad_handler --database=/Users/x/Library/Application Support/Google/Chrome/Crashpad --url=x")
        ok, c = verdict(procs)
        self.assertFalse(ok)
        self.assertEqual(len(rg.bad_db_rows(c)), 1)

    def test_fails_if_the_browser_is_missing_from_the_table(self):
        procs = table()
        del procs[BROWSER]
        self.assertFalse(verdict(procs)[0])


if __name__ == "__main__":
    unittest.main()
