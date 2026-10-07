"""Test isolation. Import this module FIRST in every test module.

- The runtime root is injected (GMAIL_MCP_RUNTIME_DIR) to a throwaway folder inside the
  worktree's gitignored .test-tmp/, so tests never touch ~/.gmail-mcp-private.
- A tripwire `keyring` module replaces the real one: any Keychain access is recorded and
  fails, and the suite asserts it never happened.
- TMPDIR points into the test root, so nothing lands in /tmp.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import time
import types

REPO = pathlib.Path(__file__).resolve().parents[1]
TEST_TMP = REPO / ".test-tmp"
RUNS = TEST_TMP / "runs"

KEYCHAIN_CALLS: list[str] = []


def _install_keyring_tripwire() -> None:
    mod = types.ModuleType("keyring")

    def _trip(*a, **k):
        KEYCHAIN_CALLS.append("keyring")
        raise RuntimeError("Keychain access is forbidden in tests")

    mod.get_password = _trip
    mod.set_password = _trip
    mod.delete_password = _trip
    sys.modules["keyring"] = mod


def _prune_old_runs(keep: int = 3) -> None:
    if not RUNS.exists():
        return
    runs = sorted((p for p in RUNS.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime)
    for old in runs[:-keep]:
        shutil.rmtree(old, ignore_errors=True)


def _setup() -> pathlib.Path:
    if os.environ.get("GMAIL_MCP_TEST_RUN_DIR"):
        run = pathlib.Path(os.environ["GMAIL_MCP_TEST_RUN_DIR"])
    else:
        RUNS.mkdir(parents=True, exist_ok=True)
        _prune_old_runs()
        run = RUNS / f"run-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
        run.mkdir(parents=True, exist_ok=True)
        os.environ["GMAIL_MCP_TEST_RUN_DIR"] = str(run)  # inherited by helper subprocesses
    rt = run / "runtime"
    rt.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(rt, 0o700)
    tmp = run / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    exports = run / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    os.environ["GMAIL_MCP_RUNTIME_DIR"] = str(rt)
    # Keep an inherited config path only if a test created it inside this run directory;
    # anything else (e.g. a real config from the shell) is replaced by the test config.
    inherited = os.environ.get("GMAIL_MCP_CONFIG", "")
    if not inherited or not pathlib.Path(inherited).resolve().is_relative_to(run.resolve()):
        os.environ["GMAIL_MCP_CONFIG"] = str(rt / "accounts.json")
    os.environ["TMPDIR"] = str(tmp) + "/"
    os.environ.pop("GMAIL_MCP_ALLOW_SEND", None)
    import tempfile

    tempfile.tempdir = str(tmp)
    cfg_path = rt / "accounts.json"
    if not cfg_path.exists():
        write_config(cfg_path, default_config(exports))
    return run


def default_config(exports_root: pathlib.Path) -> dict:
    return {
        "accounts": [
            {"alias": "alpha", "email": "alpha@example.test", "scope": "modify"},
            {"alias": "beta", "email": "beta@example.test", "scope": "modify"},
        ],
        "enable_send": False,
        "export_roots": {"default": str(exports_root)},
    }


def write_config(path: pathlib.Path, cfg: dict) -> None:
    path.write_text(json.dumps(cfg, indent=2))
    os.chmod(path, 0o600)


_install_keyring_tripwire()
RUN_DIR = _setup()
RUNTIME_DIR = RUN_DIR / "runtime"
EXPORTS_DIR = RUN_DIR / "exports"
SIZE = 64 * 1024        # a small message's Gmail sizeEstimate, for tests that do not exercise that bound


def scratch(name: str) -> pathlib.Path:
    """A fresh per-test scratch folder inside the run directory."""
    p = RUN_DIR / "scratch" / f"{name}-{time.monotonic_ns()}"
    p.mkdir(parents=True)
    return p


def assert_isolated(testcase) -> None:
    """Every test module calls this in tearDownModule-style checks."""
    import runtime

    real = pathlib.Path(os.path.expanduser("~/.gmail-mcp-private"))
    testcase.assertNotEqual(runtime.root(), real)
    testcase.assertEqual(KEYCHAIN_CALLS, [], "a test touched the Keychain")


class FakeCreds:
    def __init__(self, alias: str):
        self.alias = alias


class ServerHarness:
    """Imports server.py against the test runtime root and routes every Gmail call for an
    alias to an in-memory FakeGmail. The real identity check in server._creds runs against
    the fake's profile address."""

    def __init__(self):
        import auth
        import gmail
        import server
        from tests.fakegmail import FakeGmail

        self.server = server
        self.fakes = {a["alias"]: FakeGmail(a["email"]) for a in server.CONFIG.get("accounts", [])}
        self._orig = (auth.get_credentials, gmail.service)
        auth.get_credentials = lambda alias, scopes: FakeCreds(alias)
        gmail.service = lambda creds: self.fakes[creds.alias]
        server._verified.clear()

    def fake(self, alias: str = "alpha"):
        return self.fakes[alias]

    def close(self):
        import auth
        import gmail

        auth.get_credentials, gmail.service = self._orig
        self.server._verified.clear()


def tool_names(server_module) -> set[str]:
    import asyncio

    return {t.name for t in asyncio.run(server_module.mcp.list_tools())}
