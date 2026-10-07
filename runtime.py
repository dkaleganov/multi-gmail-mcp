"""Where the server keeps its private runtime state.

Everything private lives under ONE runtime root: config, tokens, the audit log, the label
journal, host locks, and renderer scratch. The default is ~/.gmail-mcp-private (unchanged
from v4). Tests inject a throwaway root with GMAIL_MCP_RUNTIME_DIR so they never touch the
real folder, tokens, or Keychain.
"""
from __future__ import annotations

import os
import pathlib
import stat

ENV_VAR = "GMAIL_MCP_RUNTIME_DIR"
DEFAULT_ROOT = "~/.gmail-mcp-private"


def root() -> pathlib.Path:
    """The runtime root. An injected root must be an absolute path: a relative one would
    silently depend on the process's working directory."""
    injected = os.environ.get(ENV_VAR)
    if injected:
        p = pathlib.Path(os.path.expanduser(injected))
        if not p.is_absolute():
            raise RuntimeError(f"{ENV_VAR} must be an absolute path.")
        return p
    return pathlib.Path(os.path.expanduser(DEFAULT_ROOT))


def config_path() -> pathlib.Path:
    """accounts.json: $GMAIL_MCP_CONFIG if set, else <runtime root>/accounts.json."""
    explicit = os.environ.get("GMAIL_MCP_CONFIG")
    if explicit:
        return pathlib.Path(os.path.expanduser(explicit))
    return root() / "accounts.json"


def private_dir(*parts: str) -> pathlib.Path:
    """Return <runtime root>/<parts...>, creating each missing level at 0700. Every level
    must be a real directory owned by this user (a symlink or foreign object is refused)."""
    cur = root()
    levels = [cur]
    for p in parts:
        if not p or p in (".", "..") or "/" in p:
            raise ValueError("invalid runtime path component")
        cur = cur / p
        levels.append(cur)
    for d in levels:
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode):
            raise RuntimeError(f"Runtime path is not a directory: {d.name}")
        if st.st_uid != os.getuid():
            raise RuntimeError(f"Runtime path is not owned by this user: {d.name}")
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.chmod(d, 0o700)
    return cur
