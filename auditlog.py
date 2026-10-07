"""Append-only audit log for the Gmail MCP server.

Writes one JSON line per tool invocation to <runtime root>/audit.log (0600, rotating); the
runtime root is ~/.gmail-mcp-private unless GMAIL_MCP_RUNTIME_DIR is set (tests).
Logs NON-CONTENT metadata only — tool name, account alias, ids, counts, lengths, hashes,
fixed flags — never email bodies, subjects, recipients, label names, filter criteria, or
query text. Logging must never break a tool, so errors are caught; but since v5 a failed
write is REPORTED (log() returns False) so the caller can surface a fixed "audit degraded"
diagnostic instead of hiding it. The handler forces 0600 on the base file AND every
rotated file.
"""
from __future__ import annotations

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler

import runtime

CONFIG_DIR = runtime.root()
LOG_FILE = CONFIG_DIR / "audit.log"

# File extensions recorded in the audit come from this allowlist; anything else is
# recorded as "unknown" (an extension can carry attacker-chosen text).
EXTENSION_ALLOWLIST = frozenset({
    "pdf", "jpg", "jpeg", "png", "gif", "webp", "heic", "tif", "tiff", "bmp", "svg",
    "txt", "csv", "html", "htm", "eml", "ics", "vcf", "xml", "json",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "rtf",
    "zip", "gz", "7z", "rar", "tar", "dat", "bin", "exe", "dmg", "pkg", "js", "sh",
})

_logger: logging.Logger | None = None


def ext_for_audit(name: str | None) -> str:
    """Map a file name to an allowlisted extension, or 'unknown'."""
    if not name or "." not in name:
        return "unknown"
    ext = name.rsplit(".", 1)[1].lower()
    return ext if ext in EXTENSION_ALLOWLIST else "unknown"


class _Mode600RotatingHandler(RotatingFileHandler):
    """RotatingFileHandler that creates the base file — and every file produced on rollover —
    with 0600 perms (the stock handler re-creates the base file at the default umask), and
    that lets write failures propagate to log() instead of printing them."""

    def _open(self):
        old = os.umask(0o077)
        try:
            stream = super()._open()
        finally:
            os.umask(old)
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            pass
        return stream

    def handleError(self, record):  # noqa: N802 (logging API name)
        raise  # re-raise the active exception; log() turns it into "degraded"


def _get_logger() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    runtime.private_dir()
    lg = logging.getLogger("gmail-mcp-private.audit")
    lg.setLevel(logging.INFO)
    lg.propagate = False
    if not lg.handlers:
        handler = _Mode600RotatingHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3)
        handler.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(handler)
    _logger = lg
    return lg


def log(event: str, account: str = "", **meta) -> bool:
    """Record a non-content event line. Never raises. Returns True when the line was
    written, False when auditing is degraded (the caller reports a fixed diagnostic)."""
    try:
        rec = {"ts": round(time.time(), 3), "event": event, "account": account}
        rec.update(meta)
        _get_logger().info(json.dumps(rec, ensure_ascii=False))
        return True
    except Exception:
        return False
