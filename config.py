"""Validation of the v5 settings in accounts.json (PLAN-v4 section 12).

All values are validated at startup WITHOUT changing account routing, scope selection, or
send arming (those stay in server.py exactly as in v4). An invalid value never crashes the
server: it disables only the feature it governs, fails safe, and prints a fixed warning to
stderr (never to the MCP stdio stream).

    "export_roots": {"default": "~/Downloads/gmail-exports"},
    "pdf": {"chrome_path": null, "max_pages": 50, "render_timeout_seconds": 45,
            "memory_budget_mb": null, "scratch_budget_mb": null, "monitor_interval_ms": null},
    "label_admin": true,
    "label_delete_max_messages": 10000
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

DEFAULT_EXPORT_ROOTS = {"default": "~/Downloads/gmail-exports"}
ROOT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_ROOTS = 16


def _warn(msg: str) -> None:
    print(f"[gmail-mcp-private] config: {msg}", file=sys.stderr)


@dataclass
class PdfSettings:
    chrome_path: str | None = None
    max_pages: int = 50
    render_timeout_seconds: float = 45.0
    memory_budget_mb: float | None = None
    scratch_budget_mb: float | None = None
    monitor_interval_ms: int | None = None
    problems: list[str] = field(default_factory=list)   # fixed codes; any problem disables PDF

    @property
    def budgets_set(self) -> bool:
        return (self.memory_budget_mb is not None and self.scratch_budget_mb is not None
                and self.monitor_interval_ms is not None)


@dataclass
class Settings:
    export_roots: dict[str, str]
    pdf: PdfSettings
    label_admin: bool
    label_delete_max_messages: int
    problems: list[str] = field(default_factory=list)


def _num(v, lo, hi, integer=False):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if integer and (not isinstance(v, int) or isinstance(v, bool)):
        return None
    if not (lo <= v <= hi):
        return None
    return v


def parse_pdf(raw) -> PdfSettings:
    p = PdfSettings()
    if raw is None:
        return p
    if not isinstance(raw, dict):
        p.problems.append("pdf-settings-invalid")
        return p
    cp = raw.get("chrome_path")
    if cp is not None:
        if isinstance(cp, str) and cp.startswith("/") and "\0" not in cp:
            p.chrome_path = cp
        else:
            p.problems.append("pdf-chrome-path-invalid")
    if "max_pages" in raw:
        v = _num(raw["max_pages"], 1, 1000, integer=True)
        if v is None:
            p.problems.append("pdf-max-pages-invalid")
        else:
            p.max_pages = v
    if "render_timeout_seconds" in raw:
        v = _num(raw["render_timeout_seconds"], 10, 45)
        if v is None:
            p.problems.append("pdf-timeout-invalid")   # the plan's whole-render deadline is 45 s
        else:
            p.render_timeout_seconds = float(v)
    for k, lo, hi, integer in (("memory_budget_mb", 64, 65536, False), ("scratch_budget_mb", 16, 65536, False),
                               ("monitor_interval_ms", 10, 5000, True)):
        if raw.get(k) is None:
            continue
        v = _num(raw[k], lo, hi, integer=integer)
        if v is None:
            p.problems.append(f"pdf-{k.replace('_', '-')}-invalid")
        else:
            setattr(p, k, v)
    return p


def parse(cfg: dict) -> Settings:
    problems: list[str] = []
    roots_raw = cfg.get("export_roots", DEFAULT_EXPORT_ROOTS)
    roots: dict[str, str] = {}
    if not isinstance(roots_raw, dict) or len(roots_raw) > MAX_ROOTS:
        problems.append("export-roots-invalid")
        _warn("export_roots is invalid; every export destination is disabled.")
    else:
        for name, path in roots_raw.items():
            if isinstance(name, str) and ROOT_NAME_RE.match(name) and isinstance(path, str) and path and "\0" not in path:
                roots[name] = path
            else:
                problems.append("export-root-entry-invalid")
                _warn("an export_roots entry is invalid and was disabled.")
    pdf = parse_pdf(cfg.get("pdf"))
    if pdf.problems:
        _warn("pdf settings are invalid; PDF output is disabled (" + ", ".join(pdf.problems) + ").")
    la = cfg.get("label_admin", True)
    if not isinstance(la, bool):
        problems.append("label-admin-invalid")
        _warn("label_admin must be true or false; label administration tools are NOT registered.")
        la = False
    lm = cfg.get("label_delete_max_messages", 10000)
    lm_ok = _num(lm, 1, 100000, integer=True)
    if lm_ok is None:
        problems.append("label-delete-max-invalid")
        _warn("label_delete_max_messages is invalid; delete_label refuses every deletion.")
        lm_ok = 0
    return Settings(export_roots=roots, pdf=pdf, label_admin=la, label_delete_max_messages=lm_ok, problems=problems)
