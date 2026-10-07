"""File-name rules (control C2), risk classification (C4), and the qbo-attach compatibility
contract (PLAN-v4 sections 1.3 and 7).

The qbo-attach rules mirrored here (its files.py / constants.py): a basename of at most
100 UTF-8 bytes; no character in Unicode categories Cc, Cf, Cs, Zl, Zp (DEL, bidi and
zero-width controls, lone surrogates, line/paragraph separators); no ASCII quote of either
kind; no slash or backslash; at most 25 MiB; PDF/JPEG/PNG identified by a signature at
byte zero with an agreeing extension (.pdf, .jpg/.jpeg, .png, case-insensitive).
"""
from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass

MAX_NAME_BYTES = 100                      # qbo-attach MAX_NAME_BYTES
QBO_MAX_FILE_BYTES = 25 * 1024 * 1024     # qbo-attach MAX_FILE_BYTES
SUFFIX_RESERVE = len(" (9999)".encode())  # room kept for a collision suffix
MAX_SUFFIX_N = 9999
MAX_EXT_BYTES = 16                        # longer "extensions" are treated as part of the stem
MAX_SUBFOLDER_DEPTH = 4
MAX_SUBFOLDER_COMPONENT_BYTES = 64

REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_REPLACE = frozenset("\"':*?<>|")
_EXT_RE = re.compile(r"^\.[A-Za-z0-9]{1,15}$")

SIGNATURES = (("pdf", b"%PDF-"), ("png", b"\x89PNG\r\n\x1a\n"), ("jpeg", b"\xff\xd8\xff"))
CANONICAL_EXT = {"pdf": ".pdf", "jpeg": ".jpg", "png": ".png"}
EXT_KIND = {".pdf": "pdf", ".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png"}


# --- C2: sanitizing ---------------------------------------------------------------------
def _strip_refused(s: str) -> str:
    return "".join(ch for ch in s if unicodedata.category(ch) not in REFUSED_CATEGORIES)


# Characters that render as blank space without being category Zs (Hangul fillers, Braille
# blank, Khmer inherent vowels): used to pad "Invoice.pdf<padding>.terminal".
BLANK_LOOKALIKES = frozenset("\u3164\u115f\u1160\uffa0\u2800\u17b4\u17b5")


def _blank(ch: str) -> bool:
    return ch != " " and (unicodedata.category(ch) == "Zs" or ch in BLANK_LOOKALIKES)


def sanitize_component(raw: str) -> str:
    """Apply the C2 character rules to ONE path component (no splitting). Beyond the plan's
    list, every other space separator and blank lookalike becomes a plain space and runs of
    spaces collapse, so padding cannot push a real extension out of view."""
    s = _strip_refused(raw or "")
    s = unicodedata.normalize("NFC", s)
    s = _strip_refused(s)
    s = "".join(" " if _blank(ch) else ch for ch in s)
    s = re.sub(" {2,}", " ", s)
    s = "".join("_" if ch in _REPLACE else ch for ch in s)
    s = s.strip(" ").lstrip(".")
    s = s.rstrip(". ")
    return s


def basename_of(raw: str) -> str:
    """Split on / and \\ and keep the last component (C2)."""
    return re.split(r"[/\\]", raw or "")[-1]


def _utf8_truncate(s: str, limit: int) -> str:
    if limit <= 0:
        return ""
    b = s.encode("utf-8")
    if len(b) <= limit:
        return s
    return b[:limit].decode("utf-8", errors="ignore")


def split_ext(name: str) -> tuple[str, str]:
    """(stem, extension). Only a short alphanumeric suffix counts as an extension."""
    stem, ext = os.path.splitext(name)
    if ext and _EXT_RE.match(ext) and stem:
        return stem, ext
    return name, ""


def sniff(head: bytes) -> str | None:
    """The kind a signature at byte zero identifies (qbo-attach's exact rule), or None."""
    for kind, sig in SIGNATURES:
        if head.startswith(sig):
            return kind
    return None


@dataclass(frozen=True)
class NamePlan:
    stem: str
    ext: str
    original_ext: str
    extension_corrected: bool

    def candidate(self, n: int) -> str:
        return f"{self.stem} ({n}){self.ext}" if n > 1 else f"{self.stem}{self.ext}"


def plan_name(original: str | None, fallback: str, detected_kind: str | None) -> NamePlan:
    """Build the final-name plan for an export: C2 sanitizing, extension from the detected
    type where known (only the extension is corrected), unknown extensions bounded, and
    room for the collision suffix and extension reserved before truncating."""
    base = sanitize_component(basename_of(original or ""))
    if not base:
        base = sanitize_component(fallback) or "file"
    stem, ext = split_ext(base)
    original_ext = ext.lower()
    corrected = False
    if detected_kind in CANONICAL_EXT and EXT_KIND.get(ext.lower()) != detected_kind:
        ext, corrected = CANONICAL_EXT[detected_kind], True
    budget = MAX_NAME_BYTES - SUFFIX_RESERVE - len(ext.encode())
    stem = _utf8_truncate(stem, budget).rstrip(". ")
    if not stem:
        fb_stem, _ = split_ext(sanitize_component(fallback) or "file")
        stem = _utf8_truncate(fb_stem, budget).rstrip(". ") or "file"
    return NamePlan(stem=stem, ext=ext, original_ext=original_ext, extension_corrected=corrected)


def parse_subfolder(sub) -> list[str]:
    """Validate the `subfolder` argument (C2): relative only, no '.'/'..' components, the
    same character rules per component, a byte limit, and a depth limit. Raises ValueError
    with a fixed reason code."""
    if sub is None or sub == "":
        return []
    if not isinstance(sub, str):
        raise ValueError("subfolder-not-text")
    if sub.startswith(("/", "\\", "~")) or re.match(r"^[A-Za-z]:", sub):
        raise ValueError("subfolder-absolute")
    out = []
    for comp in re.split(r"[/\\]", sub):
        if comp == "":
            continue
        if comp in (".", ".."):
            raise ValueError("subfolder-dot-component")
        c = sanitize_component(comp)
        if not c:
            raise ValueError("subfolder-empty-component")
        if len(c.encode()) > MAX_SUBFOLDER_COMPONENT_BYTES:
            raise ValueError("subfolder-component-too-long")
        out.append(c)
    if len(out) > MAX_SUBFOLDER_DEPTH:
        raise ValueError("subfolder-too-deep")
    return out


# --- C4: risk classification --------------------------------------------------------------
RISKY_EXTENSIONS = frozenset("""
.app .applescript .action .bash .bat .cmd .com .command .cpl .csh .dll .dmg .docm .dotm .exe
.fileloc .gadget .hta .htm .html .inetloc .iso .jar .js .jse .ksh .lnk .mht .mhtml .mpkg .msc .msi
.msp .pif .pkg .pl .potm .ppam .pptm .ps1 .psm1 .py .rb .reg .scpt .scptd .scr .sh .shtml .sldm
.svg .terminal .tool .url .vb .vbe .vbs .webloc .workflow .ws .wsf .wsh .xhtml .xlam .xlsm .xltm
.zsh .zip .rar .7z .tar .gz .tgz .bz2 .xz .cab .img .vhd .eml .xml .chm .desktop .appimage .deb .rpm
.shortcut .mobileconfig .xip .prefpane .kext .plugin .bundle .saver .wdgt .dylib .so .appex .osax
.qlgenerator .mdimporter .webarchive .configprofile .scptd .install .run
""".split())
RISKY_MIME_PREFIXES = (
    "application/x-msdownload", "application/x-ms", "application/x-sh", "application/x-csh",
    "application/javascript", "text/javascript", "application/x-javascript", "text/html",
    "application/xhtml", "image/svg", "application/x-apple-diskimage", "application/java",
    "application/x-executable", "application/x-mach", "application/vnd.ms-office.vbaproject",
    "application/zip", "application/x-zip", "application/x-rar", "application/x-7z",
    "application/x-tar", "application/gzip", "message/rfc822", "application/hta",
    "application/x-bat", "application/x-msi", "application/x-apple-",
)
_EXEC_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
               b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"#!")
_ACTIVE_TEXT_RE = re.compile(rb"^\s*(<!doctype\s+html|<html|<script|<svg|<\?xml)", re.I)
_OFFICE_ZIP_EXTS = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".numbers", ".pages", ".key"})


def risk_reasons(original_name: str, final_name: str, declared_mime: str, head: bytes) -> list[str]:
    """Why a saved file is risky to open (empty list = no known risk). Classified from the
    original and final extensions (every short suffix, for double extensions), the declared
    MIME type, and the detected content."""
    reasons = []
    orig_base = basename_of(original_name or "")
    suffixes = {("." + s).lower() for s in orig_base.split(".")[1:][-3:]}
    suffixes.add(os.path.splitext(final_name)[1].lower())
    if suffixes & RISKY_EXTENSIONS:
        reasons.append("risky-extension")
    mt = (declared_mime or "").lower()
    if any(mt.startswith(p) for p in RISKY_MIME_PREFIXES):
        reasons.append("risky-mime-type")
    if any(head.startswith(m) for m in _EXEC_MAGIC):
        reasons.append("executable-content")
    elif head.startswith(b"PK\x03\x04") and os.path.splitext(final_name)[1].lower() not in _OFFICE_ZIP_EXTS:
        reasons.append("archive-content")
    elif _ACTIVE_TEXT_RE.match(head[:1024].lstrip(b"\xef\xbb\xbf")):
        reasons.append("active-content")
    orig = original_name or ""
    if (any(unicodedata.category(ch) in REFUSED_CATEGORIES or _blank(ch) for ch in orig)
            or re.search(" {3,}", orig)):
        reasons.append("disguised-name")
    return reasons


# --- section 7: qbo-attach compatibility ----------------------------------------------------
def qbo_check(name: str, size: int, head: bytes, regular: bool = True) -> tuple[bool, str]:
    """(compatible, reason). `reason` is a fixed code; "ok" when compatible."""
    if not regular:
        return False, "not-regular-file"
    if not name or name in (".", ".."):
        return False, "no-usable-name"
    try:
        enc = name.encode("utf-8")
    except UnicodeEncodeError:
        return False, "name-not-utf8"
    if len(enc) > MAX_NAME_BYTES:
        return False, "name-too-long"
    for ch in name:
        if unicodedata.category(ch) in REFUSED_CATEGORIES:
            return False, "name-control-or-bidi"
        if ch in "\"'":
            return False, "name-quote"
        if ch in "/\\":
            return False, "name-slash"
    if size > QBO_MAX_FILE_BYTES:
        return False, "too-large"
    kind = sniff(head)
    if kind is None:
        return False, "unsupported-type"
    if EXT_KIND.get(os.path.splitext(name)[1].lower()) != kind:
        return False, "extension-mismatch"
    return True, "ok"
