"""The sanitized, policy-wrapped HTML view of one message (PLAN-v4 5.2 and 9.2 steps 1-2).

The decoded RAW bytes are the single source. A parsed view (email.policy.default) selects
the body MIME-aware: multipart/alternative prefers HTML, multipart/related uses its root
(the `start` parameter, else the first part), attachment bodies and nested messages are
excluded, and `cid:` references resolve only within the selected related scope. Every
other multipart (multipart/mixed above all) contributes EVERY text section, in order
(owner decision, 2026-10-05): Apple Mail splits one HTML body into several sections around
inline attachments, and each section is sanitized separately with the same policy.

Embedding: only `<img src="cid:...">` is resolved, to an image part of the section's own
multipart/related whose type is one of the six data-URI image types; the Content-ID matches
exactly first, then without regard to case; when IDs repeat, the first part wins. predict()
runs this same selection, CID collection, and sanitizer without building the page, so the
attachment enumerator (mime) marks a part inline exactly when this view would embed it.

The HTML body is never passed through partial string replacement: a real HTML tokenizer
(html.parser, HTML5 raw-text/RCDATA aware in this Python) drives an ALLOWLIST rebuild.
Only allowlisted elements and attributes are re-emitted, every text node is escaped,
every attribute value is escaped and double-quoted. Prohibited outright (dropped with
their content where they have any): script, noscript, iframe, frame, frameset, object,
embed, applet, form controls, base, link, every meta, title, template, svg, math, and
media/canvas elements. Every on* attribute and every javascript: (or other non-allowlisted)
URL is dropped. Remote images are never fetched (D10): only data: images survive, so a
remote image renders blank.

The wrapped page puts the charset and the Content-Security-Policy meta element first in
<head>, before any untrusted content; the escaped header block and the sanitized fragment
go in <body>. The saved .html is exactly this page; opened later it keeps the sanitizing,
the CSP, and the quarantine attribute, but NOT the renderer's engine controls.
"""
from __future__ import annotations

import base64
import codecs
import email
import email._encoded_words
import email.errors as _email_errors
import email.feedparser
import email.header
import email.message
import email.parser
import email.policy
import functools
import hashlib
import html
import html.parser
import importlib
import json
import re
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
# the stdlib classes the view builds on, looked up so that a missing one only turns the view off
# (see STDLIB_CHANGED) instead of breaking every tool's import
HTMLParser = getattr(html.parser, "HTMLParser", object)
_BufferedSubFile = getattr(email.feedparser, "BufferedSubFile", object)
_BytesFeedParser = getattr(email.feedparser, "BytesFeedParser", object)

RECIPE_VERSION = "v5-view-7"
CSP = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; "
       "form-action 'none'; base-uri 'none'")
MAX_PAGE_BYTES = 20 * 1024 * 1024   # HTML plus inline images per render (C5 initial value)
MAX_DEPTH = 20
MAX_PARTS = 500                     # same MIME bound as the attachment enumerator (C5)
MAX_NEST = 512                      # deeper allowlisted elements are unwrapped (content kept)
VIEW_SECONDS = 20.0                 # one view build, all of it: parse, headers, selection, sanitizing
# Measured on the server host (2026-10-05): the deadline is checked often enough that a build
# ends within about 2.5 s after it (a few single steps stay whole: the stdlib's end of one
# part, one payload decode, one tag-end match). The stdlib parser keeps one string per line, so
# a crafted message at the 50 MiB export cap peaks at about 1.9 GB (macOS peak memory footprint of
# the export path, which also holds Gmail's RAW string; measured over the reviews' heaviest
# shapes); exports run one at a time.
PREDICT_SECONDS = 2.0               # predict() runs on every read_email: its content phase is short
PREDICT_MAX_INPUT = 1024 * 1024     # body bytes predict() will decode and sanitize
# The view's MIME parse, measured on the server host (2026-10-05, load 7-8, 13 crafted line
# shapes at depths 0-20): at most 0.24 s per MiB for lines at any depth, and for lines that
# start with "--" (checked against every enclosing boundary) up to 0.45 s per MiB at depth 20.
# PARSE_MIB_SECONDS + PARSE_LEVEL_SECONDS * depth bounds both with 27% to 76% headroom; a
# prediction is unavailable when the parse of a message this size could take more than
# PARSE_SHARE of VIEW_SECONDS, so the rest of the view and a slower host have room.
PARSE_MIB_SECONDS = 0.30
PARSE_LEVEL_SECONDS = 0.025
PARSE_SHARE = 0.4
# Header parsing is bounded too: the email package's structured parser is superlinear on
# crafted values (measured: about 34 ms for one 4 KB Content-Type, 120 ms at 8 KB).
STRUCTURAL_HEADERS = ("content-type", "content-disposition", "content-id", "content-transfer-encoding")
VIEW_HEADER_VALUE = 4096            # one structural value the view parses (unfolded); longer refuses the view
VIEW_HEADER_TOTAL = 128 * 1024      # all distinct structural values it parses in one message
ADDRESS_HEADER_PARSE = 2048         # From, To, Cc longer than this are shown unparsed (superlinear parser)
SUBJECT_HEADER_PARSE = 8192         # Subject longer than this is shown unparsed (linear parser)
MAX_COMMENT_DEPTH = 32              # deeper nested comments: unreadable (the parser recurses per level)
DECODE_WORDS_MAX = 16 * 1024        # a header shown unparsed has its encoded words decoded up to this length
MAX_TAG_COST = 500_000              # separators and "&" in one start tag (html.parser reads its attributes in one step)
MAX_ENTITIES = 2_500_000            # "&" in one HTML section (each character reference costs a Python call)
_TICKS_PER_CHECK = 256              # sanitizer work units (one per construct, plus one per KiB) between clock reads
_CID_REF_MAX = 16 * 1024            # a cid: reference longer than any accepted Content-ID, %-encoded, is missing
_AUTH_RESULTS_MAX = 64 * 1024       # a longer Authentication-Results value is malformed (never scanned)
_PARSE_CHUNK = 256 * 1024           # the MIME parse is fed in chunks, the deadline checked between them
_LINES_PER_CHECK = 16 * 1024        # header lines parsed between deadline checks
_HEADER_COPIES = 64                 # occurrences of one header a part keeps (the view reads the first)
_PAGE_HEADER_MAX = 2 * 1024 * 1024  # From/To/Cc/Date/Subject read at most this long (a prediction refuses past 1.7 MB)
_DEFECTS_KEPT = 64                  # defects a part records (the view only asks whether it has any)
_SUBJECT_SCAN = 1024 * 1024         # subject_of reads at most this much of the header block
# the headers the view reads: the structural ones on every part, the header block's on the root
_PART_READS = frozenset(STRUCTURAL_HEADERS)
_PAGE_READS = frozenset({"from", "to", "cc", "date", "subject", "authentication-results"})
_ROOT_READS = _PART_READS | _PAGE_READS


def _flat_after(flat: int, text: str) -> int:
    """The length a header value has as the view reads it (policy.header_source_parse strips
    the value's leading blanks; the view then drops every CR and LF), after `text` is added.
    `flat` is -1 while only blanks have been seen."""
    if flat < 0:
        stripped = text.lstrip(" \t\r\n")
        if not stripped:
            return -1
        text = stripped
    return max(flat, 0) + len(text) - text.count("\r") - text.count("\n")
# body charsets decoded as declared: linear-time codecs only (punycode, idna, utf-7, the escape
# codecs, and anything unknown are refused and decoded as UTF-8 with replacement instead)
_FAST_CODECS = re.compile(r"^(utf-8(-sig)?|ascii|utf-(16|32)(-[lb]e)?|iso8859-\d+|cp\d+|koi8-[rtu]|mac-[a-z]+|"
                          r"kz1048|ptcp154|tis-620|hp-roman8|shift_jis(_2004|x0213)?|euc_[a-z0-9_]+|"
                          r"iso2022_[a-z0-9_]+|gb2312|gbk|gb18030|big5(hkscs)?|hz|johab)$")
_SURROGATES = re.compile("[\ud800-\udfff]")


def _scrub(text: str) -> str:
    """Replace lone surrogates (from surrogate-escaped 8-bit headers or exotic codecs) so the
    page always encodes as UTF-8."""
    return _SURROGATES.sub("\ufffd", text or "")

_ALLOWED = frozenset("""
a abbr address article aside b bdi bdo big blockquote br caption center cite code col colgroup
dd del details dfn div dl dt em figcaption figure font footer h1 h2 h3 h4 h5 h6 header hr i img
ins kbd li main mark nav ol p pre q rp rt ruby s samp section small span strike strong style sub
summary sup table tbody td tfoot th thead time tr tt u ul var wbr
""".split())
_VOID = frozenset("area base br col embed hr img input keygen link meta param source track wbr".split())
_DROP_WITH_CONTENT = frozenset("""
script noscript iframe frame frameset object applet template svg math title textarea select
option optgroup datalist xmp noembed noframes plaintext canvas video audio picture portal dialog
head-title output progress meter
""".split())
_GLOBAL_ATTRS = frozenset("style class id title dir lang align valign width height bgcolor color border".split())
_TAG_ATTRS = {
    "a": frozenset({"href"}),
    "img": frozenset({"src", "alt", "hspace", "vspace"}),
    "table": frozenset({"cellpadding", "cellspacing", "summary", "frame", "rules"}),
    "td": frozenset({"colspan", "rowspan", "nowrap", "headers", "scope", "abbr"}),
    "th": frozenset({"colspan", "rowspan", "nowrap", "headers", "scope", "abbr"}),
    "col": frozenset({"span"}), "colgroup": frozenset({"span"}),
    "ol": frozenset({"start", "type", "reversed"}), "ul": frozenset({"type"}),
    "li": frozenset({"value", "type"}), "font": frozenset({"face", "size"}),
    "del": frozenset({"datetime"}), "ins": frozenset({"datetime"}), "time": frozenset({"datetime"}),
    "hr": frozenset({"size", "noshade"}), "details": frozenset({"open"}),
}
_HREF_SCHEMES = frozenset({"http", "https", "mailto"})
_DATA_IMAGE_RE = re.compile(      # parameters possessive: no backtracking state per parameter
    r"^data:image/(png|jpeg|jpg|gif|webp|bmp|svg\+xml)(?:;(?!base64,)[a-z0-9._=-]+)*+;base64,[A-Za-z0-9+/=]*$", re.I)
_CONTROL_STRIP = re.compile(r"[\x00-\x20\x7f]+")
_DATA_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/svg+xml"}


# --- parsing ----------------------------------------------------------------------------------------
_PARSING = threading.local()


class _ViewMessage(email.message.EmailMessage):
    """While the view's parser runs, every message/* part reads as opaque, so the parser never
    parses into an attached message (the view never shows its parts). Afterwards the real type
    is reported, and selection excludes the part as a nested message."""
    dropped: frozenset = frozenset()        # headers the view reads that had more than _HEADER_COPIES
    too_long: frozenset = frozenset()       # header block headers cut while parsing (refused when read)

    def get_content_type(self):
        ctype = super().get_content_type()
        if getattr(_PARSING, "active", False) and ctype.startswith("message/"):
            return "application/octet-stream"
        return ctype


def _paren_depth(value: str) -> int:
    """The deepest parenthesis nesting in a header value, counted naively: a backslash escapes
    the next character only inside a comment, as in the parser, and quoting is ignored, so it
    never undercounts a comment (a parenthesis inside a quoted string only adds). Linear."""
    depth = best = 0
    escaped = False
    for ch in value:
        if escaped:
            escaped = False
        elif ch == "\\" and depth:
            escaped = True
        elif ch == "(":
            depth += 1
            if depth > best:
                best = depth
        elif ch == ")" and depth:
            depth -= 1
    return best


def parse_header(name: str, flat: str):
    """THE structured parse of one unfolded header value, for the view and for mime's adapter
    alike: comments nested deeper than MAX_COMMENT_DEPTH are unreadable before the parser sees
    them (the parser recurses per level, so where it gives up would otherwise depend on the
    caller's stack depth), and anything the parser rejects is unreadable."""
    if _paren_depth(flat) > MAX_COMMENT_DEPTH:
        raise ViewError("header-unreadable")
    try:
        return email.policy.default.header_factory(name, flat)
    except Exception:
        raise ViewError("header-unreadable") from None


class _ViewPolicy(email.policy.EmailPolicy):
    """email.policy.default with a per-message guard on the structural headers: each distinct
    value is parsed once (the stock policy parses again on every access), at most
    VIEW_HEADER_VALUE characters each and VIEW_HEADER_TOTAL together, through parse_header;
    a value over either, or one parse_header calls unreadable, refuses the view with a fixed
    code. mime's adapter parses with the same policy."""
    guard = None

    def header_fetch_parse(self, name, value):
        g = self.guard
        if g is None or hasattr(value, "name") or name.lower() not in STRUCTURAL_HEADERS:
            return super().header_fetch_parse(name, value)
        if len(value) - value.count("\r") - value.count("\n") > VIEW_HEADER_VALUE:
            raise ViewError("header-too-long")      # counted before unfolding: the same length
        flat = value.replace("\r", "").replace("\n", "")
        key = (name.lower(), flat)
        if key in g["parsed"]:
            return g["parsed"][key]
        g["total"] += len(flat)
        if g["total"] > VIEW_HEADER_TOTAL:
            raise ViewError("header-too-long")
        parsed = parse_header(name, flat)
        g["parsed"][key] = parsed
        return parsed


_VIEW_POLICY = _ViewPolicy(message_factory=_ViewMessage)


def view_policy() -> _ViewPolicy:
    """A guarded policy with a fresh guard: one per message."""
    return _VIEW_POLICY.clone(guard={"parsed": {}, "total": 0})


class _ViewSubFile(_BufferedSubFile):
    """The parser's line buffer. The stdlib checks every line against every enclosing
    boundary; in the view's parse each of those checks is a boundary match (message/* parts,
    delivery-status included, are opaque here), which needs a line starting with "--", so any
    other line skips them. Lines that start with "--" pay for the nesting depth."""
    boundaries_only = True              # False once any other check is pushed: then every line pays

    def push_eof_matcher(self, pred):
        if getattr(pred, "__name__", "") != "boundarymatch":       # FeedParser's boundary closure
            self.boundaries_only = False
        super().push_eof_matcher(pred)

    def readline(self):
        if not self._lines:
            if self._closed:
                return ''
            return email.feedparser.NeedMoreData
        line = self._lines.popleft()
        if not self.boundaries_only or line.startswith('--'):
            for ateof in reversed(self._eofstack):
                if ateof(line):
                    # We're at the false EOF.  But push the last line back first.
                    self._lines.appendleft(line)
                    return ''
        return line


class _ViewFeedParser(_BytesFeedParser):
    """The feed parser with the view's bounds, enforced as it parses: MIME nesting within
    MAX_DEPTH below the root and at most MAX_PARTS parts, the same answers the walk over the
    parsed message gives; and the deadline, checked inside a header block too."""

    def __init__(self, deadline: float):
        super().__init__(policy=view_policy())
        self._input = _ViewSubFile()
        self._deadline = deadline
        self._parts = 0

    def _new_message(self):
        self._parts += 1
        if self._parts > MAX_PARTS:
            raise ViewError("mime-too-many-parts")
        super()._new_message()
        if len(self._msgstack) > MAX_DEPTH + 1:
            raise ViewError("mime-too-deep")

    def _defect(self, defect_class, arg) -> None:
        if len(self._cur.defects) < _DEFECTS_KEPT:
            self.policy.handle_defect(self._cur, defect_class(arg))

    def _parse_headers(self, lines):
        # email.feedparser.FeedParser._parse_headers (CPython 3.14), changed only to: check the
        # deadline every _LINES_PER_CHECK lines (the stdlib parses a whole header block in one
        # call, and one block can be most of a message); keep only the headers the view reads,
        # at most _HEADER_COPIES of each; and record at most _DEFECTS_KEPT defects. The view
        # reads the first occurrence of a header (and counts duplicates of the header block's)
        # and asks only whether a part has defects, so what it shows is unchanged, while a block
        # of millions of lines no longer becomes millions of objects that every lookup scans.
        cur = self._cur
        root = len(self._msgstack) == 1
        reads = _ROOT_READS if root else _PART_READS
        kept: dict[str, int] = {}
        lastheader = ''
        lastvalue = []
        keep = False
        cap = flat = 0                         # the kept value's cap, and its length as the view reads it
        for lineno, line in enumerate(lines):
            if lineno % _LINES_PER_CHECK == 0 and time.monotonic() > self._deadline:
                raise ViewError("view-too-slow")
            # Check for continuation
            if line[0] in ' \t':
                if not lastheader:
                    # The first line of the headers was a continuation: a defect, ignored.
                    self._defect(_email_errors.FirstHeaderLineIsContinuationDefect, line)
                    continue
                if keep:
                    flat = _flat_after(flat, line)
                    lastvalue.append(line)
                    if flat > cap:                 # longer than the view reads: cut here, refused when read
                        keep = False
                        cur.set_raw(*self.policy.header_source_parse(lastvalue))
                        if name in _PAGE_READS:
                            cur.too_long = cur.too_long | {name}
                continue
            if lastheader:
                if keep:
                    cur.set_raw(*self.policy.header_source_parse(lastvalue))
                lastheader, lastvalue, keep = '', [], False
            # Check for envelope header, i.e. unix-from
            if line.startswith('From '):
                if lineno == 0:
                    # Strip off the trailing newline
                    mo = email.feedparser.NLCRE_eol.search(line)
                    if mo:
                        line = line[:-len(mo.group(0))]
                    cur.set_unixfrom(line)
                    continue
                elif lineno == len(lines) - 1:
                    # probably the first line of the body: push it back and stop
                    self._input.unreadline(line)
                    return
                else:
                    # Weirdly placed unix-from line.
                    self._defect(_email_errors.MisplacedEnvelopeHeaderDefect, line)
                    continue
            # Split the line on the colon separating field name from value.
            i = line.find(':')
            if i == 0:
                self._defect(_email_errors.InvalidHeaderDefect, "Missing header name.")
                continue
            assert i > 0, "_parse_headers fed line with no : and no leading WS"
            lastheader = line[:i]
            name = lastheader.lower()            # what Message.get compares
            if name in reads:
                if kept.get(name, 0) < _HEADER_COPIES:
                    kept[name] = kept.get(name, 0) + 1
                    keep, lastvalue = True, [line]
                    cap = _PAGE_HEADER_MAX if name in _PAGE_READS else VIEW_HEADER_VALUE
                    flat = _flat_after(-1, line[i + 1:])
                    if flat > cap:
                        keep = False
                        cur.set_raw(*self.policy.header_source_parse(lastvalue))
                        if name in _PAGE_READS:
                            cur.too_long = cur.too_long | {name}
                elif name not in cur.dropped:
                    cur.dropped = cur.dropped | {name}
        # Done with all the lines, so handle the last header.
        if lastheader and keep:
            cur.set_raw(*self.policy.header_source_parse(lastvalue))


def _parse(raw: bytes, deadline: float):
    """The view's parse of RAW bytes: bounded header work, no parsing into attached messages,
    nesting within MAX_DEPTH, at most MAX_PARTS parts, and the deadline checked between chunks
    of the input and inside header blocks."""
    parser = _ViewFeedParser(deadline)
    _PARSING.active = True
    try:
        for i in range(0, len(raw), _PARSE_CHUNK):
            if time.monotonic() > deadline:
                raise ViewError("view-too-slow")
            parser.feed(raw[i:i + _PARSE_CHUNK])
        if time.monotonic() > deadline:
            raise ViewError("view-too-slow")
        return parser.close()
    except ViewError:
        raise
    except Exception:
        raise ViewError("unsupported-mime") from None
    finally:
        _PARSING.active = False


# --- body selection ------------------------------------------------------------------------
@dataclass
class Selection:
    part: email.message.EmailMessage
    ctype: str
    path: tuple[int, ...]
    scope: email.message.EmailMessage | None   # the multipart/related part whose CIDs are in scope
    scope_path: tuple[int, ...] | None


def _cid_of(part) -> str | None:
    v = part.get("Content-ID")
    if v is None:
        return None
    v = str(v).strip()
    return v[1:-1].strip() if v.startswith("<") and v.endswith(">") else v or None


def select_body(msg, warnings: list[str], alternatives: list | None = None,
                deadline: float | None = None) -> list[Selection]:
    """The body sections to render, in order. multipart/alternative picks one child (the
    last whose sections include HTML, else the last with plain text); the paths of the
    text parts under its other children go to `alternatives` when given. multipart/
    related renders its root with its own parts as the CID scope; every other multipart
    renders all of its text sections in order; attachments and nested messages are never
    body. Works on any object with the email package's part interface (mime passes Gmail's
    FULL payload through an adapter)."""
    def walk(part, path, scope, scope_path, depth) -> list[Selection]:
        if deadline is not None and time.monotonic() > deadline:
            raise ViewError("view-too-slow")
        if depth > MAX_DEPTH:
            warnings.append("mime-too-deep")
            return []
        if part.is_attachment():
            return []
        ctype = part.get_content_type()
        if part.get_content_maintype() == "message":
            return []  # nested messages are never the body
        if part.is_multipart():
            kids = list(part.iter_parts())
            if ctype == "multipart/related":
                start = part.get_param("start")
                root_i = None
                if start:
                    want = str(start).strip().strip("<>").strip()
                    for i, k in enumerate(kids):
                        if _cid_of(k) == want:
                            root_i = i
                            break
                    if root_i is None:
                        warnings.append("related-start-not-found")
                if root_i is None and kids:
                    root_i = 0
                if root_i is None:
                    return []
                return walk(kids[root_i], path + (root_i,), part, path, depth + 1)
            if ctype == "multipart/alternative":
                cands = [walk(k, path + (i,), scope, scope_path, depth + 1) for i, k in enumerate(kids)]
                chosen = None
                for want in ("text/html", "text/plain"):
                    chosen = next((i for i in range(len(cands) - 1, -1, -1)
                                   if any(x.ctype == want for x in cands[i])), None)
                    if chosen is not None:
                        break
                if chosen is None:
                    return []
                if alternatives is not None:
                    for i, k in enumerate(kids):
                        if i != chosen:
                            _text_parts(k, path + (i,), depth + 1, alternatives)
                return cands[chosen]
            out: list[Selection] = []
            for i, k in enumerate(kids):
                out.extend(walk(k, path + (i,), scope, scope_path, depth + 1))
            return out
        if ctype in ("text/html", "text/plain"):
            if _uuencoded(part):                 # never decoded (see _uuencoded): not body, and said so
                warnings.append("section-encoding-unsupported")
                return []
            return [Selection(part, ctype, path, scope, scope_path)]
        return []

    found = walk(msg, (), None, None, 0)
    if alternatives is not None:
        alternatives[:] = list(dict.fromkeys(alternatives))
    return found


def _text_parts(part, path, depth: int, out: list) -> None:
    """The text parts under a multipart/alternative child that was not chosen: alternative
    renderings of the body (text/plain, text/calendar, AMP, and the like). Attachments,
    nested messages, and non-text parts are not; they stay listed."""
    if depth > MAX_DEPTH or part.is_attachment() or part.get_content_maintype() == "message":
        return
    if part.is_multipart():
        for i, k in enumerate(part.iter_parts()):
            _text_parts(k, path + (i,), depth + 1, out)
    elif part.get_content_maintype() == "text":
        out.append(path)


class BodyUnavailable(Exception):
    """A body section's bytes could not be read (raised by mime's adapter for Gmail payloads)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _declared_size(part) -> int:
    """A part's decoded size: Gmail's declared body size through mime's adapter (image bytes
    are never read there), else the decoded payload's length."""
    size = getattr(part, "declared_size", None)
    if isinstance(size, int):
        return size
    data = part.get_payload(decode=True)
    return len(data) if isinstance(data, (bytes, bytearray)) else 0


_UUENCODE = ("x-uuencode", "uuencode", "uue", "x-uue")   # Message.get_payload's spellings
_DECODE_CHUNK = 1024 * 1024


def _transfer_encoding(part) -> str:
    """The Content-Transfer-Encoding exactly as Message.get_payload(decode=True) reads it
    (CPython 3.14.6, fingerprinted): the parsed header's token when there is one."""
    h = part.get("content-transfer-encoding", "")
    return h.cte if hasattr(h, "cte") else str(h).strip().lower()


def _uuencoded(part) -> bool:
    """Whether Message.get_payload(decode=True) would uudecode this part, however the encoding
    is spelled: a Python loop per line whose output can be over twenty times its input. The
    view never runs it (the prediction calls any such encoding unreadable)."""
    return _transfer_encoding(part) in _UUENCODE


def _payload_bytes(part):
    """part.get_payload(decode=True), with a base64 body's line breaks removed in one step:
    Message.get_payload joins bytes.splitlines(), the same bytes made one object per line
    (about 0.7 GB for 50 MiB of short lines). Callers never pass a uuencoded part."""
    payload = getattr(part, "_payload", None)
    if not isinstance(payload, str) or _transfer_encoding(part) != "base64":
        return part.get_payload(decode=True)
    try:
        bpayload = payload.encode("ascii", "surrogateescape")
    except UnicodeEncodeError:
        bpayload = payload.encode("raw-unicode-escape")
    value, defects = email._encoded_words.decode_b(bpayload.translate(None, b"\r\n"))
    for defect in defects:
        part.policy.handle_defect(part, defect)
    return value


@functools.lru_cache(maxsize=None)
def _single_byte(name: str) -> bool:
    """Whether a codec maps each byte on its own (a 256-entry decoding table): such a payload
    decodes the same in any split, and an undefined byte costs a call to the error handler."""
    try:
        module = importlib.import_module("encodings." + name.replace("-", "_"))
    except ImportError:
        return False
    table = getattr(module, "decoding_table", None)
    return isinstance(table, str) and len(table) == 256


_WIDE_BOMS = {"utf-16": (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE),
              "utf-32": (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)}


def _decode_bounded(payload: bytes, name: str, deadline: float | None) -> str:
    """payload.decode(name, errors="replace"), in 1 MiB steps with the deadline checked between
    them for the codecs whose errors are slow (a single call over 47 MiB of undefined bytes
    takes 7 to 11 s for a single-byte codec, 3.5 s for UTF-16): a single-byte codec decodes
    each step on its own; UTF-16 and UTF-32 resolve their byte order once (a BOM, else the
    host's, as the one-shot decoder does) and step a fixed-order incremental decoder. Both
    give exactly the one-shot text (tests compare them)."""
    if deadline is None or len(payload) <= _DECODE_CHUNK:
        return payload.decode(name, errors="replace")
    if _single_byte(name):
        steps = (payload[i:i + _DECODE_CHUNK].decode(name, errors="replace")
                 for i in range(0, len(payload), _DECODE_CHUNK))
    elif name in ("utf-16", "utf-32", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
        if name in _WIDE_BOMS:
            le, be = _WIDE_BOMS[name]
            if payload.startswith(le):
                name, payload = name + "-le", payload[len(le):]
            elif payload.startswith(be):
                name, payload = name + "-be", payload[len(be):]
            else:
                name += "-le" if sys.byteorder == "little" else "-be"
        dec = codecs.getincrementaldecoder(name)(errors="replace")
        steps = (dec.decode(payload[i:i + _DECODE_CHUNK], final=i + _DECODE_CHUNK >= len(payload))
                 for i in range(0, len(payload), _DECODE_CHUNK))
    else:
        return payload.decode(name, errors="replace")
    out = []
    for step in _checked(steps, deadline):
        out.append(step)
    return "".join(out)


def _checked(steps, deadline: float):
    for step in steps:
        if time.monotonic() > deadline:
            raise ViewError("view-too-slow")
        yield step


def _decode_text(part, warnings: list[str], deadline: float | None = None,
                 limit: int | None = None) -> tuple[str, bytes]:
    """A text section's text and bytes. Over `limit` bytes it is refused before any charset
    decoding (the same answer the size check after it gives, without the work)."""
    payload = _payload_bytes(part)
    if not isinstance(payload, (bytes, bytearray)):
        payload = b""
    payload = bytes(payload)
    if limit is not None and len(payload) > limit:
        raise ViewError("html-too-large")
    charset = part.get_content_charset()       # lower-cased, RFC 2231 collapsed, None when absent
    try:
        name = codecs.lookup(charset or "us-ascii").name
    except (LookupError, ValueError, UnicodeError):     # unknown, or a NUL in the name
        name = None
    if name is None:
        warnings.append("body-charset-fallback")
        text = payload.decode("utf-8", errors="replace")
    elif not _FAST_CODECS.match(name):
        warnings.append("body-charset-refused")
        text = payload.decode("utf-8", errors="replace")
    else:
        try:
            text = _decode_bounded(payload, name, deadline)
        except ViewError:
            raise
        except Exception:                      # a codec that fails even with errors="replace"
            warnings.append("body-charset-fallback")
            text = payload.decode("utf-8", errors="replace")
    if getattr(part, "defects", None):
        warnings.append("body-mime-defects")
    return _scrub(text), payload


# --- CID resolution ------------------------------------------------------------------------------
@dataclass
class CidImage:
    cid: str
    mime: str
    path: tuple[int, ...]          # the image part's MIME path
    size: int
    data: bytes | None = None      # None in predict(): image bytes are never read there
    attachment: bool = False       # the sender marked it `Content-Disposition: attachment`


class CidScope:
    """What one related scope offers: for each Content-ID, its FIRST part in scope order, as a
    CidImage when that part is one of the six image types, else None (never embedded). A
    reference matches exactly first, then without regard to case (the first part, in scope
    order, whose ID matches that way)."""

    def __init__(self, ids: dict[str, CidImage | None]):
        self.exact = ids
        self.folded: dict[str, CidImage | None] = {}
        for cid, img in ids.items():
            self.folded.setdefault(cid.casefold(), img)

    def lookup(self, ref: str) -> CidImage | None:
        if ref in self.exact:
            return self.exact[ref]
        return self.folded.get(ref.casefold())


def collect_cids(scope, scope_path, warnings: list[str], read_data: bool = True,
                 deadline: float | None = None) -> CidScope:
    """Content-IDs in the selected related scope (never outside it); the first part with an ID
    wins it, and only an image of the six types can be embedded."""
    found: dict[str, CidImage | None] = {}
    if scope is None:
        return CidScope(found)
    for i, k in enumerate(scope.iter_parts()):
        cid = _cid_of(k)
        if not cid:
            continue
        if cid in found:
            warnings.append("duplicate-cid")
            continue
        mime = k.get_content_type()
        if mime not in _DATA_IMAGE_TYPES:
            found[cid] = None
            continue
        if not read_data:
            found[cid] = CidImage(cid, mime, tuple(scope_path) + (i,), _declared_size(k), None, k.is_attachment())
            continue
        if deadline is not None and time.monotonic() > deadline:
            raise ViewError("view-too-slow")
        if _uuencoded(k):                    # never decoded by the view (see _uuencoded)
            warnings.append("cid-encoding-unsupported")
            found[cid] = None
            continue
        data = _payload_bytes(k)
        if data is None:
            warnings.append("cid-decode-failed")
            found[cid] = None
            continue
        found[cid] = CidImage(cid, mime, tuple(scope_path) + (i,), len(data), data, k.is_attachment())
    return CidScope(found)


def may_embed(sections: list[Selection]) -> bool:
    """Whether any rendered HTML section's related scope holds an image part of the six types
    with a Content-ID. If none does, nothing can be embedded, whatever the HTML says."""
    for sel in sections:
        if sel.ctype == "text/html" and sel.scope is not None:
            for k in sel.scope.iter_parts():
                if _cid_of(k) and k.get_content_type() in _DATA_IMAGE_TYPES:
                    return True
    return False


# --- sanitizer -----------------------------------------------------------------------------------
def _safe_href(value: str) -> str | None:
    v = _CONTROL_STRIP.sub("", value or "")
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", v)
    if not m or m.group(1).lower() not in _HREF_SCHEMES:
        return None
    return v


_STAND_IN = "data:"

# html.parser's pattern for where a tag ends, with its loop over attributes possessive: the
# pattern always matches (its last part is optional), so the engine never backtracks into a
# finished attribute and the matches are the same, but no state is kept per attribute (the
# stock pattern holds about 320 bytes for each, over a gigabyte for one crafted tag).
_STOCK_TAGEND = getattr(getattr(html.parser, "locatetagend", None), "pattern", None)
_LOCATETAGEND = (re.compile(_STOCK_TAGEND.replace(")*\n   >?", ")*+\n   >?"), re.VERBOSE)
                 if isinstance(_STOCK_TAGEND, str) else None)

# The view copies, or depends on the exact behavior of, these stdlib internals of CPython
# 3.14.6 (the server's Python follows Homebrew's, which a patch release can change). When any
# of them differs, the view is unavailable ("stdlib-changed") and no part is marked inline,
# until the copies are reviewed against the new code; reading mail is unaffected.
_STDLIB_FINGERPRINT = {
    "email.feedparser.FeedParser._parse_headers": "fce9c91701d3b688",
    "email.feedparser.FeedParser._parsegen": "97e22fa891577454",
    "email.feedparser.BufferedSubFile.readline": "60fd12dda02ac9b0",
    "html.parser.HTMLParser.goahead": "dfb16046909f33be",
    "html.parser.HTMLParser.parse_starttag": "29145cd901e5e4c3",
    "html.parser.HTMLParser.check_for_whole_start_tag": "52f8d2f71dc6fd6b",
    "html.parser.HTMLParser.parse_endtag": "e881662959402226",
    "html.parser.locatetagend": "3cf729cae302b017",
    "html.parser.tagfind_tolerant": "d5c5cc6b0a05e4a6",
    "email.message.Message.get_payload": "8ac643ce92d305b8",
    "email.feedparser.BytesFeedParser.feed": "398c408f24a89abb",
}


def _stdlib_changes() -> list[str]:
    """The fingerprinted names whose source differs from the copies', or is missing. Never
    raises: a renamed or removed symbol only turns the view off."""
    import inspect
    changed = []
    for name, want in _STDLIB_FINGERPRINT.items():
        try:
            if name == "html.parser.locatetagend":
                text = _STOCK_TAGEND
            elif name == "html.parser.tagfind_tolerant":
                text = getattr(html.parser, "tagfind_tolerant").pattern
            else:
                module, cls, attr = name.rsplit(".", 2)
                text = inspect.getsource(getattr(getattr(importlib.import_module(module), cls), attr))
            got = hashlib.sha256(text.encode()).hexdigest()[:16]
        except Exception:
            got = None
        if got != want:
            changed.append(name)
    if not isinstance(_STOCK_TAGEND, str) or _STOCK_TAGEND.count(")*\n   >?") != 1:
        changed.append("html.parser.locatetagend (possessive form)")
    return changed


STDLIB_CHANGED = _stdlib_changes()


def _budget(limit: int, seconds: float = 0.0, deadline: float | None = None) -> dict:
    return {"used": 0, "bytes": 0, "limit": limit,
            "deadline": deadline if deadline is not None else time.monotonic() + seconds}


def _charge(budget: dict, chars: int, utf8_bytes: int = 0) -> None:
    budget["used"] += chars
    budget["bytes"] += utf8_bytes
    if budget["used"] > budget["limit"] or budget["bytes"] > budget["limit"]:
        raise ViewError("html-too-large")


class _Sanitizer(HTMLParser):
    """Allowlist rebuild. Linear in the input: open elements are tracked with counters (an
    unmatched end tag costs O(1)), nesting is capped, and the output size and elapsed time
    are budgeted while parsing, so repeated cid: references or pathological nesting stop at
    the cap instead of exhausting memory or freezing the server."""

    def __init__(self, cids: CidScope, used: dict, warnings: list[str], budget: dict | None = None,
                 collect_only: bool = False, embedded: set | None = None):
        super().__init__(convert_charrefs=True)
        self.cids, self.used, self.warnings = cids, used, warnings
        self.out: list[str] = []
        # one output and time budget across every section of a message
        self.budget = budget if budget is not None else _budget(MAX_PAGE_BYTES, VIEW_SECONDS)
        # collect_only (predict): nothing is kept; sizes are charged exactly, in characters and
        # UTF-8 bytes, and the parts embedded are recorded
        self.collect_only = collect_only
        self.embedded = embedded if embedded is not None else set()
        self.stack: list[str] = []
        self.open_counts: dict[str, int] = {}
        self.skip_tag: str | None = None
        self.skip_depth = 0
        self.remote_images = 0
        self.ticks = 0
        self.next_check = _TICKS_PER_CHECK

    def _emit(self, text: str) -> None:
        if self.collect_only:
            _charge(self.budget, len(text), len(text.encode("utf-8")))
            return
        _charge(self.budget, len(text))
        self.out.append(text)

    def _tick(self, cost: int = 1) -> None:
        # a unit is about one small construct; a long one counts one more per KiB of input, so
        # the clock is read at least every _TICKS_PER_CHECK units of work, whatever the markup
        self.ticks += cost
        if self.ticks >= self.next_check:
            self.next_check = self.ticks + _TICKS_PER_CHECK
            if time.monotonic() > self.budget["deadline"]:
                raise ViewError("view-too-slow")

    # tags
    def handle_starttag(self, tag, attrs):
        self._start(tag, attrs, self_closing=False)

    def handle_startendtag(self, tag, attrs):
        # HTML ignores "/>" on an element that is not void: a raw-text element written that way
        # still takes what follows as its raw text, as an over-cost tag does (parse_starttag)
        if self.skip_tag not in ("svg", "math") and (
                tag in self.CDATA_CONTENT_ELEMENTS or tag in self.RCDATA_CONTENT_ELEMENTS or tag == "plaintext"):
            self._start(tag, attrs, self_closing=False)
            self.set_cdata_mode(tag, escapable=tag in self.RCDATA_CONTENT_ELEMENTS)
            return
        self._start(tag, attrs, self_closing=True)

    def _start(self, tag, attrs, self_closing):
        self._tick()
        if self.skip_tag is not None:
            if tag == self.skip_tag and tag not in _VOID and not self_closing:
                self.skip_depth += 1
            return
        if tag in _DROP_WITH_CONTENT:
            if tag not in _VOID and not self_closing:
                self.skip_tag, self.skip_depth = tag, 1
            return
        if tag not in _ALLOWED:
            return  # unknown/unwrapped element (html, head, body, form, button, o:p, ...): keep content
        if tag not in _VOID and not self_closing and len(self.stack) >= MAX_NEST:
            return  # too deep: unwrap (content kept)
        rendered = self._attrs(tag, attrs)
        if rendered is None:
            return
        self._emit(f"<{tag}{rendered}>")
        if tag in _VOID:
            return
        if self_closing:
            self._emit(f"</{tag}>")
        else:
            self.stack.append(tag)
            self.open_counts[tag] = self.open_counts.get(tag, 0) + 1

    def handle_endtag(self, tag):
        self._tick()
        if self.skip_tag is not None:
            if tag == self.skip_tag:
                self.skip_depth -= 1
                if self.skip_depth == 0:
                    self.skip_tag = None
            return
        if self.open_counts.get(tag, 0) > 0:
            while self.stack:
                t = self.stack.pop()
                self.open_counts[t] -= 1
                self._emit(f"</{t}>")
                if t == tag:
                    break

    def _attrs(self, tag, attrs) -> str | None:
        allowed = _GLOBAL_ATTRS | _TAG_ATTRS.get(tag, frozenset())
        if tag == "style":
            return ""
        parts = []
        seen: set[str] = set()
        for name, value in attrs:
            self._tick()
            name = (name or "").lower()
            if name in seen:
                continue                 # a repeated attribute: browsers keep the first
            seen.add(name)
            if name not in allowed or name.startswith("on"):
                continue
            value = "" if value is None else _scrub(value)
            if name == "href":
                value = _safe_href(value)
                if value is None:
                    continue
            elif name == "src":
                value = self._img_src(value)
                if value is None:
                    continue
            elif name == "style":
                low = _CONTROL_STRIP.sub("", value).lower()
                if "expression(" in low or "javascript:" in low or "-moz-binding" in low or "behavior:" in low:
                    continue
            parts.append(f' {name}="{html.escape(value, quote=True)}"')
        return "".join(parts)

    def _img_src(self, value: str) -> str | None:
        v = _CONTROL_STRIP.sub("", value or "")
        low = v.lower()
        if low.startswith("cid:"):
            if len(v) > _CID_REF_MAX:            # longer than any Content-ID the view accepts, encoded
                self.warnings.append("missing-cid")
                return None
            ref = urllib.parse.unquote(v[4:]).strip().strip("<>")
            img = self.cids.lookup(ref)
            if img is None:
                self.warnings.append("missing-cid")
                return None
            self.embedded.add(img.path)
            if self.collect_only:
                # the data: URI is charged at its exact length; a short stand-in is emitted
                extra = len(f"data:{img.mime};base64,") + 4 * ((img.size + 2) // 3) - len(_STAND_IN)
                _charge(self.budget, extra, extra)
                return _STAND_IN
            uri = self.used.get(img.path)
            if uri is None:
                uri = f"data:{img.mime};base64," + base64.b64encode(img.data).decode()
                self.used[img.path] = uri
            return uri
        if low.startswith("data:") and _DATA_IMAGE_RE.match(v):
            return v
        self.remote_images += 1  # remote, relative, or other schemes: never fetched (D10)
        return None

    # content
    def handle_data(self, data):
        self._tick(1 + len(data) // 1024)
        if self.skip_tag is not None:
            return
        data = _scrub(data)
        if self.stack and self.stack[-1] == "style":
            self._emit(data.replace("<", ""))  # raw text: no "<" means no "</style" breakout
            return
        self._emit(html.escape(data, quote=False))

    def handle_comment(self, data):
        self._tick(1 + len(data) // 1024)

    def handle_decl(self, decl):
        self._tick(1 + len(decl) // 1024)

    def handle_pi(self, data):
        self._tick(1 + len(data) // 1024)

    def unknown_decl(self, data):
        self._tick(1 + len(data) // 1024)

    # html.parser internals: one start tag's attributes are read in a single step before its
    # handler runs, and "</>" calls no handler at all, so both count here, a tag by its length
    # (an unfinished one by all the text after it, which html.parser rescans on close). A start
    # tag with more attribute work than MAX_TAG_COST keeps its element, with the element's
    # raw-text handling whatever its ending, but loses its attributes, the same way in predict()
    # and the view. Where a tag ends is found with _LOCATETAGEND.
    def parse_starttag(self, i):
        end = self.check_for_whole_start_tag(i)
        if end < 0:                            # unfinished: html.parser's own answer, without a rescan
            self._tick(1 + (len(self.rawdata) - i) // 1024)
            return end
        self._tick(1 + (end - i) // 1024)
        if end - i > MAX_TAG_COST and _tag_cost(self.rawdata, i, end) > MAX_TAG_COST:
            self.warnings.append("html-attributes-dropped")
            # html.parser.HTMLParser.parse_starttag's tail (CPython 3.14), with no attributes
            self.lasttag = tag = _TAGNAME.match(self.rawdata, i + 1).group(0).lower()
            self.handle_starttag(tag, [])
            if tag in self.CDATA_CONTENT_ELEMENTS or (self.scripting and tag == "noscript") or tag == "plaintext":
                self.set_cdata_mode(tag, escapable=False)
            elif tag in self.RCDATA_CONTENT_ELEMENTS:
                self.set_cdata_mode(tag, escapable=True)
            return end
        return super().parse_starttag(i)

    def check_for_whole_start_tag(self, i):
        # html.parser.HTMLParser.check_for_whole_start_tag (CPython 3.14) with _LOCATETAGEND
        rawdata = self.rawdata
        match = _LOCATETAGEND.match(rawdata, i + 1)
        assert match
        j = match.end()
        if rawdata[j - 1] != ">":
            return -1
        return j

    def parse_endtag(self, i):
        self._tick()
        # html.parser.HTMLParser.parse_endtag (CPython 3.14) with _LOCATETAGEND
        rawdata = self.rawdata
        assert rawdata[i:i + 2] == "</", "unexpected call to parse_endtag"
        if rawdata.find('>', i + 2) < 0:  # fast check
            return -1
        if not html.parser.endtagopen.match(rawdata, i):  # </ + letter
            if rawdata[i + 2:i + 3] == '>':  # </> is ignored
                return i + 3
            else:
                return self.parse_bogus_comment(i)
        match = _LOCATETAGEND.match(rawdata, i + 2)
        assert match
        j = match.end()
        self._tick((j - i) // 1024)
        if rawdata[j - 1] != ">":
            return -1
        match = _TAGNAME.match(rawdata, i + 2)
        assert match
        tag = match.group(0).lower()
        self.handle_endtag(tag)
        self.clear_cdata_mode()
        return j

    def result(self) -> str:
        self.close()
        while self.stack:
            self._emit(f"</{self.stack.pop()}>")
        return "".join(self.out)


_TAG_COST_CHARS = "'\"\t\n\r\f /&"
# html.parser.tagfind_tolerant's group 1 alone: its trailing loop over separators keeps
# backtracking state for each (3.3 GiB for one crafted 20 MiB tag)
_TAGNAME = re.compile(r"[a-zA-Z][^\t\n\r\f />]*")
_DECIMAL_REF_ZEROS = re.compile(r"&#0+(?=[0-9])")
_LONG_DECIMAL_REF = re.compile(r"&#[1-9][0-9]{7,}")


def _tag_cost(text: str, start: int, end: int) -> int:
    """An upper bound on html.parser's work for the start tag text[start:end]: each attribute
    name follows one of the separators, and each character reference in a value starts with
    "&". Counted in C, without copying."""
    return sum(text.count(c, start, end) for c in _TAG_COST_CHARS)


def sanitize_html(source: str, cids: CidScope, used: dict, warnings: list[str], budget: dict | None = None,
                  collect_only: bool = False, embedded: set | None = None) -> tuple[str, int]:
    """One section, sanitized; the same text gets the same answer in predict() and the view.
    A section with more than MAX_ENTITIES "&" is refused (html.parser decodes the character
    references of one text run in a single step); it is over twice PREDICT_MAX_INPUT, so this
    never refuses a section a prediction accepted. Decimal character references are first
    written the way html.unescape reads them, without leading zeros, and one of eight or more
    digits (over U+10FFFF, so U+FFFD) as 65533: Python refuses to convert over 4,300 digits."""
    if source.count("&") > MAX_ENTITIES:
        raise ViewError("html-too-complex")
    if "&#" in source:   # also inside raw text (a style's CSS may read "&#65;" for "&#0065;": harmless)
        source = _LONG_DECIMAL_REF.sub("&#65533", _DECIMAL_REF_ZEROS.sub("&#", source))
    s = _Sanitizer(cids, used, warnings, budget, collect_only, embedded)
    s.feed(source)
    return s.result(), s.remote_images


# --- header block and authentication line ----------------------------------------------------------
def _raw_header(msg, name: str) -> list[str]:
    """Top-level header values exactly as supplied (unfolded), without the policy's parsing:
    a parsed Date, for example, is reformatted by email.policy.default."""
    out = []
    for k, v in msg.raw_items():
        if k.lower() == name.lower():
            v = str(v).encode("utf-8", "surrogateescape").decode("utf-8", "replace")  # raw 8-bit bytes
            out.append(re.sub(r"\r?\n[ \t]+", " ", v).strip())
    return out


def _display(name: str, stored) -> str | None:
    """The header block's text for one stored value, or None when it must be shown unparsed: the
    unfolded value is exactly what the parser would read, and it is parsed only within the
    bound for its kind (address lists are parsed superlinearly) and the comment-depth check."""
    stored = str(stored)
    limit = SUBJECT_HEADER_PARSE if name.lower() == "subject" else ADDRESS_HEADER_PARSE
    if len(stored) - stored.count("\r") - stored.count("\n") > limit:
        return None                              # counted before unfolding: the same length
    flat = stored.replace("\r", "").replace("\n", "")
    try:
        return _scrub(str(parse_header(name, flat)))
    except ViewError:
        return None


def _unparsed(value: str) -> str:
    """A header value shown without the structured parse: its RFC 2047 encoded words decoded
    when it is at most DECODE_WORDS_MAX characters (email.header's decoder is superlinear),
    else, or when they do not decode, the text as supplied."""
    if "=?" in value and len(value) <= DECODE_WORDS_MAX:
        try:
            return str(email.header.make_header(email.header.decode_header(value)))
        except Exception:
            pass
    return value


def _hdr(msg, name: str, warnings: list[str]) -> str:
    """One header for the header block: its first occurrence (duplicates are counted from the
    raw headers, never parsed). Date is shown as the message-supplied text (5.2); a value over
    its parse bound, or one the parser rejects, is shown unparsed (encoded words decoded)."""
    if name.lower() in getattr(msg, "too_long", ()):
        raise ViewError("header-too-long")       # over _PAGE_HEADER_MAX: a prediction never accepts it
    raw = _raw_header(msg, name)
    if len(raw) > 1:
        warnings.append(f"duplicate-header-{name.lower()}")
    if not raw:
        return ""
    if name == "Date":
        return raw[0]
    stored = next(v for k, v in msg.raw_items() if k.lower() == name.lower())
    shown = _display(name, stored)
    if shown is None:
        warnings.append(f"header-shown-unparsed-{name.lower()}")
        return _scrub(_unparsed(raw[0]))
    return shown


def subject_of(raw: bytes) -> str:
    """The Subject for file names when no view is built, as the view's header block would show
    it: only the top-level header block (at most _SUBJECT_SCAN bytes, up to the first empty
    line) is read, with compat32, which parses no structured header; the first Subject is
    then shown exactly as _hdr shows it. Never raises."""
    try:
        head = raw[:_SUBJECT_SCAN]
        ends = [i for i in (head.find(b"\r\n\r\n"), head.find(b"\n\n")) if i >= 0]
        if ends:
            head = head[:min(ends) + 2]
        msg = email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(head)
        return _hdr(msg, "Subject", [])
    except Exception:
        return ""


_AUTHSERV_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_METHOD_RE = re.compile(r"^\s*([A-Za-z0-9-]{1,64})\s*=\s*([A-Za-z]{1,32})(?![A-Za-z])")


def _strip_comments(s: str) -> str:
    out, depth = [], 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


def auth_line(msg) -> str:
    """'Authentication-Results reported in message (not independently verified)'.
    Top-level headers only; authserv-id parsed as a token; only mx.google.com results are
    summarized; absent, conflicting, or malformed headers show as unavailable or ambiguous.
    Header position and authserv-id text do not establish origin."""
    label = "Authentication-Results reported in message (not independently verified)"
    if "authentication-results" in getattr(msg, "dropped", ()):
        return f"{label}: unavailable (too many headers)"   # the view kept only the first _HEADER_COPIES
    values = _raw_header(msg, "Authentication-Results")    # raw text: no structured parse
    summaries, malformed = [], False
    for v in values:
        if len(v) > _AUTH_RESULTS_MAX:          # never scanned (the scan is per character)
            malformed = True
            continue
        items = _strip_comments(v).split(";")
        head = items[0].split()
        if not head or not _AUTHSERV_RE.match(head[0]):
            malformed = True
            continue
        if head[0].lower() != "mx.google.com":
            continue
        results = []
        for it in items[1:]:
            m = _METHOD_RE.match(it)
            if m and m.group(1).lower() in ("dkim", "spf", "dmarc", "arc"):
                results.append(f"{m.group(1).lower()}={m.group(2).lower()}")
        summaries.append(" ".join(sorted(set(results))) or "none")
    if not summaries:
        return f"{label}: unavailable{' (malformed)' if malformed else ''}"
    if len(set(summaries)) > 1:
        return f"{label}: ambiguous (conflicting mx.google.com headers)"
    return f"{label}: mx.google.com {summaries[0]}"


# --- the view -----------------------------------------------------------------------------------------
@dataclass
class View:
    page: bytes
    title: str
    headers: dict
    body_part: dict
    warnings: list[str] = field(default_factory=list)
    inputs_key: str = ""
    cid_used: int = 0
    remote_images: int = 0
    embedded: list = field(default_factory=list)   # MIME paths of the image parts embedded


class ViewError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _path_str(path: tuple[int, ...]) -> str:
    return ".".join(map(str, path)) or "root"


def _class_prefix(raw_sha: str) -> str:
    return "gmcp" + raw_sha[:10]


_HEADER_CSS = """
.{p}-hdr{{font:13px/1.45 -apple-system,Helvetica,Arial,sans-serif;color:#111;background:#f4f4f4;
border:1px solid #ccc;padding:10px 12px;margin:0 0 14px 0}}
.{p}-hdr td{{padding:1px 8px 1px 0;vertical-align:top}}
.{p}-hdr td.{p}-k{{font-weight:600;white-space:nowrap}}
.{p}-auth{{font-size:11px;color:#444}}
.{p}-plain{{white-space:pre-wrap;font:13px/1.45 Menlo,monospace}}
pre,code,tt,kbd,samp,xmp,listing{{white-space:pre-wrap!important;overflow-wrap:anywhere!important}}
"""


def _count_parts(part, depth: int = 0) -> int:
    """The parts the view walks: every node outside nested messages (whose parts are never
    shown), to the depth selection descends."""
    n = 1
    if part.get_content_maintype() != "message" and part.is_multipart() and depth <= MAX_DEPTH:
        for k in part.iter_parts():
            n += _count_parts(k, depth + 1)
            if n > MAX_PARTS:
                break
    return n


def _deepest(part, depth: int = 0) -> int:
    """The depth of the deepest node the view parses (nested messages are leaves), counted up
    to MAX_DEPTH + 1: the view's parse refuses anything deeper than MAX_DEPTH."""
    if depth > MAX_DEPTH or part.get_content_maintype() == "message" or not part.is_multipart():
        return depth
    return max((_deepest(k, depth + 1) for k in part.iter_parts()), default=depth)


def _render_sections(sections: list[Selection], p: str, warnings: list[str], budget: dict, collect_only: bool):
    """THE section loop, for the view (collect_only False) and predict() (True: nothing is
    built and image bytes are not read; every size is charged exactly). Each section is
    decoded and sanitized on its own (a fresh parser, every element it opened closed at its
    end), so markup in one section cannot reach into the next. Images are decoded once per
    related scope. Returns (fragments, infos, shas, scopes, embedded, remote)."""
    scopes: dict = {}          # related scope path -> (its CidScope, data: URIs built by part path)
    embedded: set = set()
    fragments: list[str] = []
    infos: list[dict] = []
    shas: list[str] = []
    remote = total_in = 0
    open_w, close_w = f'<div class="{p}-section">', "</div>"
    plain_open = f'<div class="{p}-plain">'
    for sel in sections:
        if time.monotonic() > budget["deadline"]:
            raise ViewError("view-too-slow")
        if _uuencoded(sel.part):                 # never decoded: left out, and said so
            warnings.append("section-encoding-unsupported")
            continue
        text, payload = _decode_text(sel.part, warnings, budget["deadline"], budget["limit"] - total_in)
        if time.monotonic() > budget["deadline"]:
            raise ViewError("view-too-slow")
        total_in += len(payload)
        if total_in > budget["limit"]:
            raise ViewError("html-too-large")
        if not collect_only:
            shas.append(hashlib.sha256(payload).hexdigest())
        infos.append({"selected": _path_str(sel.path), "content_type": sel.ctype,
                      "related_scope": None if sel.scope_path is None else _path_str(sel.scope_path)})
        wrap = len(open_w) + len(close_w)
        _charge(budget, wrap, wrap if collect_only else 0)
        if sel.ctype == "text/html":
            if sel.scope_path not in scopes:
                scopes[sel.scope_path] = (collect_cids(sel.scope, sel.scope_path or (), warnings,
                                                       read_data=not collect_only, deadline=budget["deadline"]), {})
            cids, used = scopes[sel.scope_path]
            frag, r = sanitize_html(text, cids, used, warnings, budget, collect_only, embedded)
            remote += r
        elif collect_only:
            frag = ""
            extra = 4 * text.count("&") + 3 * text.count("<") + 3 * text.count(">")   # html.escape, quote=False
            fixed = len(plain_open) + len("</div>")
            _charge(budget, fixed + len(text) + extra, fixed + len(text.encode("utf-8")) + extra)
        else:
            frag = f"{plain_open}{html.escape(text, quote=False)}</div>"
            _charge(budget, len(frag))
        if not collect_only:
            fragments.append(f"{open_w}{frag}{close_w}")
    return fragments, infos, shas, scopes, embedded, remote


@dataclass
class Prediction:
    """What build_view would do with a message, for the attachment enumerator."""
    ok: bool                       # False: the view would fail or could not be predicted (reason)
    reason: str | None
    sections: list                 # paths of the text sections rendered as the body
    alternatives: list             # paths of text sections that are alternatives of them
    embedded: list                 # paths of the image parts embedded (empty unless ok)
    marked: list = field(default_factory=list)   # of those, the ones marked `attachment`


def parse_cost_failure(size_estimate, depth: int) -> str | None:
    """Why the view's parse could miss its deadline for a message of `size_estimate` bytes
    (Gmail's sizeEstimate) whose deepest MIME part is at `depth`, or None. The prediction
    cannot see the lines of parts it never reads, so it bounds them by size: a successful
    prediction then implies the view parses the message in time."""
    if not isinstance(size_estimate, int) or isinstance(size_estimate, bool) or size_estimate < 0:
        return "size-unknown"
    seconds = size_estimate / (1024 * 1024) * (PARSE_MIB_SECONDS + PARSE_LEVEL_SECONDS * max(0, depth))
    return "too-large-to-predict" if seconds > PARSE_SHARE * VIEW_SECONDS else None


def _page_limit(header_bytes: int) -> int:
    """The page size a prediction allows: MAX_PAGE_BYTES less 5%, the page's fixed parts, and
    twelve times the header block's bytes (each value escaped, up to six times, and the Subject
    shown twice)."""
    return MAX_PAGE_BYTES - MAX_PAGE_BYTES // 20 - 16384 - 12 * max(0, header_bytes)


def unembedded_failure(sections: list[Selection], header_bytes: int = 0) -> str | None:
    """Why the view could fail a message in which nothing can be embedded (predict() does not
    sanitize such a body), or None. Its body text must be at most PREDICT_MAX_INPUT bytes, so
    the sanitizer's work stays small, and six times that (escaping a character takes at most
    six) must fit the page with its header block."""
    declared = sum(_declared_size(sel.part) for sel in sections)
    if declared > PREDICT_MAX_INPUT:
        return "too-large-to-predict"
    if 6 * declared > _page_limit(header_bytes):
        return "html-too-large"
    return None


def predict(root, header_bytes: int = 0, deadline: float | None = None) -> Prediction:
    """build_view's own selection, CID collection, and sanitizer over `root` (any object with
    the email package's part interface; mime passes Gmail's FULL payload), without building
    the page. Selection is structural and always answered, so the enumerator's listing never
    depends on the rest. When no rendered section's related scope holds an embeddable image,
    nothing is decoded or fetched: the declared body size alone must fit (unembedded_failure).
    Otherwise image bytes are still not read: an embedded image
    is assumed to decode and its declared size is charged. The size limit is lowered by 5% plus
    a bound on the header block (`header_bytes`: From, To, Cc, Date, Subject, and
    Authentication-Results), at most PREDICT_MAX_INPUT body bytes are decoded, and the content
    phase has PREDICT_SECONDS, so a successful prediction implies the view succeeds (on the
    conditions mime.predict_view states); when the view could fail, nothing counts as embedded."""
    warnings: list[str] = []
    alternatives: list = []
    try:
        if _count_parts(root) > MAX_PARTS:
            return Prediction(False, "mime-too-many-parts", [], [], [])
        if _deepest(root) > MAX_DEPTH:
            return Prediction(False, "mime-too-deep", [], [], [])
        sections = select_body(root, warnings, alternatives)
        paths = [sel.path for sel in sections]
        if STDLIB_CHANGED:
            return Prediction(False, "stdlib-changed", paths, alternatives, [])
        if not may_embed(sections):
            why = unembedded_failure(sections, header_bytes)
            return Prediction(why is None, why, paths, alternatives, [])
    except Exception:
        return Prediction(False, "unsupported-mime", [], [], [])
    limit = _page_limit(header_bytes)
    budget = _budget(limit, PREDICT_SECONDS, deadline)
    try:
        declared = sum(_declared_size(sel.part) for sel in sections)    # before any fetch
        if declared > limit:
            raise ViewError("html-too-large")
        if declared > PREDICT_MAX_INPUT:
            raise ViewError("too-large-to-predict")
        rendered = _render_sections(sections, _class_prefix("0" * 64), warnings, budget, collect_only=True)
    except (ViewError, BodyUnavailable) as e:
        return Prediction(False, e.code, paths, alternatives, [])
    except Exception:
        return Prediction(False, "view-error", paths, alternatives, [])
    scopes, embedded = rendered[3], rendered[4]
    images = {img.path: img for cids, _ in scopes.values() for img in cids.exact.values() if img is not None}
    return Prediction(True, None, paths, alternatives, sorted(embedded),
                      sorted(x for x in embedded if images[x].attachment))


def _check(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise ViewError("view-too-slow")


def _escaped_len(text: str, quote: bool) -> int:
    """len(html.escape(text, quote)), counted."""
    n = len(text) + 4 * text.count("&") + 3 * (text.count("<") + text.count(">"))
    return n + 5 * (text.count('"') + text.count("'")) if quote else n


def build_view(raw: bytes) -> View:
    """Build the sanitized, wrapped page for one message from its decoded RAW bytes."""
    if STDLIB_CHANGED:
        raise ViewError("stdlib-changed")
    raw_sha = hashlib.sha256(raw).hexdigest()
    warnings: list[str] = []
    deadline = time.monotonic() + VIEW_SECONDS
    msg = _parse(raw, deadline)
    if getattr(msg, "defects", None):
        warnings.append("message-mime-defects")
    if _count_parts(msg) > MAX_PARTS:
        raise ViewError("mime-too-many-parts")
    sections = select_body(msg, warnings, deadline=deadline)
    if time.monotonic() > deadline:
        raise ViewError("view-too-slow")
    hdrs = {}
    for n in ("From", "To", "Cc", "Date", "Subject"):
        _check(deadline)
        hdrs[n] = _hdr(msg, n, warnings)
    _check(deadline)
    auth = _scrub(auth_line(msg))
    _check(deadline)
    p = _class_prefix(raw_sha)

    budget = _budget(MAX_PAGE_BYTES, deadline=deadline)   # shared by all sections
    fragments, infos, shas, scopes, embedded, remote = _render_sections(sections, p, warnings, budget, False)
    if not fragments:
        warnings.append("no-displayable-body")
        fragments.append("<p><em>(No displayable text body in this message.)</em></p>")
    fragment = "".join(fragments)
    body_info = {"sections": infos}
    cid_digest = sorted((_path_str(path), hashlib.sha256(uri.encode()).hexdigest())
                        for _, used in scopes.values() for path, uri in used.items())

    shown = [v for k, v in hdrs.items() if v or k in ("From", "Date", "Subject")]
    title = hdrs.get("Subject") or "(no subject)"
    # the page's size is known before it is built: escaped lengths are counted (the page's UTF-8
    # length is at least this many characters), so a page over the cap is never assembled
    if (sum(_escaped_len(v, True) for v in shown) + _escaped_len(title, False) + _escaped_len(auth, False)
            + len(fragment) > MAX_PAGE_BYTES):
        raise ViewError("html-too-large")
    _check(deadline)
    rows = "".join(
        f'<tr><td class="{p}-k">{k}:</td><td>{html.escape(v, quote=True)}</td></tr>'
        for k, v in hdrs.items() if v or k in ("From", "Date", "Subject"))
    page = (
        "<!DOCTYPE html>\n<html><head>"
        '<meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(CSP, quote=True)}">'
        f"<title>{html.escape(title, quote=False)}</title>"
        f"<style>{_HEADER_CSS.format(p=p)}</style>"
        "</head><body>"
        f'<div class="{p}-hdr"><table>{rows}</table>'
        f'<div class="{p}-auth">{html.escape(auth, quote=False)}</div></div>'
        f'<div class="{p}-body">{fragment}</div>'
        "</body></html>\n"
    ).encode("utf-8")
    if len(page) > MAX_PAGE_BYTES:
        raise ViewError("html-too-large")
    key_inputs = {"recipe": RECIPE_VERSION, "csp": CSP, "raw_sha256": raw_sha, "body": body_info,
                  "body_sha256": shas, "cids": cid_digest, "headers": hdrs, "auth": auth}
    inputs_key = hashlib.sha256(json.dumps(key_inputs, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return View(page=page, title=title, headers=hdrs, body_part=body_info, warnings=sorted(set(warnings)),
                inputs_key=inputs_key, cid_used=len(embedded), remote_images=remote, embedded=sorted(embedded))
