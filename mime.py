"""Shared MIME enumerator over Gmail's format=FULL payload (PLAN-v4 5.1 and 5.3).

`read_email` and `save_attachments` both number parts with this one enumerator, so the
indexes a caller sees in read_email are the indexes save_attachments accepts.

- Stable depth-first order over the whole MIME tree, keeping Gmail's `partId` and the
  tree path.
- Coverage (owner decisions, 2026-10-05): every leaf part is body text (a section the
  export view renders, or an alternative of one), embedded by the view, or listed and
  saved by default. Listed: a part with a filename, an explicit `attachment` disposition,
  or an attached `message/rfc822` part (as before), plus every other leaf that is not body
  text and not inside an attached message saved whole. Listing depends only on the MIME
  structure, so indexes never move.
- Inline (skipped by default) ONLY when the export view would embed the part and the sender
  did not mark it `attachment` (that disposition wins). The answer comes from the view's own
  code: htmlview.predict() runs the view's selection, CID collection, and sanitizer over this
  FULL payload through an adapter, so the two cannot drift. When the view would fail or
  cannot be predicted, no part is inline and the tools say why.
- Unnamed listed parts get a generated name (RFC 2183 makes filenames optional).
- Bounds: at most MAX_PARTS parts and MAX_DEPTH nesting, checked while walking.
"""
from __future__ import annotations

import base64
import email.parser
import email.policy
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

import htmlview

MAX_PARTS = 500
MAX_DEPTH = 20
MAX_SECTION_FETCHES = 4      # body sections Gmail stored behind an attachment id, fetched to predict the view
MAX_HEADER_VALUE = 2048      # one Content-Type, Content-Disposition, or Content-ID value the prediction parses
MAX_HEADER_TOTAL = 64 * 1024 # all of them in one message (the email package's parser is superlinear)
MAX_NODE_HEADERS = 64        # structural headers on one node
MAX_STRUCTURAL_HEADERS = 2000  # structural headers in one message
PREDICTION_TTL = 600.0       # seconds a prediction is reused for the same account and message
_HEADER_NAME_RE = re.compile(r"^[!-9;-~]+$")      # an RFC 5322 field name
_LINE_BREAKS = re.compile(r"[\r\n]+")
# a boundary parameter however written (a comment or RFC 2231 star before "="); a second one,
# or "boundary=" inside a value, makes the structure ambiguous
_BOUNDARY_PARAM = re.compile(r'boundary[^=;"]*=', re.I)
# a boundary parameter written plainly: a token (no tspecials, quotes, or apostrophes), or a
# quoted string without a backslash, then only blanks before the next parameter
_PLAIN_BOUNDARY = re.compile(r'(?:^|;)[ \t]*boundary[ \t]*=[ \t]*(?:"([^"\\]*)"|([^\s"\'\\;()<>@,:/\[\]?=]+))'
                             r'[ \t]*(?=;|$)', re.I)
_BCHARS = re.compile(r"[0-9A-Za-z'()+_,\-./:=? ]*[0-9A-Za-z'()+_,\-./:=?]")   # RFC 2046, no trailing space
# the encodings the view decodes exactly as written (any case); other spellings make the
# prediction unavailable, since Gmail may decode a body the view would not, or the reverse
_STANDARD_CTE = frozenset({"7bit", "8bit", "binary", "base64", "quoted-printable"})
_PAGE_HEADERS = ("from", "to", "cc", "date", "subject", "authentication-results")

_GENERATED_EXT = {
    "application/pdf": ".pdf", "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
    "image/webp": ".webp", "image/heic": ".heic", "image/jpg": ".jpg", "image/tiff": ".tif", "text/plain": ".txt",
    "text/html": ".html", "text/csv": ".csv", "text/calendar": ".ics", "message/rfc822": ".eml",
    "application/zip": ".zip", "application/json": ".json", "application/xml": ".xml",
}


class MimeLimitError(Exception):
    """The MIME structure exceeds MAX_PARTS or MAX_DEPTH."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class MalformedData(Exception):
    """Base64url data that is not well formed."""


class DataTooLarge(Exception):
    """Encoded data whose decoded size would exceed the caller's bound."""


@dataclass(frozen=True)
class Part:
    index: int                 # 1-based, stable, among ELIGIBLE parts in depth-first order
    part_id: str               # Gmail partId ("" for the root payload)
    path: tuple[int, ...]      # MIME tree path (child indexes from the root)
    mime_type: str
    filename: str              # Gmail-supplied name ("" if none)
    name: str                  # filename, or a generated name
    generated_name: bool
    disposition: str | None    # "attachment" | "inline" | other | None
    content_id: str | None
    inline: bool
    size: int | None           # Gmail's declared body.size
    attachment_id: str | None
    data: str | None           # inline base64url body data, when Gmail supplies it
    is_message: bool           # an attached message/rfc822 part
    parsed_container: bool     # rfc822 exposed only as parsed parts (no original octets)

    @property
    def path_str(self) -> str:
        return ".".join(str(i) for i in self.path) or "root"


def _header(node: dict, name: str) -> str | None:
    for h in node.get("headers") or []:
        if (h.get("name") or "").lower() == name.lower():
            return h.get("value") or ""
    return None


def _disposition(node: dict) -> str | None:
    raw = _header(node, "Content-Disposition")
    if raw is None:
        return None
    return raw.split(";", 1)[0].strip().lower() or None


def _content_id(node: dict) -> str | None:
    raw = _header(node, "Content-ID")
    if not raw:
        return None
    return raw.strip().strip("<>").strip() or None


def generated_name(mime_type: str, part_id: str, is_message: bool) -> str:
    stem = "attached-message" if is_message else "part"
    label = part_id if part_id else "root"
    return f"{stem}-{label}{_GENERATED_EXT.get(mime_type, '.bin')}"


class _Payload:
    """One message's FULL payload, adapted once: the adapter of every node the view parses (all
    but the inside of attached messages) is built up front, in a fixed order, so the result
    never depends on timing, and reused by every walk."""

    def __init__(self, payload: dict, fetch=None):
        self.fetch = fetch
        self.broken = False                       # a node's own headers are unreadable (it reads as an attachment)
        self.structural = False                   # Gmail's tree and the view's parse may differ
        self.policy = htmlview.view_policy()      # one guard for the message: each value parsed once
        self._parts: dict[int, _GmailPart] = {}
        self._keep: list = []                    # keeps nodes alive so their id() stays unique
        self._frozen = False
        # (node, its default type, the boundaries of the multiparts it is nested in)
        stack: list[tuple[object, str, tuple]] = [(payload, "text/plain", ())]
        while stack:
            node, default, outer = stack.pop()
            part = self.part(node, default)
            kids = node.get("parts") if isinstance(node, dict) else None
            if not part.broken:
                if _is_message(node) != (part.get_content_maintype() == "message"):
                    self.structural = True       # Gmail and the headers disagree on an attached message
                elif not _is_message(node) and (isinstance(kids, list) and bool(kids)) != (
                        part.get_content_maintype() == "multipart"):
                    self.structural = True       # Gmail split a part the view would not, or the reverse
            if _is_message(node):
                if _inner_conflict(node, outer):
                    self.structural = True       # the view's parse could end an enclosing part inside it
                continue                         # the view never parses into an attached message
            if part.boundary is not None:
                if any(b.startswith(part.boundary) or part.boundary.startswith(b) for b in outer):
                    self.structural = True       # nested boundaries readers may match differently
                outer = outer + (part.boundary,)
            if isinstance(kids, list):
                child = "message/rfc822" if part.get_content_type() == "multipart/digest" else "text/plain"
                stack.extend((k, child, outer) for k in kids)
        self.root = self.part(payload)
        self._frozen = True

    def part(self, node, default_type: str = "text/plain") -> "_GmailPart":
        p = self._parts.get(id(node))
        if p is None:
            if self._frozen:
                # a node this walk did not build (Gmail labels it message/* while its headers
                # say otherwise): never parsed on demand; the prediction is unavailable
                self.structural = True
                return _GmailPart(None, self, default_type)
            p = _GmailPart(node, self, default_type)
            self._parts[id(node)] = p
            self._keep.append(node)
            self.broken = self.broken or p.broken
        return p


class _GmailPart:
    """One node of Gmail's FULL payload with the email package's part interface. Its four
    structural headers (htmlview.STRUCTURAL_HEADERS) are unfolded as the view unfolds them and
    parsed once, through the view's own guarded policy and htmlview.parse_header, so the view
    and this adapter agree on every value, and htmlview's selection, CID collection, and
    sanitizer run on it unchanged. The node is broken when it has more than MAX_NODE_HEADERS
    of them, any of them twice, a value over MAX_HEADER_VALUE, one parse_header calls
    unreadable, a value with a comment, a Content-Transfer-Encoding other than the five
    standard ones exactly, or (a multipart) a boundary not written plainly or read differently
    by the view's parser: it then reads as application/octet-stream (never body, never
    embedded) and the prediction is unavailable. Construction never raises. A text section's
    bytes come from body.data or, when Gmail stored it behind an attachment id, one fetch;
    image bytes are never read (declared_size is Gmail's body.size)."""

    def __init__(self, node, owner: _Payload, default_type: str = "text/plain"):
        self.node = node if isinstance(node, dict) else {}
        self._owner = owner
        self.broken = not isinstance(node, dict)
        self.boundary: str | None = None          # a multipart's boundary, when plainly written
        lines, seen, ctype = [], set(), ""
        for h in self.node.get("headers") or []:
            name = str(h.get("name") or "") if isinstance(h, dict) else ""
            if name.lower() not in htmlview.STRUCTURAL_HEADERS or not _HEADER_NAME_RE.match(name):
                continue
            value = _LINE_BREAKS.sub("", str(h.get("value") or ""))      # unfolded as the view unfolds
            if len(value) > MAX_HEADER_VALUE or len(lines) >= MAX_NODE_HEADERS or name.lower() in seen:
                self.broken = True                # a second value: readers may take either one
                break
            seen.add(name.lower())
            if name.lower() == "content-type":
                ctype = value
            elif name.lower() == "content-transfer-encoding" and value.lower() not in _STANDARD_CTE:
                self.broken = True
            elif name.lower() == "content-id" and not value.isascii():
                self.broken = True                # read from 8-bit bytes: Gmail and the view may differ
            if _has_comment(value):
                self.broken = True
            lines.append(f"{name}: {value}\n")
        self._ctype, self._attachment, self._charset, self._start, self._cid = (
            "application/octet-stream", False, None, None, None)
        if not self.broken:
            try:
                h = email.parser.HeaderParser(policy=owner.policy).parsestr("".join(lines) + "\n")
                if default_type != "text/plain":
                    h.set_default_type(default_type)
                cid = h.get("Content-ID")
                h.get("Content-Transfer-Encoding")      # parsed (and checked) as the view parses it
                if h.get_content_maintype() == "multipart":
                    literal = _plain_boundary(ctype)
                    if literal is None or not ctype.isascii() or h.get_boundary() != literal:
                        raise htmlview.ViewError("header-unreadable")
                    self.boundary = literal
                self._ctype, self._attachment, self._charset, self._start, self._cid = (
                    h.get_content_type(), h.is_attachment(), h.get_content_charset(), h.get_param("start"),
                    None if cid is None else str(cid))
            except Exception:              # header-too-long or header-unreadable from the guard
                self.broken = True
                self.boundary = None
                self._ctype, self._attachment, self._charset, self._start, self._cid = (
                    "application/octet-stream", False, None, None, None)
        size = (self.node.get("body") or {}).get("size")
        self.declared_size = size if isinstance(size, int) and size >= 0 else 0
        self.defects: list = []

    def get(self, name, failobj=None):
        if str(name).lower() == "content-id" and self._cid is not None:
            return self._cid
        return failobj

    def get_param(self, param, failobj=None, header="content-type", unquote=True):
        if str(param).lower() == "start" and header == "content-type" and self._start is not None:
            return self._start
        return failobj

    def get_content_type(self) -> str:
        return self._ctype

    def get_content_maintype(self) -> str:
        return self._ctype.split("/")[0]

    def get_content_charset(self, failobj=None):
        return self._charset if self._charset is not None else failobj

    def is_attachment(self) -> bool:
        return self._attachment

    def _kids(self) -> list:
        kids = self.node.get("parts")
        return kids if isinstance(kids, list) else []

    def is_multipart(self) -> bool:
        return bool(self._kids())

    def iter_parts(self):
        if self.get_content_maintype() != "multipart":
            return
        default = "message/rfc822" if self._ctype == "multipart/digest" else "text/plain"
        for k in self._kids():
            yield self._owner.part(k, default)

    def needs_fetch(self) -> bool:
        body = self.node.get("body") or {}
        return body.get("data") is None and bool(body.get("attachmentId"))

    def get_payload(self, decode=False):
        body = self.node.get("body") or {}
        if body.get("data") is not None:
            encoded = body["data"]
        elif body.get("attachmentId"):
            if self._owner.fetch is None:
                raise htmlview.BodyUnavailable("body-not-fetched")
            try:
                encoded = self._owner.fetch(body["attachmentId"]) or ""
            except Exception:
                raise htmlview.BodyUnavailable("body-unavailable") from None
        else:
            return b""
        try:
            return b64url_decode(encoded, htmlview.MAX_PAGE_BYTES)
        except DataTooLarge:
            raise htmlview.ViewError("html-too-large") from None
        except MalformedData:
            raise htmlview.BodyUnavailable("body-malformed") from None


def _inner_conflict(message: dict, outer: tuple) -> bool:
    """Whether a multipart Gmail shows inside an attached message has a boundary that equals or
    prefixes an enclosing one, or one not written plainly. The view reads the attached message
    as opaque lines, each checked against the enclosing boundaries, so such a boundary could end
    an enclosing part where Gmail does not. An attached message Gmail keeps whole shows none."""
    if not outer:
        return False
    stack = list(message.get("parts") or []) if isinstance(message.get("parts"), list) else []
    total = 0
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        kids = node.get("parts")
        if isinstance(kids, list) and kids:
            stack.extend(kids)
            if _is_message(node):
                continue                          # a message inside it: its own parts are walked
            ctypes = _header_values(node, ("content-type",))
            if len(ctypes) != 1 or len(ctypes[0]) > MAX_HEADER_VALUE:
                return True                       # none, a second one, or too long to read
            total += len(ctypes[0])
            if total > MAX_HEADER_TOTAL:
                return True                       # more than the prediction reads anywhere else
            b = _plain_boundary(_LINE_BREAKS.sub("", ctypes[0]))     # unfolded as the adapter unfolds
            if b is None or any(o.startswith(b) or b.startswith(o) for o in outer):
                return True
    return False


def _plain_boundary(value: str) -> str | None:
    """A multipart Content-Type's boundary when it is written plainly, so that every reader
    takes the same value from it: exactly one boundary parameter, a token or a quoted string
    with no backslash and no encoded word, followed by nothing but the next parameter. Else
    None (the view's parser decodes, unescapes, or truncates other spellings; Gmail may not)."""
    found = _PLAIN_BOUNDARY.findall(value)
    if len(found) != 1 or len(_BOUNDARY_PARAM.findall(value)) != 1:
        return None
    literal = found[0][0] or found[0][1]
    # RFC 2046 characters only: an 8-bit boundary reads decoded in the header but stays escaped
    # in the body lines the view's parser compares it with, so the view could never split on it
    return literal if _BCHARS.fullmatch(literal) and "=?" not in literal else None


def _has_comment(value: str) -> bool:
    """Whether a header value has a comment: a "(" outside a quoted string. Gmail and the
    view's parser may read such a value differently (where a parameter starts, whether a
    multipart splits), so it makes the prediction unavailable. Linear."""
    quoted = escaped = False
    for ch in value:
        if escaped:
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == "(" and not quoted:
            return True
    return False


def _header_values(node: dict, names) -> list[str]:
    out = []
    for h in (node.get("headers") or []) if isinstance(node, dict) else []:
        if isinstance(h, dict) and str(h.get("name") or "").lower() in names:
            out.append(str(h.get("value") or ""))
    return out


def _is_message(node) -> bool:
    return isinstance(node, dict) and str(node.get("mimeType") or "").lower().startswith("message/")


def _view_nodes(payload: dict) -> tuple[list[dict], int]:
    """The nodes the export view parses, and the deepest one's depth (the root is 0): every
    node except the inside of an attached message (the view never parses into a message/*
    part; that part's own headers it does read)."""
    out, deepest, stack = [], 0, [(payload, 0)]
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, dict):
            continue
        out.append(node)
        deepest = max(deepest, depth)
        kids = node.get("parts")
        if not _is_message(node) and isinstance(kids, list):
            stack.extend((k, depth + 1) for k in kids)
    return out, deepest


def _raw_estimate(value: str) -> int:
    """An upper bound on how long the view could find this value in the RAW message, with
    headroom: twice its length when Gmail shows plain ASCII; four times its UTF-8 size plus 16
    otherwise, since Gmail may show RFC 2047 or 2231 encoded text decoded, and the encoded
    form is up to about 3.6 times longer."""
    size = len(value.encode("utf-8", "surrogatepass"))
    return 2 * size if value.isascii() else 4 * size + 16


def _view_accepts_headers(nodes: list[dict]) -> bool:
    """False when the view could refuse this message for its structural headers (each value
    over VIEW_HEADER_VALUE, or all of them over VIEW_HEADER_TOTAL, as RAW text). Counts every
    occurrence of every structural header the view parses; the view counts each distinct
    value once, so this never says yes where the view says no."""
    total = 0
    for node in nodes:
        for v in _header_values(node, htmlview.STRUCTURAL_HEADERS):
            est = _raw_estimate(v)
            if est > htmlview.VIEW_HEADER_VALUE:
                return False
            total += est
    return total <= htmlview.VIEW_HEADER_TOTAL


def predict_view(payload: dict, fetch_attachment=None, *, size_estimate) -> htmlview.Prediction:
    """The export view's own answer for this FULL payload: htmlview.predict through the
    adapter. The structural part (headers, within MAX_STRUCTURAL_HEADERS, MAX_HEADER_VALUE,
    and MAX_HEADER_TOTAL, and body selection) is bounded and deterministic, so the listing
    built from it never moves. It is unavailable whenever the view could refuse the message:
    for its headers (every structural header the view parses, checked against the view's own
    caps with headroom), for its structure (anything Gmail and the view's parser may split
    differently), for the time its parse could take (`size_estimate`, Gmail's sizeEstimate,
    against the deepest part; without one it is unavailable), or for its body
    (htmlview.predict). A successful prediction therefore implies the view builds this message
    and embeds the predicted parts, on these conditions: Gmail's FULL payload shows RAW's tree,
    and its structural values as written apart from unfolding (the size caps also allow for
    encoded words shown decoded); it decodes bodies as Python does; its sizeEstimate is close
    to the RAW size; and the host runs the view's parse at most about twice as slowly as
    measured (htmlview.PARSE_*). When Gmail's tree and the view's could differ, the prediction
    is "structure-ambiguous" with no sections, so every part is listed and saved. The content
    part sanitizes only when an image could be embedded, fetches at most MAX_SECTION_FETCHES
    sections, and has htmlview's short prediction budget."""
    deadline = time.monotonic() + htmlview.PREDICT_SECONDS      # the header phase counts against it too
    try:
        try:
            _check_bounds(payload)                  # the view refuses more parts or deeper nesting
        except MimeLimitError as e:
            return htmlview.Prediction(False, e.code, [], [], [])
        nodes, depth = _view_nodes(payload or {})
        values = [v for n in nodes for v in _header_values(n, htmlview.STRUCTURAL_HEADERS)]
        if len(values) > MAX_STRUCTURAL_HEADERS:
            return htmlview.Prediction(False, "too-many-headers", [], [], [])
        if sum(len(v) for v in values) > MAX_HEADER_TOTAL:
            return htmlview.Prediction(False, "header-too-long", [], [], [])
        adapted = _Payload(payload or {}, fetch_attachment)
        if adapted.structural:          # Gmail's sections may not be the view's: none count as body
            return htmlview.Prediction(False, "structure-ambiguous", [], [], [])
        if adapted.broken:              # a node read as an attachment may be the view's body: none counts
            return htmlview.Prediction(False, "header-unreadable", [], [], [])
        alternatives: list = []
        sections = htmlview.select_body(adapted.root, [], alternatives)
        paths = [sel.path for sel in sections]
        if htmlview.STDLIB_CHANGED:
            return htmlview.Prediction(False, "stdlib-changed", paths, alternatives, [])
        if not _view_accepts_headers(nodes):
            return htmlview.Prediction(False, "header-too-long", paths, alternatives, [])
        why = htmlview.parse_cost_failure(size_estimate, depth)
        if why:
            return htmlview.Prediction(False, why, paths, alternatives, [])
        page_headers = sum(len(v.encode("utf-8", "replace")) for v in _header_values(payload or {}, _PAGE_HEADERS))
        if not htmlview.may_embed(sections):
            why = htmlview.unembedded_failure(sections, page_headers)
            return htmlview.Prediction(why is None, why, paths, alternatives, [])
        if sum(1 for sel in sections if sel.part.needs_fetch()) > MAX_SECTION_FETCHES:
            return htmlview.Prediction(False, "too-many-sections-to-fetch", paths, alternatives, [])
        pred = htmlview.predict(adapted.root, page_headers, deadline)
        if adapted.structural:  # a node only predict()'s own walk reached
            return htmlview.Prediction(False, "structure-ambiguous", [], [], [])
        if adapted.broken:
            return htmlview.Prediction(False, "header-unreadable", [], [], [])
        return pred
    except Exception:
        return htmlview.Prediction(False, "unsupported-mime", [], [], [])


_predictions: OrderedDict = OrderedDict()
_predictions_lock = threading.Lock()


def _cached_prediction(key, payload: dict, fetch, size_estimate) -> htmlview.Prediction:
    """One prediction per (account, message) for PREDICTION_TTL seconds, so read_email and a
    following save_attachments agree on inline flags even if a fetch fails in between."""
    now = time.monotonic()
    with _predictions_lock:
        hit = _predictions.get(key)
        if hit is not None and now - hit[0] < PREDICTION_TTL:
            _predictions.move_to_end(key)
            return hit[1]
    pred = predict_view(payload, fetch, size_estimate=size_estimate)
    with _predictions_lock:
        _predictions[key] = (now, pred)
        _predictions.move_to_end(key)
        while len(_predictions) > 256:
            _predictions.popitem(last=False)
    return pred


def inline_note(reason: str) -> str:
    return f"Inline classification ({reason}): no part is marked inline, so every listed part is saved by default."


def _check_bounds(payload: dict) -> None:
    stack: list[tuple[object, int]] = [(payload or {}, 0)]
    seen = 0
    while stack:
        node, depth = stack.pop()
        seen += 1
        if seen > MAX_PARTS:
            raise MimeLimitError("mime-too-many-parts")
        if depth > MAX_DEPTH:
            raise MimeLimitError("mime-too-deep")
        kids = node.get("parts") if isinstance(node, dict) else None
        if isinstance(kids, list):
            stack.extend((k, depth + 1) for k in kids)


def enumerate_message(payload: dict, fetch_attachment=None, cache_key=None, *,
                      size_estimate) -> tuple[list[Part], str | None]:
    """THE entry point for read_email and save_attachments, so their indexes and inline flags
    agree: bounds first (a refused structure costs no fetch), then the export view's
    prediction (reused for the same `cache_key`, the account and message), then the listing.
    `size_estimate` is the message's Gmail sizeEstimate (required: the view's parse time
    grows with it). Returns (parts, reason): reason is None when the view's embedding is
    known, else the fixed code for why no part is marked inline."""
    _check_bounds(payload)
    if cache_key is None:
        pred = predict_view(payload, fetch_attachment, size_estimate=size_estimate)
    else:
        pred = _cached_prediction(cache_key, payload, fetch_attachment, size_estimate)
    return enumerate_parts(payload, pred), (None if pred.ok else pred.reason)


def enumerate_parts(payload: dict, pred: htmlview.Prediction | None = None) -> list[Part]:
    """All listed parts, numbered in stable depth-first order (see the module notes).
    `pred` is the export view's prediction (when omitted, one without a fetcher or a size,
    so no part is inline); its sections and alternatives are structural, so the listing
    never depends on its outcome, only the inline flags do."""
    _check_bounds(payload)
    if pred is None:
        pred = predict_view(payload, size_estimate=None)
    covered = {tuple(x) for x in pred.sections} | {tuple(x) for x in pred.alternatives}
    embedded = {tuple(x) for x in pred.embedded} if pred.ok else set()
    marked = {tuple(x) for x in pred.marked} if pred.ok else set()
    eligible: list[Part] = []
    stack: list[tuple[dict, tuple[int, ...], bool]] = [(payload or {}, (), False)]
    while stack:
        node, path, in_saved_message = stack.pop()
        if not isinstance(node, dict):
            continue
        mime = (node.get("mimeType") or "application/octet-stream").lower()
        children = node.get("parts") or []
        if not isinstance(children, list):
            children = []
        is_multipart = mime.startswith("multipart/")
        filename = node.get("filename") or ""
        disp = _disposition(node)
        is_message = mime == "message/rfc822"
        body = node.get("body") or {}
        att = body.get("attachmentId") or None
        data = body.get("data") or None
        size = body.get("size")
        named = not is_multipart and bool(filename or disp == "attachment" or is_message)
        has_content = att is not None or data is not None or (isinstance(size, int) and size > 0)
        # every leaf is body text, embedded, inside an attached message saved whole, or listed
        uncovered = not children and path not in covered and not in_saved_message and has_content
        if named or uncovered:
            part_id = str(node.get("partId") or "")
            eligible.append(Part(
                index=len(eligible) + 1, part_id=part_id, path=path, mime_type=mime,
                filename=filename,
                name=filename or generated_name(mime, part_id, is_message),
                generated_name=not filename, disposition=disp, content_id=_content_id(node),
                # inline only when the view embeds it; an explicit attachment disposition wins
                inline=path in embedded and path not in marked,
                size=size if isinstance(size, int) and size >= 0 else None,
                attachment_id=att, data=data, is_message=is_message,
                parsed_container=is_message and not att and data is None,
            ))
        saved_whole = is_message and (att is not None or data is not None)
        for i in range(len(children) - 1, -1, -1):
            stack.append((children[i], path + (i,), in_saved_message or saved_whole))
    return eligible


_B64URL_RE = re.compile(rb"^[A-Za-z0-9_-]*={0,2}$")


def b64url_decode(data, max_decoded: int) -> bytes:
    """Decode Gmail base64url deliberately: only the URL-safe alphabet, padding optional but
    correct when present, a remainder of 1 refused, and the decoded size bounded BEFORE
    decoding. Malformed input raises MalformedData; never silently skipped characters."""
    if isinstance(data, str):
        try:
            data = data.encode("ascii")
        except UnicodeEncodeError:
            raise MalformedData("non-ascii") from None
    if not isinstance(data, (bytes, bytearray)) or not _B64URL_RE.match(data):
        raise MalformedData("alphabet")
    stripped = bytes(data).rstrip(b"=")
    pads = len(data) - len(stripped)
    rem = len(stripped) % 4
    if rem == 1:
        raise MalformedData("length")
    if pads and (len(data) % 4 != 0 or pads != (4 - rem) % 4):
        raise MalformedData("padding")
    if len(stripped) * 3 // 4 > max_decoded:
        raise DataTooLarge()
    padded = stripped + b"=" * ((4 - rem) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        raise MalformedData("decode") from None


def attachment_lines(parts: list[Part], clean) -> list[str]:
    """The read_email listing (inside the fence): `[index] name (mimeType, size, inline|attachment)`."""
    out = []
    for p in parts:
        size = f"{p.size} bytes" if p.size is not None else "size unknown"
        kind = "inline" if p.inline else "attachment"
        gen = " [generated name]" if p.generated_name else ""
        extra = ", original octets unavailable" if p.parsed_container else ""
        out.append(f"[{p.index}] {clean(p.name)}{gen} ({clean(p.mime_type)}, {size}, {kind}{extra})")
    return out
