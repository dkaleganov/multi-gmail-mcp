"""Thin wrapper over the Gmail API: search, read, labels, archive/mark-read, drafts.

Uses only the official google-api-python-client. The only network calls this module makes
are to https://www.googleapis.com (Gmail). No telemetry, no other endpoints.
"""
from __future__ import annotations

import base64
import html
import re
from email.mime.text import MIMEText

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials


def service(creds: Credentials):
    # cache_discovery=False avoids writing a discovery cache file to disk.
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def get_profile_email(creds: Credentials) -> str:
    return service(creds).users().getProfile(userId="me").execute().get("emailAddress", "")


def _header(headers: list[dict], name: str) -> str:
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def _b64d(data: str) -> bytes:
    """Decode base64url, tolerating missing padding (Gmail sometimes omits it)."""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _no_crlf(value: str | None, field: str) -> str | None:
    """Reject CR/LF in a user-supplied header value (blocks header injection regardless
    of interpreter version)."""
    if value is None:
        return value
    if "\r" in value or "\n" in value:
        raise ValueError(f"Illegal newline in '{field}'.")
    return value


_BLOCK_START = re.compile(r"<(script|style)", re.I)
_CLOSE_CACHE: dict[str, re.Pattern] = {}


def _drop_script_style(text: str) -> str:
    """Linear-time equivalent of v4's
        re.sub(r"<(script|style)[^>]*>.*?</\\1>", "", text, flags=re.S | re.I)
    which was quadratic on unclosed <script> tags (a hostile email could freeze the server).
    Same match semantics: each start tag ends at its first '>', the block at the first
    case-insensitive closing tag after it; a start with no closing tag stays as text."""
    out, pos, no_close = [], 0, set()
    for m in _BLOCK_START.finditer(text):
        i = m.start()
        if i < pos:
            continue
        name = m.group(1)
        key = name.lower()
        if key in no_close:
            continue                      # no closing tag after an earlier start, so none after this one
        gt = text.find(">", m.end())
        if gt < 0:
            break                         # no '>' after this start, so none after any later start
        pat = _CLOSE_CACHE.get(name)
        if pat is None:
            pat = _CLOSE_CACHE[name] = re.compile("</" + re.escape(name) + ">", re.I)
        c = pat.search(text, gt + 1)
        if c is None:
            no_close.add(key)
            continue
        out.append(text[pos:i])
        pos = c.end()
    out.append(text[pos:])
    return "".join(out)


def _drop_tags(text: str) -> str:
    """Linear-time equivalent of v4's re.sub(r"<[^>]+>", " ", text) (quadratic on many '<'
    without a '>')."""
    out, pos = [], 0
    while True:
        i = text.find("<", pos)
        if i < 0:
            break
        gt = text.find(">", i + 1)
        if gt < 0:
            break                         # no '>' after this '<', so no later '<' matches either
        if gt == i + 1:                   # "<>": [^>]+ needs at least one character
            out.append(text[pos:i + 1])
            pos = i + 1
            continue
        out.append(text[pos:i])
        out.append(" ")
        pos = gt + 1
    out.append(text[pos:])
    return "".join(out)


def _strip_html(html_text: str) -> str:
    text = _drop_script_style(html_text)
    text = _drop_tags(text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _extract_body(payload: dict) -> str:
    """Recursively pull text/plain from a MIME payload; fall back to stripped text/html."""
    mime = payload.get("mimeType", "")
    data = payload.get("body", {}).get("data")
    if mime == "text/plain" and data:
        return _b64d(data).decode("utf-8", errors="replace")
    parts = payload.get("parts")
    if parts:
        for part in parts:  # prefer a top-level text/plain part
            if part.get("mimeType") == "text/plain":
                txt = _extract_body(part)
                if txt:
                    return txt
        chunks = [_extract_body(part) for part in parts]  # else recurse (multipart/*)
        joined = "\n".join(c for c in chunks if c)
        if joined:
            return joined
    if mime == "text/html" and data:
        return _strip_html(_b64d(data).decode("utf-8", errors="replace"))
    return ""


def search(creds, query: str, max_results: int = 10) -> list[dict]:
    """v4 interface (one page, no token); kept for compatibility."""
    return search_page(creds, query, max_results=max_results)["messages"]


def search_page(creds, query: str, max_results: int = 10, page_token: str | None = None) -> dict:
    """One page of results plus Gmail's nextPageToken (returned even on an empty page).
    A message that vanishes between list and metadata fetch (404) is skipped and counted,
    without losing the page token. Any other error propagates."""
    from googleapiclient.errors import HttpError

    svc = service(creds)
    kw = {"userId": "me", "q": query, "maxResults": max_results}
    if page_token:
        kw["pageToken"] = page_token
    resp = svc.users().messages().list(**kw).execute()
    out, vanished = [], 0
    for m in resp.get("messages", []):
        try:
            full = (
                svc.users()
                .messages()
                .get(userId="me", id=m["id"], format="metadata", metadataHeaders=["From", "Subject", "Date"])
                .execute()
            )
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", None)
            if str(status) == "404":
                vanished += 1
                continue
            raise
        h = full.get("payload", {}).get("headers", [])
        out.append(
            {
                "id": full["id"],
                "threadId": full.get("threadId", ""),
                "from": _header(h, "From"),
                "subject": _header(h, "Subject"),
                "date": _header(h, "Date"),
                "snippet": full.get("snippet", ""),
                "labelIds": full.get("labelIds", []),
            }
        )
    return {"messages": out, "next_page_token": resp.get("nextPageToken"), "vanished": vanished}


def read_message(creds, message_id: str) -> dict:
    full = service(creds).users().messages().get(userId="me", id=message_id, format="full").execute()
    payload = full.get("payload", {})
    h = payload.get("headers", [])
    return {
        "id": full.get("id", message_id),
        "threadId": full.get("threadId", ""),
        "from": _header(h, "From"),
        "to": _header(h, "To"),
        "cc": _header(h, "Cc"),
        "subject": _header(h, "Subject"),
        "date": _header(h, "Date"),
        "labelIds": full.get("labelIds", []),
        "body": _extract_body(payload),
        "payload": payload,
        "sizeEstimate": full.get("sizeEstimate"),
    }


def get_message_full(creds, message_id: str) -> dict:
    """The message with its full MIME payload (format=FULL), for the attachment enumerator."""
    return service(creds).users().messages().get(userId="me", id=message_id, format="full").execute()


def get_message_raw(creds, message_id: str) -> dict:
    """The message as base64url RFC 2822 bytes (format=RAW): the single source for exports."""
    return service(creds).users().messages().get(userId="me", id=message_id, format="raw").execute()


def get_attachment(creds, message_id: str, attachment_id: str) -> dict:
    """users.messages.attachments.get -> {"size": int, "data": base64url}."""
    return (
        service(creds).users().messages().attachments()
        .get(userId="me", messageId=message_id, id=attachment_id).execute()
    )


def read_thread(creds, thread_id: str) -> list[dict]:
    thread = service(creds).users().threads().get(userId="me", id=thread_id, format="full").execute()
    msgs = []
    for full in thread.get("messages", []):
        payload = full.get("payload", {})
        h = payload.get("headers", [])
        msgs.append(
            {
                "id": full.get("id", ""),
                "from": _header(h, "From"),
                "to": _header(h, "To"),
                "cc": _header(h, "Cc"),
                "subject": _header(h, "Subject"),
                "date": _header(h, "Date"),
                "labelIds": full.get("labelIds", []),
                "body": _extract_body(payload),
            }
        )
    return msgs


def list_labels(creds) -> list[dict]:
    resp = service(creds).users().labels().list(userId="me").execute()
    return [{"id": l["id"], "name": l["name"]} for l in resp.get("labels", [])]


# Adding these moves mail toward deletion (Trash auto-purges permanently after ~30 days),
# which would break this server's no-delete guarantee. Removing them (untrash) is fine.
_BLOCKED_ADD_LABELS = frozenset({"TRASH", "SPAM"})


def resolve_labels(creds, add: list[str], remove: list[str]) -> tuple[list[str], list[str]]:
    """Map NAMES or IDs to label IDs for both lists in a SINGLE labels.list call.
    System labels (INBOX/UNREAD/...) resolve via their name; unknown labels raise.
    (Gmail reserves system-label names, so a name can't ambiguously mean a user label.)
    ADDING TRASH or SPAM is refused — see _BLOCKED_ADD_LABELS."""
    labels = list_labels(creds)
    ids = {l["id"] for l in labels}
    exact: dict[str, list[str]] = {}
    folded: dict[str, list[str]] = {}
    for l in labels:
        exact.setdefault(l["name"], []).append(l["id"])
        folded.setdefault(l["name"].lower(), []).append(l["id"])

    def lookup(t: str):
        """Exact id, then exact name, then a case-insensitive name only when unambiguous."""
        if t in ids:
            return t
        if len(exact.get(t, [])) == 1:
            return exact[t][0]
        cands = folded.get(t.lower(), [])
        if len(cands) > 1:
            raise ValueError(f"Ambiguous label '{t}': names differ only by case. Use the label id from list_labels.")
        return cands[0] if cands else None

    def resolve(tokens, blocked=frozenset()):
        out, unknown = [], []
        for t in tokens or []:
            lid = lookup(t)
            if lid is None:
                unknown.append(t)
                continue
            # check both the resolved id and the raw token, so the block holds even if
            # Gmail ever omits these system labels from labels.list
            if lid.upper() in blocked or t.strip().upper() in blocked:
                raise ValueError(
                    f"Refusing to add label '{t}': moving mail to Trash/Spam is blocked "
                    f"(Trash auto-purges after ~30 days; this server never deletes mail)."
                )
            out.append(lid)
        if unknown:
            raise ValueError(
                f"Unknown label(s): {', '.join(unknown)}. Use list_labels to see valid names/ids."
            )
        return out

    return resolve(add, blocked=_BLOCKED_ADD_LABELS), resolve(remove)


def modify_labels(creds, message_id: str, add: list[str] | None = None, remove: list[str] | None = None) -> dict:
    body = {"addLabelIds": add or [], "removeLabelIds": remove or []}
    return service(creds).users().messages().modify(userId="me", id=message_id, body=body).execute()


def create_draft(
    creds,
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    reply_to_message_id: str | None = None,
    thread_id: str | None = None,
) -> tuple[dict, str]:
    """Create a draft. Returns (api_result, subject_actually_used) so callers can audit the
    real subject (which is overridden to match the thread on replies)."""
    svc = service(creds)
    _no_crlf(to, "to")
    _no_crlf(cc, "cc")
    msg = MIMEText(body)  # Python 3 MIMEText auto-uses utf-8 when the body isn't ascii
    if reply_to_message_id:
        orig = (
            svc.users()
            .messages()
            .get(
                userId="me",
                id=reply_to_message_id,
                format="metadata",
                metadataHeaders=["Message-ID", "References", "Subject"],
            )
            .execute()
        )
        oh = orig.get("payload", {}).get("headers", [])
        orig_subject = _header(oh, "Subject")
        if orig_subject:  # force subject to match thread (sanitized; derived from existing mail)
            base = re.sub(r"[\r\n]+", " ", re.sub(r"^(re:\s*)+", "", orig_subject, flags=re.I)).strip()
            subject = f"Re: {base}"
        else:
            _no_crlf(subject, "subject")
        mid = _header(oh, "Message-ID")
        if mid:
            msg["In-Reply-To"] = mid
            msg["References"] = (_header(oh, "References") + " " + mid).strip()
        thread_id = thread_id or orig.get("threadId")
    else:
        _no_crlf(subject, "subject")
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    msg["Subject"] = subject
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    draft = {"message": {"raw": raw}}
    if thread_id:
        draft["message"]["threadId"] = thread_id
    result = svc.users().drafts().create(userId="me", body=draft).execute()
    return result, subject


def send_message(creds, to: str, subject: str, body: str, cc: str | None = None) -> dict:
    """Only invoked when enable_send=true. Defined here but never reached otherwise."""
    _no_crlf(to, "to")
    _no_crlf(cc, "cc")
    _no_crlf(subject, "subject")
    msg = MIMEText(body)
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    msg["Subject"] = subject
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return service(creds).users().messages().send(userId="me", body={"raw": raw}).execute()


# --- v5 label administration (sections 5.5-5.9) ------------------------------------------------
def list_labels_full(creds) -> list[dict]:
    """Full label resources (id, name, type, visibility, color)."""
    return service(creds).users().labels().list(userId="me").execute().get("labels", [])


def get_label(creds, label_id: str) -> dict:
    return service(creds).users().labels().get(userId="me", id=label_id).execute()


def create_label(creds, body: dict) -> dict:
    return service(creds).users().labels().create(userId="me", body=body).execute()


def patch_label(creds, label_id: str, body: dict) -> dict:
    return service(creds).users().labels().patch(userId="me", id=label_id, body=body).execute()


def delete_label(creds, label_id: str) -> None:
    service(creds).users().labels().delete(userId="me", id=label_id).execute()


def list_filters(creds) -> list[dict]:
    """users.settings.filters.list (read-only; permitted with gmail.modify)."""
    return service(creds).users().settings().filters().list(userId="me").execute().get("filter", []) or []


def label_member_ids(creds, label_id: str, cap: int) -> list[str] | None:
    """Every message id carrying the label, across all pages, INCLUDING spam and trash,
    deduplicated. Returns None as soon as the actual count exceeds `cap`."""
    svc = service(creds)
    seen: dict[str, None] = {}
    token = None
    while True:
        kw = {"userId": "me", "labelIds": [label_id], "includeSpamTrash": True, "maxResults": 500}
        if token:
            kw["pageToken"] = token
        resp = svc.users().messages().list(**kw).execute()
        for m in resp.get("messages", []) or []:
            seen[m["id"]] = None
            if len(seen) > cap:
                return None
        token = resp.get("nextPageToken")
        if not token:
            return list(seen)


def batch_modify(creds, ids: list[str], add: list[str] | None = None, remove: list[str] | None = None) -> None:
    """messages.batchModify (at most 1,000 ids; empty response body on success)."""
    body = {"ids": ids, "addLabelIds": add or [], "removeLabelIds": remove or []}
    service(creds).users().messages().batchModify(userId="me", body=body).execute()


def modify_thread(creds, thread_id: str, add: list[str] | None = None, remove: list[str] | None = None) -> dict:
    body = {"addLabelIds": add or [], "removeLabelIds": remove or []}
    return service(creds).users().threads().modify(userId="me", id=thread_id, body=body).execute()


def message_exists(creds, message_id: str) -> bool:
    """True if the message exists; False on 404; other errors propagate."""
    from googleapiclient.errors import HttpError

    try:
        service(creds).users().messages().get(userId="me", id=message_id, format="minimal").execute()
        return True
    except HttpError as e:
        status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", None)
        if str(status) == "404":
            return False
        raise
