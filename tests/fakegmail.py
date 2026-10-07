"""An in-memory fake of the parts of the Gmail API the server uses.

Messages are built from synthetic RFC 822 bytes, so FULL payloads, RAW bytes, and
attachments are consistent. Fault injection lets tests make any call fail definitively
(HTTP error) or ambiguously (mutation applied, response lost). No network, no real data.
"""
from __future__ import annotations

import base64
import email
import email.policy
import hashlib
import json
import secrets
import socket

import httplib2
from googleapiclient.errors import HttpError

SYSTEM_LABELS = ["INBOX", "SPAM", "TRASH", "UNREAD", "STARRED", "IMPORTANT", "SENT", "DRAFT",
                 "CHAT", "CATEGORY_PERSONAL", "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS",
                 "CATEGORY_UPDATES", "CATEGORY_FORUMS"]


def http_error(status: int, message: str = "fake error") -> HttpError:
    resp = httplib2.Response({"status": str(status)})
    resp.status = status
    content = json.dumps({"error": {"code": status, "message": message}}).encode()
    return HttpError(resp, content, uri="https://gmail.googleapis.com/fake")


class LostResponse(socket.timeout):
    """The fake applied the mutation, then 'lost' the response (an ambiguous outcome)."""


def b64url(data: bytes, pad: bool = False) -> str:
    s = base64.urlsafe_b64encode(data).decode()
    return s if pad else s.rstrip("=")


class _Req:
    def __init__(self, fn):
        self._fn = fn

    def execute(self, num_retries: int = 0):
        return self._fn()


class _Node:
    """Generic chain node: attribute access returns a callable that builds a _Req."""

    def __init__(self, g: "FakeGmail", prefix: str):
        self._g = g
        self._prefix = prefix

    def __getattr__(self, name):
        sub = {"messages", "threads", "labels", "drafts", "settings", "filters", "attachments", "history"}
        if name in sub:
            return lambda: _Node(self._g, f"{self._prefix}.{name}" if self._prefix else name)
        full = f"{self._prefix}.{name}" if self._prefix else name
        return lambda **kw: _Req(lambda: self._g.call(full, **kw))


class FakeGmail:
    def __init__(self, email_address: str = "alpha@example.test", padded_b64: bool = False,
                 rfc822_mode: str = "opaque", batch_missing: str = "ignore",
                 label_names_case_insensitive: bool = True):
        self.email = email_address
        self.padded_b64 = padded_b64
        self.rfc822_mode = rfc822_mode          # "opaque" | "parsed"
        self.batch_missing = batch_missing      # "ignore" | "error"
        self.ci_names = label_names_case_insensitive
        self.messages: dict[str, dict] = {}
        self.labels: dict[str, dict] = {}
        self.filters: list[dict] = []
        self.calls: list[tuple[str, dict]] = []
        self.faults: list[dict] = []
        self._next_label = 1
        self._next_msg = 0x18c0000000000000 + (secrets.randbits(36) << 12)  # unique per fake
        for name in SYSTEM_LABELS:
            self.labels[name] = {"id": name, "name": name, "type": "system"}

    # --- chain entry points -------------------------------------------------------
    def users(self):
        return _Node(self, "")

    # --- fault injection --------------------------------------------------------------
    def fail(self, method: str, status: int | None = None, *, times: int = 1, lost: bool = False,
             when=None, exc: Exception | None = None):
        """Make `method` fail. status -> HttpError; lost=True -> apply, then raise
        LostResponse; exc -> raise that exception before applying."""
        self.faults.append({"method": method, "status": status, "times": times, "lost": lost,
                            "when": when, "exc": exc})

    def _fault_for(self, method: str, kw: dict):
        for f in self.faults:
            if f["method"] == method and f["times"] > 0 and (f["when"] is None or f["when"](kw)):
                f["times"] -= 1
                return f
        return None

    def call(self, method: str, **kw):
        self.calls.append((method, kw))
        f = self._fault_for(method, kw)
        if f and not f["lost"]:
            if f["exc"] is not None:
                raise f["exc"]
            raise http_error(f["status"] or 500)
        result = getattr(self, "_" + method.replace(".", "_"))(**kw)
        if f and f["lost"]:
            raise LostResponse("response lost after the mutation was applied")
        return result

    def count(self, method: str) -> int:
        return sum(1 for m, _ in self.calls if m == method)

    # --- building messages ----------------------------------------------------------
    def add_message(self, raw: bytes, *, msg_id: str | None = None, thread_id: str | None = None,
                    labels=("INBOX",), search_text: str = "") -> str:
        if msg_id is None:
            self._next_msg += 1
            msg_id = f"{self._next_msg:016x}"
        attachments: dict[str, bytes] = {}
        parsed = email.message_from_bytes(raw, policy=email.policy.compat32)
        payload = self._payload(parsed, "", attachments, msg_id)
        subj = parsed.get("Subject", "")
        self.messages[msg_id] = {
            "id": msg_id, "threadId": thread_id or msg_id, "labelIds": set(labels), "raw": raw,
            "payload": payload, "attachments": attachments, "snippet": f"snippet {subj}"[:100],
            "search": (search_text or subj).lower(),
        }
        return msg_id

    def _payload(self, part, part_id: str, attachments: dict, msg_id: str) -> dict:
        headers = [{"name": k, "value": str(v)} for k, v in part.items()]
        mime = part.get_content_type()
        node = {"partId": part_id, "mimeType": mime, "filename": part.get_filename() or "",
                "headers": headers, "body": {"size": 0}}
        if part.is_multipart() and mime != "message/rfc822":
            kids = part.get_payload()
            node["parts"] = [self._payload(c, f"{part_id}.{i}" if part_id else str(i), attachments, msg_id)
                             for i, c in enumerate(kids)]
            return node
        if mime == "message/rfc822":
            inner = part.get_payload()[0]
            data = inner.as_bytes()
            node["body"]["size"] = len(data)
            if self.rfc822_mode == "opaque":
                att = self._att_id(msg_id, part_id, data)
                attachments[att] = data
                node["body"]["attachmentId"] = att
            else:
                node["parts"] = [self._payload(inner, f"{part_id}.0" if part_id else "0", attachments, msg_id)]
            return node
        data = part.get_payload(decode=True) or b""
        node["body"]["size"] = len(data)
        disp = (part.get("Content-Disposition") or "").split(";")[0].strip().lower()
        if node["filename"] or disp == "attachment":
            att = self._att_id(msg_id, part_id, data)
            attachments[att] = data
            node["body"]["attachmentId"] = att
        else:
            node["body"]["data"] = b64url(data, self.padded_b64)
        return node

    @staticmethod
    def _att_id(msg_id: str, part_id: str, data: bytes) -> str:
        return "ANGjdJ" + hashlib.sha256(f"{msg_id}/{part_id}".encode() + data).hexdigest()[:40]

    def add_stub(self, msg_id: str, thread_id: str | None = None, labels=("INBOX",)):
        self.messages[msg_id] = {"id": msg_id, "threadId": thread_id or msg_id, "labelIds": set(labels),
                                 "raw": b"", "payload": {"mimeType": "text/plain", "headers": []},
                                 "attachments": {}, "snippet": "", "search": ""}
        return msg_id

    def add_label(self, name: str, *, type_: str = "user", **settings) -> str:
        lid = f"Label_{self._next_label}"
        self._next_label += 1
        self.labels[lid] = {"id": lid, "name": name, "type": type_, **settings}
        return lid

    def members(self, label_id: str) -> set[str]:
        return {m for m, rec in self.messages.items() if label_id in rec["labelIds"]}

    # --- API surface ----------------------------------------------------------------------
    def _getProfile(self, userId):
        return {"emailAddress": self.email}

    def _get(self, msg_id):
        if msg_id not in self.messages:
            raise http_error(404, "Requested entity was not found.")
        return self.messages[msg_id]

    def _messages_list(self, userId, q=None, maxResults=100, pageToken=None, labelIds=None,
                       includeSpamTrash=False, fields=None):
        ids = []
        for mid, rec in self.messages.items():
            if not includeSpamTrash and rec["labelIds"] & {"SPAM", "TRASH"}:
                continue
            if labelIds and not set(labelIds) <= rec["labelIds"]:
                continue
            if q and q.lower() not in rec["search"]:
                continue
            ids.append(mid)
        start = 0
        if pageToken is not None:
            if not (isinstance(pageToken, str) and pageToken.isdigit()):
                raise http_error(400, "Invalid pageToken")
            start = int(pageToken)
        page = ids[start:start + int(maxResults)]
        resp = {"resultSizeEstimate": len(ids)}
        if page:
            resp["messages"] = [{"id": m, "threadId": self.messages[m]["threadId"]} for m in page]
        if start + int(maxResults) < len(ids):
            resp["nextPageToken"] = f"{start + int(maxResults):020d}"
        return resp

    def _messages_get(self, userId, id, format="full", metadataHeaders=None, fields=None):
        rec = self._get(id)
        out = {"id": rec["id"], "threadId": rec["threadId"], "labelIds": sorted(rec["labelIds"]),
               "snippet": rec["snippet"], "sizeEstimate": len(rec["raw"])}
        if format == "raw":
            out["raw"] = b64url(rec["raw"], self.padded_b64)
        elif format == "metadata":
            hs = [h for h in rec["payload"]["headers"]
                  if not metadataHeaders or h["name"].lower() in {x.lower() for x in metadataHeaders}]
            out["payload"] = {"mimeType": rec["payload"]["mimeType"], "headers": hs}
        elif format == "full":
            out["payload"] = json.loads(json.dumps(rec["payload"]))
        return out

    def _messages_attachments_get(self, userId, messageId, id):
        rec = self._get(messageId)
        if id not in rec["attachments"]:
            raise http_error(404, "attachment not found")
        data = rec["attachments"][id]
        return {"size": len(data), "data": b64url(data, self.padded_b64)}

    def _apply(self, rec, add, remove):
        for l in add or []:
            if l not in self.labels:
                raise http_error(400, "Invalid label")
        rec["labelIds"] |= set(add or [])
        rec["labelIds"] -= set(remove or [])

    def _messages_modify(self, userId, id, body):
        rec = self._get(id)
        self._apply(rec, body.get("addLabelIds"), body.get("removeLabelIds"))
        return {"id": id, "threadId": rec["threadId"], "labelIds": sorted(rec["labelIds"])}

    def _messages_batchModify(self, userId, body):
        ids = body.get("ids") or []
        if len(ids) > 1000:
            raise http_error(400, "Too many ids")
        missing = [i for i in ids if i not in self.messages]
        if missing and self.batch_missing == "error":
            raise http_error(404, "Requested entity was not found.")
        for i in ids:
            if i in self.messages:
                self._apply(self.messages[i], body.get("addLabelIds"), body.get("removeLabelIds"))
        return ""

    def _threads_get(self, userId, id, format="full"):
        msgs = [m for m in self.messages.values() if m["threadId"] == id]
        if not msgs:
            raise http_error(404, "thread not found")
        return {"id": id, "messages": [self._messages_get(userId, m["id"], format=format) for m in msgs]}

    def _threads_modify(self, userId, id, body):
        msgs = [m for m in self.messages.values() if m["threadId"] == id]
        if not msgs:
            raise http_error(404, "thread not found")
        for m in msgs:
            self._apply(m, body.get("addLabelIds"), body.get("removeLabelIds"))
        return {"id": id, "messages": [{"id": m["id"], "labelIds": sorted(m["labelIds"])} for m in msgs]}

    def _labels_list(self, userId):
        return {"labels": [dict(l) for l in self.labels.values()]}

    def _labels_get(self, userId, id):
        if id not in self.labels:
            raise http_error(404, "label not found")
        lab = dict(self.labels[id])
        lab["messagesTotal"] = len(self.members(id))
        return lab

    def _name_taken(self, name: str, exclude: str | None = None) -> bool:
        for l in self.labels.values():
            if l["id"] == exclude:
                continue
            if l["name"] == name or (self.ci_names and l["name"].lower() == name.lower()):
                return True
        return False

    def _labels_create(self, userId, body):
        name = body.get("name", "")
        if not name or self._name_taken(name):
            raise http_error(409, "Label name exists or conflicts")
        lid = f"Label_{self._next_label}"
        self._next_label += 1
        lab = {"id": lid, "type": "user"}
        lab.update({k: v for k, v in body.items() if v is not None})
        self.labels[lid] = lab
        return dict(lab)

    def _labels_patch(self, userId, id, body):
        if id not in self.labels:
            raise http_error(404, "label not found")
        lab = self.labels[id]
        if lab["type"] != "user":
            raise http_error(400, "Invalid update for a system label")
        if "name" in body and self._name_taken(body["name"], exclude=id):
            raise http_error(409, "Label name exists or conflicts")
        lab.update(body)
        return dict(lab)

    def _labels_delete(self, userId, id):
        if id not in self.labels:
            raise http_error(404, "label not found")
        if self.labels[id]["type"] != "user":
            raise http_error(400, "Invalid delete for a system label")
        for rec in self.messages.values():
            rec["labelIds"].discard(id)
        del self.labels[id]
        return ""

    def _settings_filters_list(self, userId):
        return {"filter": [dict(f) for f in self.filters]} if self.filters else {}

    def _drafts_create(self, userId, body):
        return {"id": "r-1234567890123456789", "message": {"id": "18c00000000000aa"}}

    def _messages_send(self, userId, body):
        return {"id": "18c00000000000bb"}


class PersistentFake(FakeGmail):
    """A FakeGmail whose label/membership/filter state lives in a JSON file and is saved
    after every mutating call, so a crashed worker process leaves the 'remote' state behind
    exactly as Gmail would (used by the label crash gates)."""

    MUTATING = {"labels.create", "labels.patch", "labels.delete", "messages.modify", "messages.batchModify",
                "threads.modify"}

    def __init__(self, path, email_address="alpha@example.test", **kw):
        super().__init__(email_address, **kw)
        self.path = str(path)
        import os
        if os.path.exists(self.path):
            with open(self.path) as f:
                st = json.load(f)
            self.labels = st["labels"]
            self.filters = st["filters"]
            self._next_label = st["next_label"]
            self.batch_missing = st.get("batch_missing", self.batch_missing)
            self.messages = {}
            for mid, rec in st["messages"].items():
                self.add_stub(mid, rec["threadId"], rec["labelIds"])

    def save(self):
        import os
        st = {"labels": self.labels, "filters": self.filters, "next_label": self._next_label,
              "batch_missing": self.batch_missing,
              "messages": {m: {"threadId": r["threadId"], "labelIds": sorted(r["labelIds"])} for m, r in self.messages.items()}}
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def call(self, method: str, **kw):
        try:
            return super().call(method, **kw)
        finally:
            if method in self.MUTATING:
                self.save()
