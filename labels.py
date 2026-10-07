"""Label administration (PLAN-v4 5.5-5.9, 8.3) on top of the recovery journal (5.8).

Every operation runs inside a journal.AdminSession (the host-wide label-admin lock), uses
the verified account identity, and refuses system labels using the FETCHED resource's type
before any mutating call (CL1). Update, delete, and their undo write durable recovery
intent before each remote mutation; creation is not journaled (5.5). An ambiguous outcome
(timeout, 5xx, lost connection) is recorded as UNKNOWN_OUTCOME, never assumed "not
applied", and nothing is ever retried blindly. Results count evidence at its actual level:
accepted (API accepted), confirmed-missing (independently verified absent), unresolved,
conflicting; restored-and-verified only for ids actually read back.
"""
from __future__ import annotations

import os
import unicodedata

from googleapiclient.errors import HttpError

import exports
import gmail
import journal
import output
from output import ToolError

RESERVED_NAMES = frozenset(n.casefold() for n in (
    "INBOX", "SPAM", "TRASH", "UNREAD", "STARRED", "IMPORTANT", "SENT", "DRAFT", "DRAFTS", "CHAT", "CHATS",
    "ALL MAIL", "SCHEDULED", "SNOOZED", "OUTBOX", "MUTED", "YELLOW_STAR"))
LABEL_VISIBILITY = ("labelShow", "labelShowIfUnread", "labelHide")
MESSAGE_VISIBILITY = ("show", "hide")
TRACKED = ("name", "labelListVisibility", "messageListVisibility", "color")
ABSENT = {"__absent__": True}
UNDO_CHUNK = 1000
BATCH_MAX = 100
MAX_LABEL_NAME = 225
CHURN_RETRIES = 2

STATEMENTS_DELETE = (
    "No mail was deleted.",
    "Recovery can restore only the recorded label settings and memberships, to a NEW label id.",
    "Gmail filters and other references to the old label id are not repaired.",
)


def _checkpoint(stage: str) -> None:
    """Crash-test seam: tests replace this to kill the process at a protocol boundary."""


# --- helpers -----------------------------------------------------------------------------------
def http_status(e) -> int | None:
    code = getattr(e, "status_code", None)
    if code is None and getattr(e, "resp", None) is not None:
        code = getattr(e.resp, "status", None)
    try:
        return int(code) if code is not None else None
    except (TypeError, ValueError):
        return None


def definitive(e) -> bool:
    """True when the API definitively refused (4xx other than 408): nothing was applied.
    Timeouts, 5xx, connection errors, and anything unknown are ambiguous."""
    if isinstance(e, HttpError):
        s = http_status(e)
        return s is not None and 400 <= s < 500 and s != 408
    return False


def _journal(fn):
    """Map journal failures to fixed refusals, and report the retained journal size."""
    def wrapped(*a, **k):
        try:
            out, meta = fn(*a, **k)
            try:
                size = sum(e.stat().st_size for e in os.scandir(journal.runtime.private_dir("label-journal")))
                first, _, rest = out.partition("\n")
                out = first + " " + output.kv(journal_bytes=size) + ("\n" + rest if rest else "")
            except OSError:
                pass
            return out, meta
        except journal.JournalError as e:
            raise ToolError(e.code, "Label journal unavailable or busy; label administration refused "
                                    "(no further remote change was made).") from None
    return wrapped


def clean_name(raw) -> str:
    """Strip control characters and CR/LF; refuse empty, malformed nested, and reserved names."""
    if not isinstance(raw, str):
        raise ToolError("invalid-label-name", "Label name must be text.")
    s = "".join(ch for ch in raw if unicodedata.category(ch) != "Cc").strip()
    if not s:
        raise ToolError("invalid-label-name", "Label name is empty after removing control characters.")
    if len(s) > MAX_LABEL_NAME:
        raise ToolError("invalid-label-name", f"Label name is longer than {MAX_LABEL_NAME} characters.")
    if s.startswith("/") or s.endswith("/") or "//" in s:
        raise ToolError("invalid-label-name", "Nested label names use '/' between non-empty parts.")
    if s.casefold() in RESERVED_NAMES or s.upper().startswith("CATEGORY_"):
        raise ToolError("reserved-label-name", "That name is reserved for a system label.")
    return s


def _settings_args(label_list_visibility, message_list_visibility, color) -> dict:
    out = {}
    if label_list_visibility is not None:
        if label_list_visibility not in LABEL_VISIBILITY:
            raise ToolError("invalid-argument", "label_list_visibility must be labelShow, labelShowIfUnread, or labelHide.")
        out["labelListVisibility"] = label_list_visibility
    if message_list_visibility is not None:
        if message_list_visibility not in MESSAGE_VISIBILITY:
            raise ToolError("invalid-argument", "message_list_visibility must be show or hide.")
        out["messageListVisibility"] = message_list_visibility
    if color is not None:
        if (not isinstance(color, dict) or set(color) != {"backgroundColor", "textColor"}
                or not all(isinstance(v, str) and len(v) == 7 and v.startswith("#") for v in color.values())):
            raise ToolError("invalid-argument", "color must be {backgroundColor, textColor} as #rrggbb from Gmail's palette.")
        out["color"] = {"backgroundColor": color["backgroundColor"].lower(), "textColor": color["textColor"].lower()}
    return out


def state(label: dict, fields=TRACKED) -> dict:
    """The tracked settings, preserving whether optional fields were absent (a null value
    counts as absent: undo patches null to clear a field that did not exist before)."""
    return {f: label[f] if label.get(f) is not None else ABSENT for f in fields}


def _body(st: dict) -> dict:
    return {k: v for k, v in st.items() if v != ABSENT}


def resolve(labels: list[dict], token) -> dict:
    """Exact id first, exact name next; a case-insensitive match only when unambiguous."""
    if not isinstance(token, str) or not token.strip():
        raise ToolError("invalid-argument", "A label name or id is required.")
    for l in labels:
        if l.get("id") == token:
            return l
    exact = [l for l in labels if l.get("name") == token]
    if len(exact) == 1:
        return exact[0]
    folded = [l for l in labels if (l.get("name") or "").casefold() == token.casefold()]
    if len(exact) > 1 or len(folded) > 1:
        raise ToolError("ambiguous-label", "More than one label matches (names differ only by case); use the label id.",
                        detail="matching ids: " + ", ".join(str(l.get("id")) for l in (exact or folded)))
    if len(folded) == 1:
        return folded[0]
    raise ToolError("unknown-label", "Unknown label; use list_labels to see names and ids.",
                    detail=f"label as received: {token[:200]}")


def _lid(value) -> output.Safe:
    v = output.label_id(value)
    if v is None:
        raise ToolError("unexpected-label-id", "Gmail returned a label id in an unexpected format.")
    return v


def _account_id(a: dict) -> str:
    return exports.identity_hash(a["email"])  # a["email"] was verified against the token by _creds


def _get_or_none(creds, label_id: str):
    """(present, label) — 404 means absent; other errors propagate."""
    try:
        return True, gmail.get_label(creds, label_id)
    except HttpError as e:
        if http_status(e) == 404:
            return False, None
        raise


# --- reconciliation (5.8) -----------------------------------------------------------------------
def reconcile(s: journal.AdminSession, creds, op: journal.Op) -> None:
    """Resolve a PREPARED or UNKNOWN_OUTCOME operation by its original account and label id,
    from what is observed now. Never retries the mutation; records what was observed."""
    p = op.prepared
    try:
        present, cur = _get_or_none(creds, p["label_id"])
    except Exception:
        return  # still unresolved; the next permitted action stays "reconcile"
    if p["kind"] == "delete":
        if not present:
            s.append("APPLIED", op.op_id, observed={"absent": True}, reconciled=True)
        else:
            s.append("NOT_APPLIED", op.op_id, observed=state(cur), reconciled=True, reason="label-still-present")
        return
    if not present:
        if not op.reconciled or (op.observed or {}) != {"absent": True}:
            s.append("UNKNOWN_OUTCOME", op.op_id, observed={"absent": True}, reconciled=True,
                     next="none: the label no longer exists")
        return
    st = state(cur)
    if st == p["expected_after"]:
        s.append("APPLIED", op.op_id, observed=st, reconciled=True)
    elif st == p["before"]:
        s.append("NOT_APPLIED", op.op_id, observed=st, reconciled=True, reason="observed-before-state")
    elif not op.reconciled or op.observed != st:
        s.append("UNKNOWN_OUTCOME", op.op_id, observed=st, reconciled=True,
                 next="manual: the label is in neither the recorded before nor after state")


def _clear_pending(s, creds, account_id: str, label_id: str) -> None:
    for op in s.unresolved_for(account_id, label_id):
        reconcile(s, creds, op)
    if s.unresolved_for(account_id, label_id):
        raise ToolError("unresolved-operation", "An earlier change to this label has an unknown outcome that could "
                                                "not be reconciled; nothing was changed.")


# --- create_label (5.5) --------------------------------------------------------------------------
@_journal
def create_label(creds, a, name, label_list_visibility=None, message_list_visibility=None, color=None):
    nm = clean_name(name)
    body = {"name": nm, **_settings_args(label_list_visibility, message_list_visibility, color)}
    with journal.AdminSession():   # creation runs under the host-wide administration lock
        labels = gmail.list_labels_full(creds)
        exact = [l for l in labels if l.get("name") == nm]
        if exact:
            if exact[0].get("type") != "user":
                raise ToolError("reserved-label-name", "That name belongs to a system label.")
            return _create_result(a, "already-exists", exact[0]["id"], nm, "The label already exists; its settings were not changed.")
        folded = [l for l in labels if (l.get("name") or "").casefold() == nm.casefold()]
        if folded:
            raise ToolError("case-collision", "A label whose name differs only by case exists; nothing was created.",
                            detail="existing ids: " + ", ".join(str(l.get("id")) for l in folded))
        try:
            created = gmail.create_label(creds, body)
        except Exception as e:
            try:
                after = [l for l in gmail.list_labels_full(creds) if l.get("name") == nm]
            except Exception:
                after = None
            if isinstance(e, HttpError) and http_status(e) == 409:
                if after:
                    return _create_result(a, "already-exists", after[0]["id"], nm,
                                          "A label with this name was created concurrently; its settings were not changed.")
                raise ToolError("name-conflict", "Gmail reports that the name conflicts with an existing label; nothing was created.")
            if definitive(e):
                raise ToolError("create-rejected", "Gmail rejected the label (for example, a color outside its palette).",
                                detail=f"HTTP {http_status(e)}")
            if after:
                return _create_result(a, "ambiguous-outcome", after[0]["id"], nm,
                                      "The create's response was lost. A label with this name now exists, but this call "
                                      "cannot tell whether it created it (a matching name never proves ownership). "
                                      "The create was not retried.")
            return _create_result(a, "unknown-outcome", None, nm,
                                  "The create's response was lost and no label with this name is visible now. "
                                  "The create was not retried; check list_labels before trying again.")
        return _create_result(a, "created", created.get("id"), nm, "Created.")


def _create_result(a, st, label_id, name, note):
    lid = output.label_id(label_id) if label_id else None
    head = output.trusted(a["alias"], "create_label " + output.kv(state=output.code(st), label=lid))
    return head + "\n" + output.fence(f"name: {output.clean(name)}\n{note}"), {"state": st, "label_id": lid}


# --- update_label (5.6) --------------------------------------------------------------------------
@_journal
def update_label(creds, a, label, new_name=None, label_list_visibility=None, message_list_visibility=None, color=None):
    req = _settings_args(label_list_visibility, message_list_visibility, color)
    if new_name is not None:
        req["name"] = clean_name(new_name)
    if not req:
        raise ToolError("invalid-argument", "Nothing to change: pass new_name and/or a setting.")
    acct = _account_id(a)
    with journal.AdminSession() as s:
        labels = gmail.list_labels_full(creds)
        target = resolve(labels, label)
        cur = gmail.get_label(creds, target["id"])             # authoritative read under the lock
        if cur.get("type") != "user":
            raise ToolError("system-label", "System labels cannot be changed.")
        lid = _lid(cur.get("id"))
        _clear_pending(s, creds, acct, lid)
        if "name" in req and req["name"] != cur.get("name"):
            prefix = (cur.get("name") or "") + "/"
            if any((l.get("name") or "").startswith(prefix) for l in labels):
                raise ToolError("unsupported-cascade", "This label has nested labels; renaming it is refused until "
                                                       "Gmail's cascade behavior is established (5.6).")
            folded = [l for l in labels if l.get("id") != lid and (l.get("name") or "").casefold() == req["name"].casefold()]
            if folded:
                raise ToolError("name-conflict", "Another label already uses that name (or differs only by case).")
        before = state(cur)
        changes = {k: v for k, v in req.items() if before.get(k) != v}
        if not changes:
            head = output.trusted(a["alias"], "update_label " + output.kv(state=output.code("no-change"), label=lid))
            return head, {"label_id": lid, "state": "no-change"}
        expected_after = {**before, **changes}
        op = journal.new_op_id()
        s.append("PREPARED", op, kind="update", account_id=acct, alias=a["alias"], label_id=lid,
                 before=before, changes=changes, expected_after=expected_after)
        _checkpoint("update-after-prepared")
        try:
            gmail.patch_label(creds, lid, changes)
        except Exception as e:
            _checkpoint("update-after-remote-error")
            return _mutation_failed(s, creds, a, op, "update_label", lid, e, before, expected_after)
        _checkpoint("update-after-remote")
        try:
            observed = state(gmail.get_label(creds, lid))
        except Exception:
            observed = None
        try:
            s.append("APPLIED", op, observed=observed)
        except journal.JournalError:
            raise ToolError("outcome-not-recorded", "Gmail accepted the change, but its outcome could not be recorded; "
                                                    "the durable intent stays unresolved.",
                            fields={"op": output.op_id(op), "label": lid}) from None
        _checkpoint("update-after-applied")
        head = output.trusted(a["alias"], "update_label " + output.kv(state=output.code("applied"), op=output.op_id(op), label=lid))
        body = (f"before: {output.clean(_show(before))}\nafter (read back): {output.clean(_show(observed or expected_after))}\n"
                "Undo with undo_label_change and this op id (three-way rule: restores only fields still at these after-values).")
        return head + "\n" + output.fence(body), {"op": op, "label_id": lid, "fields": sorted(changes)}


def _show(st: dict | None) -> str:
    if not st:
        return "(unavailable)"
    return ", ".join(f"{k}={'(absent)' if v == ABSENT else v}" for k, v in st.items())


def _mutation_failed(s, creds, a, op, tool, lid, e, before, expected_after):
    """Outcome of a failed patch/delete: definitive errors are confirmed by a read-back;
    ambiguous ones are recorded as UNKNOWN_OUTCOME and never assumed 'not applied'."""
    if definitive(e):
        try:
            present, cur = _get_or_none(creds, lid)
        except Exception:
            present, cur = None, None
        if tool == "delete_label":
            if present is False:
                s.append("APPLIED", op, observed={"absent": True}, note="delete error but the label is absent")
                st = "applied"
            elif present:
                s.append("NOT_APPLIED", op, observed=state(cur), reason=f"rejected-{http_status(e)}")
                st = "not-applied"
            else:
                s.append("UNKNOWN_OUTCOME", op, error=f"http-{http_status(e)}")
                st = "unknown-outcome"
        else:
            obs = state(cur) if cur else None
            if obs == before:
                s.append("NOT_APPLIED", op, observed=obs, reason=f"rejected-{http_status(e)}")
                st = "not-applied"
            elif obs == expected_after:
                s.append("APPLIED", op, observed=obs)
                st = "applied"
            else:
                s.append("UNKNOWN_OUTCOME", op, observed=obs, error=f"http-{http_status(e)}")
                st = "unknown-outcome"
    else:
        s.append("UNKNOWN_OUTCOME", op, error="ambiguous")
        st = "unknown-outcome"
    head = output.trusted(a["alias"], f"{tool} " + output.kv(state=output.code(st), op=output.op_id(op), label=lid))
    note = {"applied": "Applied (confirmed by read-back).",
            "not-applied": "Gmail rejected the request; the read-back shows nothing changed.",
            "unknown-outcome": "The outcome is unknown (timeout or server error). It is recorded for reconciliation and "
                               "was not retried; undo_label_change or the next change to this label reconciles it."}[st]
    return head + "\n" + output.fence(note), {"op": op, "label_id": lid, "state": st}


# --- delete_label (5.7) --------------------------------------------------------------------------
@_journal
def delete_label(creds, a, label, confirm_name, confirm_filter_references=None, max_messages: int = 10000):
    if not isinstance(max_messages, int) or max_messages <= 0:
        raise ToolError("config-invalid", "label_delete_max_messages is invalid; every deletion is refused.")
    acct = _account_id(a)
    with journal.AdminSession() as s:
        labels = gmail.list_labels_full(creds)
        target = resolve(labels, label)
        cur = gmail.get_label(creds, target["id"])             # authoritative read under the lock
        if cur.get("type") != "user":
            raise ToolError("system-label", "System labels cannot be deleted.")
        lid = _lid(cur.get("id"))
        prefix = (cur.get("name") or "") + "/"
        if any((l.get("name") or "").startswith(prefix) for l in labels):
            raise ToolError("unsupported-cascade", "This label has nested labels; deleting it is refused until Gmail's "
                                                   "cascade behavior is established (their settings and memberships "
                                                   "would not be in the recovery record).")
        if not isinstance(confirm_name, str) or confirm_name != cur.get("name"):
            raise ToolError("confirm-name-mismatch", "confirm_name must equal the label's current name exactly; nothing was deleted.",
                            detail=f"current name: {output.clean(cur.get('name'))}")
        _clear_pending(s, creds, acct, lid)
        try:
            filters = gmail.list_filters(creds)
            refs = 0
            for f in filters:
                act = f.get("action") or {}
                if lid in (act.get("addLabelIds") or []) or lid in (act.get("removeLabelIds") or []):
                    refs += 1
        except Exception:
            raise ToolError("filter-check-failed", "Could not list Gmail filters, so the reference count is unknown "
                                                   "(never treated as zero); nothing was deleted.") from None
        cfr = confirm_filter_references
        if refs > 0 or cfr is not None:
            if isinstance(cfr, bool) or not isinstance(cfr, int) or cfr != refs:
                raise ToolError("filter-references-unconfirmed",
                                f"{refs} Gmail filter(s) reference this label. Pass confirm_filter_references={refs} "
                                "to delete anyway; references to the old id are not repaired.")
        op = None
        for attempt in range(CHURN_RETRIES + 1):
            try:
                members = gmail.label_member_ids(creds, lid, max_messages)
            except Exception:
                raise ToolError("snapshot-failed", "Could not enumerate the label's messages; nothing was deleted.") from None
            if members is None:
                raise ToolError("snapshot-too-large", f"The label carries more than {max_messages} messages; nothing was deleted.")
            settings = state(cur)
            op = journal.new_op_id()
            s.append("PREPARED", op, kind="delete", account_id=acct, alias=a["alias"], label_id=lid,
                     settings=settings, members=sorted(members), filter_refs=refs, max_messages=max_messages)
            _checkpoint("delete-after-prepared")
            try:
                again = gmail.get_label(creds, lid)
                members2 = gmail.label_member_ids(creds, lid, max_messages)
            except Exception:
                s.append("NOT_APPLIED", op, reason="recheck-failed")
                raise ToolError("snapshot-failed", "The membership recheck failed; nothing was deleted.",
                                fields={"op": output.op_id(op)}) from None
            if again.get("type") != "user" or state(again) != settings:
                s.append("NOT_APPLIED", op, reason="label-changed-during-setup", observed=state(again))
                raise ToolError("label-changed", "The label changed while the deletion was being prepared; nothing was deleted.",
                                fields={"op": output.op_id(op)})
            if members2 is None or set(members2) != set(members):
                s.append("NOT_APPLIED", op, reason="membership-churn")
                if attempt < CHURN_RETRIES:
                    cur = again
                    continue
                raise ToolError("membership-churn", "Membership kept changing during the snapshot; nothing was deleted.",
                                fields={"op": output.op_id(op)})
            break
        _checkpoint("delete-before-remote")
        try:
            gmail.delete_label(creds, lid)
        except Exception as e:
            _checkpoint("delete-after-remote-error")
            return _mutation_failed(s, creds, a, op, "delete_label", lid, e, None, None)
        _checkpoint("delete-after-remote")
        try:
            s.append("APPLIED", op, observed={"absent": True})
        except journal.JournalError:
            raise ToolError("outcome-not-recorded", "The label was deleted, but the outcome could not be recorded; the "
                                                    "durable intent stays unresolved. Undo with this op id.",
                            fields={"op": output.op_id(op), "label": lid}) from None
        _checkpoint("delete-after-applied")
        n = len(members)
        head = output.trusted(a["alias"], "delete_label " + output.kv(state=output.code("applied"), op=output.op_id(op), label=lid,
                                                                      snapshot=n, filter_references=refs))
        statements = "\n".join(output.trusted(a["alias"], t) for t in STATEMENTS_DELETE)
        body = (f"deleted label: {output.clean(settings.get('name'))}\n"
                "Undo with undo_label_change and this op id. It does not claim that every action of a referencing filter stops.")
        return head + "\n" + statements + "\n" + output.fence(body), {"op": op, "label_id": lid, "snapshot": n,
                                                                       "filter_refs": refs}


# --- undo_label_change (5.8) ------------------------------------------------------------------------
@_journal
def undo_label_change(creds, a, operation_id):
    opid = output.op_id(operation_id)
    if opid is None:
        raise ToolError("invalid-id", "Invalid operation_id.")
    acct = _account_id(a)
    with journal.AdminSession() as s:
        op = s.op(opid)
        if op is None or op.prepared is None:
            raise ToolError("unknown-operation", "No such journaled operation on this host.")
        if op.prepared.get("account_id") != acct:
            raise ToolError("cross-account-refused", "That operation belongs to a different account; nothing was changed.")
        if op.prepared.get("host") != s.host:
            raise ToolError("other-host", "That operation was journaled on another host.")
        if op.unresolved:
            reconcile(s, creds, op)
        if op.outcome == "NOT_APPLIED":
            head = output.trusted(a["alias"], "undo_label_change " + output.kv(op=opid, state=output.code("nothing-to-undo")))
            return head, {"op": opid, "state": "nothing-to-undo"}
        if op.outcome != "APPLIED":
            raise ToolError("unresolved-operation", "The original change's outcome is still unknown; it cannot be undone yet.")
        if op.undo_terminal == "UNDONE":
            return _undone_result(a, opid, op, repeated=True)
        if op.kind == "update":
            return _undo_update(s, creds, a, op)
        return _undo_delete(s, creds, a, op)


def _undone_result(a, opid, op, repeated=False):
    opid = output.op_id(opid)
    last = [r for r in op.undo_progress if r.get("type") == "UNDONE"][-1]
    counts = last.get("counts") or {}
    head = output.trusted(a["alias"], "undo_label_change " + output.kv(
        op=opid, state=output.code("undone"), outcome=output.code(last.get("outcome", "restored")),
        **{k: int(v) for k, v in counts.items()}))
    note = "Already completed earlier; nothing was repeated." if repeated else "Completed."
    if op.kind == "delete":
        note += (" Membership was not individually verified. UNDONE means the recovery procedure finished at this "
                 "evidence level, not that the mailbox was transactionally restored.")
    return head + "\n" + output.fence(note), {"op": opid, "state": "undone", **counts}


def _undo_update(s, creds, a, op):
    p = op.prepared
    fields = sorted(p["changes"])
    before = p["before"]
    after = op.observed if isinstance(op.observed, dict) and all(f in op.observed for f in fields) else p["expected_after"]
    prior = {f: before[f] for f in fields}
    post = {f: after[f] for f in fields}
    lid = p["label_id"]
    if op.undo_prepared is None or op.undo_terminal == "CONFLICT":
        s.append("UNDO_PREPARED", op.op_id, fields=fields, expected_current=post, desired_prior=prior)
    _checkpoint("undo-update-after-prepared")
    present, cur = _get_or_none(creds, lid)
    if not present:
        s.append("CONFLICT", op.op_id, reason="label-absent")
        return _conflict(a, op, "The label no longer exists; nothing was changed.")
    cs = {f: state(cur)[f] for f in fields}
    if cs == prior:
        s.append("UNDONE", op.op_id, outcome="observed-restored", observed=cs)
        return _undone_result(a, op.op_id, s.op(op.op_id))
    if cs != post:
        s.append("CONFLICT", op.op_id, reason="third-state", observed=cs)
        return _conflict(a, op, "The label is in neither the recorded after state nor the prior state; the third "
                                "state was not overwritten.")
    body = {f: (None if prior[f] == ABSENT else prior[f]) for f in fields}
    try:
        gmail.patch_label(creds, lid, body)
    except Exception as e:
        s.append("UNKNOWN_OUTCOME", op.op_id, phase="undo", error="definitive" if definitive(e) else "ambiguous")
        raise ToolError("undo-unknown-outcome", "The undo request failed or its outcome is unknown; run undo again "
                                                "(the three-way rule re-checks the state first).") from None
    _checkpoint("undo-update-after-remote")
    try:
        back = state(gmail.get_label(creds, lid))
        back = {f: back[f] for f in fields}
    except Exception:
        back = None
    if back == prior:
        s.append("UNDONE", op.op_id, outcome="restored", observed=back)
        return _undone_result(a, op.op_id, s.op(op.op_id))
    s.append("CONFLICT", op.op_id, reason="read-back-differs", observed=back)
    return _conflict(a, op, "The read-back after the undo does not match the prior state.")


def _conflict(a, op, note):
    head = output.trusted(a["alias"], "undo_label_change " + output.kv(op=output.op_id(op.op_id), state=output.code("conflict")))
    return head + "\n" + output.fence(note), {"op": op.op_id, "state": "conflict"}


def _undo_delete(s, creds, a, op):
    p = op.prepared
    settings = p["settings"]
    members = list(p["members"])
    rid = None
    for r in op.undo_progress:
        if r.get("type") == "UNDO_PROGRESS" and r.get("replacement_id"):
            rid = r["replacement_id"]
    sticky = {"ambiguous-create", "ambiguous-replacement-create"}
    if rid is None and any(r.get("type") == "CONFLICT" and r.get("reason") in sticky for r in op.undo_progress):
        return _conflict(a, op, "An earlier recreate had an ambiguous outcome, so a second replacement is never "
                                "created. Reconcile manually: check whether a label with the old name exists.")
    if rid is None:
        pending = op.undo_prepared is not None and op.undo_terminal is None
        if pending:
            s.append("CONFLICT", op.op_id, reason="ambiguous-replacement-create")
            return _conflict(a, op, "An earlier recreate attempt has no recorded result, so whether it created a label "
                                    "is unknown. A label with the old name is never adopted; reconcile manually.")
        s.append("UNDO_PREPARED", op.op_id, settings=settings)
        _checkpoint("undo-delete-after-prepared")
        try:
            created = gmail.create_label(creds, _body(settings))
        except Exception as e:
            if isinstance(e, HttpError) and http_status(e) == 409:
                s.append("CONFLICT", op.op_id, reason="name-taken")
                return _conflict(a, op, "A label with the original name exists now; it is never adopted. Rename or "
                                        "remove it, then run undo again.")
            s.append("CONFLICT", op.op_id, reason="create-rejected" if definitive(e) else "ambiguous-create")
            return _conflict(a, op, "Recreating the label failed or its outcome is unknown; no second replacement is "
                                    "ever created automatically.")
        _checkpoint("undo-delete-after-create")
        rid = output.label_id(created.get("id"))
        if rid is None:
            s.append("CONFLICT", op.op_id, reason="unexpected-replacement-id")
            return _conflict(a, op, "Gmail returned an unexpected label id.")
        s.append("UNDO_PROGRESS", op.op_id, replacement_id=rid)   # durable BEFORE any membership change
        _checkpoint("undo-delete-after-replacement-recorded")
    else:
        present, cur = _get_or_none(creds, rid)
        if not present:
            s.append("CONFLICT", op.op_id, reason="replacement-missing")
            return _conflict(a, op, "The recorded replacement label no longer exists; another label is never adopted.")
        if cur.get("type") != "user" or state(cur) != settings:
            s.append("CONFLICT", op.op_id, reason="replacement-changed", observed=state(cur))
            return _conflict(a, op, "The recorded replacement label no longer has the recorded name and settings; "
                                    "it is not used, and no second replacement is created.")

    chunks = [members[i:i + UNDO_CHUNK] for i in range(0, len(members), UNDO_CHUNK)]
    status: dict[int, dict] = {}
    for r in op.undo_progress:
        if r.get("type") == "UNDO_PROGRESS" and isinstance(r.get("chunk"), int):
            status[r["chunk"]] = r
    for idx, chunk in enumerate(chunks):
        prev = status.get(idx)
        if prev and prev.get("status") == "accepted":
            continue
        todo = chunk if not prev or prev.get("status") == "ambiguous" else list(prev.get("unresolved") or [])
        carried = {k: list(prev.get(k) or []) for k in ("accepted", "confirmed_missing", "conflicting")} if prev and prev.get("status") == "classified" else {"accepted": [], "confirmed_missing": [], "conflicting": []}
        if not todo:
            continue
        try:
            gmail.batch_modify(creds, todo, add=[rid])
            if prev and prev.get("status") == "classified":
                rec = {"chunk": idx, "status": "classified", "accepted": carried["accepted"] + todo,
                       "confirmed_missing": carried["confirmed_missing"], "conflicting": carried["conflicting"], "unresolved": []}
            else:
                rec = {"chunk": idx, "status": "accepted", "count": len(todo)}
        except Exception as e:
            if not definitive(e):
                rec = {"chunk": idx, "status": "ambiguous"} if not prev or prev.get("status") != "classified" else {
                    "chunk": idx, "status": "classified", **carried, "unresolved": todo}
            else:
                acc, miss, unres, conf = list(carried["accepted"]), list(carried["confirmed_missing"]), [], list(carried["conflicting"])
                for mid in todo:                       # independent classification of each id
                    try:
                        exists = gmail.message_exists(creds, mid)
                    except Exception:
                        unres.append(mid)
                        continue
                    if not exists:
                        miss.append(mid)
                        continue
                    try:
                        gmail.modify_labels(creds, mid, add=[rid])
                        acc.append(mid)
                    except Exception as e2:
                        s2 = http_status(e2)
                        (conf if (definitive(e2) and s2 not in (401, 403, 429)) else unres).append(mid)
                rec = {"chunk": idx, "status": "classified", "accepted": acc, "confirmed_missing": miss,
                       "unresolved": unres, "conflicting": conf}
        s.append("UNDO_PROGRESS", op.op_id, **rec)
        status[idx] = s.op(op.op_id).undo_progress[-1]
        _checkpoint("undo-delete-after-chunk")

    counts = {"accepted": 0, "confirmed-missing": 0, "unresolved": 0, "conflicting": 0, "restored-and-verified": 0}
    for idx, chunk in enumerate(chunks):
        r = status.get(idx)
        if r is None or r.get("status") == "ambiguous":
            counts["unresolved"] += len(chunk)
        elif r.get("status") == "accepted":
            counts["accepted"] += len(chunk)
        else:
            counts["accepted"] += len(r.get("accepted") or [])
            counts["confirmed-missing"] += len(r.get("confirmed_missing") or [])
            counts["unresolved"] += len(r.get("unresolved") or [])
            counts["conflicting"] += len(r.get("conflicting") or [])
    if counts["unresolved"] == 0:
        s.append("UNDONE", op.op_id, outcome="restored", replacement_id=rid,
                 counts={k.replace("-", "_"): v for k, v in counts.items()})
        res = _undone_result(a, op.op_id, s.op(op.op_id))
        return res[0], {**res[1], "replacement": rid}
    head = output.trusted(a["alias"], "undo_label_change " + output.kv(
        op=output.op_id(op.op_id), state=output.code("partial"), replacement=output.label_id(rid),
        **{k.replace("-", "_"): v for k, v in counts.items()}))
    note = ("Some memberships are unresolved (permission, quota, or transient errors, or an ambiguous batch); run undo "
            "again to retry only those. Membership was not individually verified.")
    return head + "\n" + output.fence(note), {"op": op.op_id, "state": "partial", **counts}


# --- modify_labels targets (5.9) -------------------------------------------------------------------
def modify_targets(creds, a, message_id, message_ids, thread_id, add_labels, remove_labels, lock_timeout=60.0):
    import locks

    given = [x for x in (message_id, message_ids, thread_id) if x not in (None, "", [])]
    if len(given) != 1:
        raise ToolError("invalid-argument", "Pass exactly one target: message_id, message_ids, or thread_id.")
    try:
        lock = locks.admin_lock(lock_timeout)
        lock.__enter__()
    except locks.LockTimeout:
        raise ToolError("labels-busy", "A label deletion snapshot is in progress on this host; try again shortly.") from None
    try:
        add_ids, remove_ids = gmail.resolve_labels(creds, add_labels or [], remove_labels or [])  # one list; TRASH/SPAM refused
        if set(add_ids) & set(remove_ids):
            raise ToolError("invalid-argument", "The same label cannot be both added and removed.")
        if not add_ids and not remove_ids:
            raise ToolError("invalid-argument", "Nothing to change: pass add_labels and/or remove_labels.")
        if message_id not in (None, ""):
            mid = output.require_message_id(message_id)
            gmail.modify_labels(creds, mid, add=add_ids, remove=remove_ids)
            return ("single", mid, 1, add_ids, remove_ids)
        if message_ids not in (None, []):
            if not isinstance(message_ids, list):
                raise ToolError("invalid-argument", "message_ids must be a list.")
            ids = [output.require_message_id(x, "message_ids entry") for x in message_ids]
            if len(set(ids)) != len(ids):
                raise ToolError("invalid-argument", "message_ids must be distinct.")
            if not 2 <= len(ids) <= BATCH_MAX:
                raise ToolError("invalid-argument", f"message_ids takes 2 to {BATCH_MAX} distinct ids (use message_id for one).")
            gmail.batch_modify(creds, ids, add=add_ids, remove=remove_ids)
            return ("batch", None, len(ids), add_ids, remove_ids)
        tid = output.require_message_id(thread_id, "thread_id")
        resp = gmail.modify_thread(creds, tid, add=add_ids, remove=remove_ids)
        return ("thread", tid, len((resp or {}).get("messages") or []), add_ids, remove_ids)
    finally:
        lock.__exit__(None, None, None)


# --- list_label_operations (read-only recovery aid) -------------------------------------------------
_OUTCOME_CODES = {"APPLIED": "applied", "NOT_APPLIED": "not-applied", "UNKNOWN_OUTCOME": "unknown-outcome", None: "pending"}


@_journal
def list_operations(creds, a, limit=20):
    """The most recent journaled label operations for this verified account on this host,
    newest first, so an op id is never lost (e.g. when a session ended mid-operation)."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ToolError("invalid-argument", "limit must be an integer from 1 to 100.")
    acct = _account_id(a)
    with journal.AdminSession() as s:
        ops = [o for o in s.ops.values() if o.prepared and o.prepared.get("account_id") == acct
               and o.prepared.get("host") == s.host]
        ops.sort(key=lambda o: o.prepared["seq"], reverse=True)
        lines, names_ = [], []
        for o in ops[:limit]:
            p = o.prepared
            undo = (o.undo_terminal or ("in-progress" if o.undo_prepared else "none")).lower()
            lines.append(output.trusted(a["alias"], output.kv(
                op=output.op_id(o.op_id), kind=output.code(p.get("kind", "unknown")),
                label=output.label_id(p.get("label_id")), outcome=output.code(_OUTCOME_CODES.get(o.outcome, "pending")),
                undo=output.code(undo), at=int(p.get("ts") or 0))))
            nm = (p.get("before") or p.get("settings") or {}).get("name")
            names_.append(f"{o.op_id}: {output.clean(nm) if isinstance(nm, str) else '(name unavailable)'}")
        head = output.trusted(a["alias"], "list_label_operations " + output.kv(count=len(lines), total=len(ops)))
        body = ("\n" + "\n".join(lines) + "\n" + output.fence("label names at the time of each operation:\n"
                                                              + "\n".join(names_))) if lines else ""
        return head + body, {"count": len(lines)}
