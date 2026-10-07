"""save_attachments and export_email (PLAN-v4 5.1, 5.2) on top of the shared enumerator
(mime), the name rules (names), the write controls (exportfs), the export identity
protocol (exports), the view builder (htmlview), and the renderer.

Every selected item ends in exactly one state: saved, already-present, skipped, refused,
or failed. Partial success is reported, never hidden. Results put only counts, fixed codes,
the canonical alias, and the validated message id in the trusted line; names, paths, MIME
fields, and reasons' details go inside the fence.
"""
from __future__ import annotations

import hashlib
import secrets

import auditlog
import exportfs
import exports
import gmail
import htmlview
import locks
import mime
import names
import output
import renderer
from googleapiclient.errors import HttpError

from output import ToolError

def _status(e) -> int | None:
    code = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", None)
    try:
        return int(code) if code is not None else None
    except (TypeError, ValueError):
        return None


FORMATS = ("pdf", "eml", "html")
DEFAULT_FORMATS = ("pdf", "eml")


def _subfolder(sub) -> list[str]:
    try:
        return names.parse_subfolder(sub)
    except ValueError as e:
        raise ToolError("invalid-subfolder", "Invalid subfolder (relative names only, no '.' or '..').",
                        detail=f"reason: {e}; subfolder as received: {str(sub)[:200]}") from None


def _root(roots: dict, destination) -> exportfs.Root:
    if not isinstance(destination, str) or destination not in roots:
        raise ToolError("unknown-destination", "Unknown export destination (use a configured root name).",
                        detail=f"configured: {', '.join(sorted(roots)) or 'none'}; destination as received: {str(destination)[:100]}")
    root = roots[destination]
    problem = root.check_live()
    if problem:
        raise ToolError(problem, "Export destination unavailable; other tools are unaffected.")
    return root


def _canonical_id(requested: str, returned) -> str:
    """Folder names and manifests use the id Gmail returns (lower-case hex), never a
    differently-cased spelling of it; any other mismatch is refused."""
    rid = output.message_id(returned)
    if rid is None or rid.lower() != requested.lower():
        raise ToolError("id-mismatch", "Gmail returned a different message id; nothing was written.")
    return rid


def _target(root, a: dict, sub: list[str], mid: str) -> exports.Target:
    email_addr = a["email"]  # verified against the token's real identity by server._creds
    return exports.Target(root=root, alias=a["alias"], identity=exports.identity_hash(email_addr),
                          account_ns=exports.account_namespace(a["alias"], email_addr),
                          subfolder=sub, message_id=mid)


class _Session:
    """ExportSession with its fixed failure codes mapped to ToolError (trusted code, no echo)."""

    def __init__(self, target, meta):
        self.s = exports.ExportSession(target, meta)

    def __enter__(self):
        try:
            return self.s.__enter__()
        except exports.ManifestError as e:
            raise ToolError(e.code, "Export folder unavailable or its manifest is not usable; nothing was written.") from None
        except exportfs.UnsafePath as e:
            raise ToolError("unsafe-path", "Export path refused (symlink, non-directory, or foreign owner).",
                            detail=f"reason: {e.code}") from None
        except locks.LockTimeout:
            raise ToolError("export-busy", "Another export of this message is in progress; try again.") from None

    def __exit__(self, *exc):
        return self.s.__exit__(*exc)


def _counts(results) -> dict:
    c = {s: 0 for s in exports.STATES}
    for r in results:
        c[r.state] += 1
    return c


def _trusted_counts(c: dict) -> str:
    return output.kv(saved=c["saved"], **{"already-present": c["already-present"]}, skipped=c["skipped"],
                     refused=c["refused"], failed=c["failed"])


def _session_notes(sess) -> tuple[str, list[str]]:
    trusted = ""
    lines = []
    if sess is None:
        return trusted, lines
    # retained size of this message's exports (reported; never automatic retention)
    trusted += " " + output.kv(retained_bytes=sess.retained_bytes())
    if sess.recovered or sess.conflicts or sess.orphans:
        trusted += " " + output.kv(recovered=sess.recovered, conflicts=sess.conflicts, orphans=len(sess.orphans))
    for ns, n in sess.orphans:
        lines.append(f"orphan (reported for reconciliation, not adopted): {ns}/{n}")
    if sess.conflicts:
        lines.append("conflict: a recorded name now holds a file that does not match its durable intent; it was left untouched.")
    return trusted, lines


# --- save_attachments ------------------------------------------------------------------------
def _select(parts: list[mime.Part], attachments, include_inline: bool):
    """[(part or None, index, state or None, code)] — state None means 'selected'."""
    if attachments is None or attachments == "all":
        return [(p, p.index, None if (include_inline or not p.inline) else "skipped",
                 "ok" if (include_inline or not p.inline) else "inline-excluded") for p in parts]
    if not isinstance(attachments, list) or not attachments:
        raise ToolError("invalid-argument", "`attachments` must be \"all\" or a non-empty list of indexes.")
    by_index = {p.index: p for p in parts}
    out, seen = [], set()
    for raw in attachments:
        if isinstance(raw, bool):
            raw = None
        if isinstance(raw, str) and raw.strip().isdigit():
            raw = int(raw.strip())
        if not isinstance(raw, int):
            raise ToolError("invalid-argument", "`attachments` indexes must be integers as listed by read_email.",
                            detail=f"entry as received: {str(raw)[:50]}")
        if raw in seen:
            continue
        seen.add(raw)
        p = by_index.get(raw)
        if p is None:
            out.append((None, raw, "refused", "no-such-index"))
        elif p.inline and not include_inline:
            out.append((p, raw, "refused", "inline-not-included"))
        else:
            out.append((p, raw, None, "ok"))
    return out


def _fetch(creds, mid: str, p: mime.Part) -> bytes:
    if p.parsed_container:
        raise exports.ProduceError("refused", "unsupported-original-part")
    if p.size is not None and p.size > exports.PER_FILE_CAP:
        raise exports.ProduceError("refused", "too-large")
    sizes = [p.size] if p.size is not None else []
    if p.attachment_id:
        resp = gmail.get_attachment(creds, mid, p.attachment_id)
        if isinstance(resp.get("size"), int):
            sizes.append(resp["size"])
        encoded = resp.get("data") or ""
    elif p.data is not None:
        encoded = p.data
    else:
        encoded = ""
    try:
        data = mime.b64url_decode(encoded, exports.PER_FILE_CAP)
    except mime.DataTooLarge:
        raise exports.ProduceError("refused", "too-large") from None
    except mime.MalformedData:
        raise exports.ProduceError("failed", "malformed-data") from None
    if any(s != len(data) for s in sizes):
        raise exports.ProduceError("refused", "size-mismatch")
    return data


def save_attachments(creds, a: dict, roots: dict, message_id, attachments="all", include_inline=False,
                     destination="default", subfolder=None):
    mid = output.require_message_id(message_id)
    sub = _subfolder(subfolder)
    root = _root(roots, destination)
    full = gmail.get_message_full(creds, mid)
    mid = _canonical_id(mid, full.get("id"))
    payload = full.get("payload") or {}
    try:
        parts, why = mime.enumerate_message(
            payload, lambda att: gmail.get_attachment(creds, mid, att).get("data") or "",
            cache_key=(a["email"].lower(), mid), size_estimate=full.get("sizeEstimate"))
    except mime.MimeLimitError as e:
        raise ToolError(e.code, "MIME structure exceeds the export limits (500 parts, depth 20).") from None
    except Exception:
        raise ToolError("mime-unreadable", "The message's MIME structure could not be read; nothing was saved.") from None
    selection = _select(parts, attachments, bool(include_inline))

    items = []  # (index, part, result-or-None, request-or-None)
    files = total = 0
    for p, idx, state, code in selection:
        if state is not None:
            items.append((idx, p, exports.ItemResult(f"index-{idx}", "attachment", state, code), None))
            continue
        if files >= exports.PER_CALL_FILES:
            items.append((idx, p, exports.ItemResult(f"index-{idx}", "attachment", "skipped", "per-call-file-limit"), None))
            continue
        try:
            data = _fetch(creds, mid, p)
        except exports.ProduceError as pe:
            items.append((idx, p, exports.ItemResult(f"index-{idx}", "attachment", pe.state, pe.code), None))
            continue
        except HttpError as e:
            st = _status(e)
            items.append((idx, p, exports.ItemResult(f"index-{idx}", "attachment", "failed",
                                                     f"gmail-{st}" if st else "gmail-error"), None))
            continue
        except Exception:
            items.append((idx, p, exports.ItemResult(f"index-{idx}", "attachment", "failed", "fetch-failed"), None))
            continue
        if total + len(data) > exports.PER_CALL_BYTES:
            items.append((idx, p, exports.ItemResult(f"index-{idx}", "attachment", "skipped", "per-call-byte-limit"), None))
            continue
        files += 1
        total += len(data)
        sha = hashlib.sha256(data).hexdigest()
        kind = names.sniff(data[:16])
        plan = names.plan_name(p.filename or None, p.name, kind)
        risks = names.risk_reasons(p.filename or p.name, plan.candidate(1), p.mime_type, data[:1024])
        key = exports.artifact_key("attachment", p.part_id, list(p.path), sha)
        meta = {"index": idx, "part_id": p.part_id, "path": p.path_str, "original_name": p.filename,
                "generated_name": p.generated_name, "declared_mime": p.mime_type, "detected_type": kind or "unknown",
                "risk": risks, "extension_corrected": plan.extension_corrected, "inline": p.inline}

        def produce(fd, _data=data):
            return exportfs.write_temp(fd, [_data], exports.PER_FILE_CAP, expected_size=len(_data))

        items.append((idx, p, None, exports.Request(key, "attachment", "attachments", plan, produce, meta)))

    reqs = [r for _, _, res, r in items if r is not None]
    hdrs = {h.get("name", "").lower(): h.get("value", "") for h in payload.get("headers") or []}
    sess = None
    pub: dict[str, exports.ItemResult] = {}
    if reqs:
        with _Session(_target(root, a, sub, mid), {
                "thread_id": full.get("threadId"), "subject": hdrs.get("subject"),
                "from": hdrs.get("from"), "date": hdrs.get("date")}) as sess:
            for r in sess.publish(reqs):
                pub[r.key] = r
    results = []
    lines = []
    for idx, p, res, req in items:
        r = res if res is not None else pub[req.key]
        results.append(r)
        lines.append(_attachment_line(idx, p, r))
    c = _counts(results)
    note_trusted, note_lines = _session_notes(sess)
    if parts and why:
        note_lines.append(mime.inline_note(why))
    head = output.trusted(a["alias"], f"save_attachments message={mid} " + _trusted_counts(c) + note_trusted)
    body = "\n".join(lines + note_lines) or "No eligible attachments in this message."
    audit = {"op": secrets.token_hex(16), "message_id": mid, **{k.replace("-", "_"): v for k, v in c.items()},
             "bytes": total, "sha256": [r.sha256 for r in results if r.sha256],
             "ext": [auditlog.ext_for_audit(r.name) for r in results if r.name],
             "risky": sum(1 for r in results if (r.meta or {}).get("risk"))}
    return head + "\n" + output.fence(body), audit


def _attachment_line(idx, p, r: exports.ItemResult) -> str:
    c = output.clean
    out = [f"[{idx}] state={r.state}" + ("" if r.code == "ok" else f" reason={r.code}")]
    if p is not None:
        out.append(f"    original name: {c(p.filename) or '(none)'}{' [generated: ' + c(p.name) + ']' if p.generated_name else ''}"
                   f" | declared type: {c(p.mime_type)}")
    if r.path:
        meta = r.meta or {}
        ok, why = names.qbo_check(r.name, r.size or 0, r.head)
        flags = []
        if meta.get("risk"):
            flags.append("risky-type(" + ",".join(meta["risk"]) + ")")
        if meta.get("extension_corrected"):
            flags.append("extension-corrected")
        if r.state == "already-present":
            flags.append("already-present")
        out.append(f"    path: {r.path}")
        out.append(f"    saved name: {c(r.name)} | size: {r.size} bytes | sha256: {r.sha256}")
        out.append(f"    detected type: {meta.get('detected_type', 'unknown')} | qbo_compatible: {str(ok).lower()} ({why})")
        if flags:
            out.append("    flags: " + ", ".join(flags))
    return "\n".join(out)


# --- export_email ------------------------------------------------------------------------------
def _formats(formats) -> list[str]:
    if formats is None:
        return list(DEFAULT_FORMATS)
    if isinstance(formats, str):
        formats = [formats]
    if not isinstance(formats, list) or not formats:
        raise ToolError("invalid-argument", "`formats` must be a non-empty list drawn from pdf, eml, html.")
    out = []
    for f in formats:
        if not isinstance(f, str) or f.lower() not in FORMATS:
            raise ToolError("invalid-argument", "`formats` must be drawn from pdf, eml, html.",
                            detail=f"format as received: {str(f)[:50]}")
        if f.lower() not in out:
            out.append(f.lower())
    return out


def _view_plan(subject: str, ext: str, kind: str | None) -> names.NamePlan:
    stem = (subject or "").replace("/", "_").replace("\\", "_")
    return names.plan_name(f"{stem}{ext}" if stem.strip() else None, f"message{ext}", kind)


def export_email(creds, a: dict, roots: dict, pdf_settings, message_id, formats=None, destination="default",
                 subfolder=None):
    mid = output.require_message_id(message_id)
    fmts = _formats(formats)
    sub = _subfolder(subfolder)
    root = _root(roots, destination)
    msg = gmail.get_message_raw(creds, mid)
    mid = _canonical_id(mid, msg.get("id"))
    try:
        raw = mime.b64url_decode(msg.get("raw") or "", exports.PER_FILE_CAP)
    except mime.DataTooLarge:
        raise ToolError("too-large", "Message exceeds the 50 MiB export limit; nothing was written.") from None
    except mime.MalformedData:
        raise ToolError("malformed-data", "Gmail returned malformed RAW data; nothing was written.") from None
    raw_sha = hashlib.sha256(raw).hexdigest()

    ready = renderer.readiness(pdf_settings) if "pdf" in fmts else None
    view, view_error = None, None
    # The sanitized view is built only when it will be used: html requested, or PDF ready.
    if "html" in fmts or ("pdf" in fmts and ready is not None and ready.ready):
        try:
            view = htmlview.build_view(raw)
        except htmlview.ViewError as e:
            view_error = e.code
        except Exception:          # never let a hostile body take the .eml down with it
            view_error = "view-failed"
    # without a view, the Subject (for names and the manifest) comes from the top-level headers
    # alone, parsed with the view's guards: never a full parse of the message
    subject = view.headers.get("Subject", "") if view else htmlview.subject_of(raw)

    pre: dict[str, exports.ItemResult] = {}
    reqs: list[exports.Request] = []
    for f in fmts:
        if f == "eml":
            plan = _view_plan(subject, ".eml", None)

            def produce_eml(fd):
                return exportfs.write_temp(fd, [raw], exports.PER_FILE_CAP, expected_size=len(raw))

            reqs.append(exports.Request(exports.artifact_key("eml", raw_sha), "eml", "views", plan, produce_eml,
                                        {"format": "eml", "raw_sha256": raw_sha}))
        elif f == "pdf" and not ready.ready:
            pre[f] = exports.ItemResult("fmt-pdf", "pdf", "skipped", "pdf-unavailable", meta={"why": ready.code})
        elif view is None:
            pre[f] = exports.ItemResult(f"fmt-{f}", f, "refused", view_error or "unsupported-mime")
        elif f == "html":
            plan = _view_plan(subject, ".html", None)

            def produce_html(fd):
                return exportfs.write_temp(fd, [view.page], exports.PER_FILE_CAP, expected_size=len(view.page))

            reqs.append(exports.Request(exports.artifact_key("html", view.inputs_key), "html", "views", plan,
                                        produce_html, {"format": "html", "view_key": view.inputs_key,
                                                       "warnings": view.warnings, "body": view.body_part}))
        elif f == "pdf":
            plan = _view_plan(subject, ".pdf", "pdf")
            pdf_meta = {"format": "pdf", "view_key": view.inputs_key, "chrome": ready.chrome_version,
                        "recipe": renderer.RENDER_RECIPE, "max_pages": pdf_settings.max_pages,
                        "warnings": view.warnings, "body": view.body_part}

            def produce_pdf(fd, _ready=ready, _meta=pdf_meta):
                try:
                    tf = renderer.render_to_temp(fd, view.page, pdf_settings, _ready)
                except renderer.RenderFailure as rf:
                    raise exports.ProduceError(rf.state, rf.code) from None
                _meta["scale"] = getattr(tf, "render_scale", None)   # recorded in the manifest
                return tf

            key = exports.artifact_key("pdf", view.inputs_key, renderer.RENDER_RECIPE, ready.chrome_version,
                                       pdf_settings.max_pages)
            reqs.append(exports.Request(key, "pdf", "views", plan, produce_pdf, pdf_meta))

    sess = None
    pub: dict[str, exports.ItemResult] = {}
    if reqs:
        meta = {"thread_id": msg.get("threadId"), "subject": subject, "raw_sha256": raw_sha,
                "from": view.headers.get("From") if view else None, "date": view.headers.get("Date") if view else None}
        with _Session(_target(root, a, sub, mid), meta) as sess:
            for r in sess.publish(reqs):
                pub[r.kind] = r
    results, lines = [], []
    for f in fmts:
        r = pre.get(f) or pub[f]
        results.append(r)
        lines.append(_format_line(f, r, ready))
    if view is not None and view.warnings:
        lines.append("view warnings: " + ", ".join(view.warnings))
    if view is not None and view.remote_images:
        lines.append(f"remote images not fetched (D10): {view.remote_images}")
    c = _counts(results)
    note_trusted, note_lines = _session_notes(sess)
    head = output.trusted(a["alias"], f"export_email message={mid} " + _trusted_counts(c) + note_trusted)
    audit = {"op": secrets.token_hex(16), "message_id": mid, "formats": fmts,
             **{k.replace("-", "_"): v for k, v in c.items()},
             "states": {f: r.state for f, r in zip(fmts, results)}, "raw_sha256": raw_sha,
             "sha256": [r.sha256 for r in results if r.sha256]}
    return head + "\n" + output.fence("\n".join(lines + note_lines)), audit


def _format_line(f: str, r: exports.ItemResult, ready) -> str:
    out = [f"{f}: state={r.state}" + ("" if r.code == "ok" else f" reason={r.code}")]
    if f == "pdf" and r.code == "pdf-unavailable" and ready is not None:
        out.append(f"    renderer not ready: {ready.code}" + (f" ({ready.detail})" if ready.detail else ""))
    if f == "pdf" and (r.meta or {}).get("chrome") and r.path:
        out.append(f"    rendered by: {r.meta['chrome']} | recipe {r.meta.get('recipe')} | max_pages "
                   f"{r.meta.get('max_pages')} | scale {r.meta.get('scale')}")
    if r.path:
        out.append(f"    path: {r.path}")
        out.append(f"    size: {r.size} bytes | sha256: {r.sha256}")
        if f == "pdf":
            ok, why = names.qbo_check(r.name, r.size or 0, r.head)
            out.append(f"    qbo_compatible: {str(ok).lower()} ({why})")
        else:
            ok, why = names.qbo_check(r.name, r.size or 0, r.head)
            out.append(f"    qbo_compatible: {str(ok).lower()} ({why})")
    return "\n".join(out)
