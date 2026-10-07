# Security model

This server exists so an AI assistant can triage, file and export email **without** a
third-party service in the middle and **without** the ability to do irreversible damage.
Every guarantee below names its enforcement layer, because that is the honest way to state
guarantees.

## Guarantees and how they're enforced

| Guarantee | Enforced by |
|---|---|
| No third party sees your mail | Architecture: the server runs on your machine and its only network calls go to Google's Gmail and OAuth endpoints (`*.googleapis.com`). There is no telemetry. The PDF renderer makes no network requests at all (below). |
| Cannot permanently delete mail | The OAuth scope (`gmail.modify` cannot hard-delete), AND no mail-deletion tool exists, AND adding `TRASH`/`SPAM` is refused on every path: single message, batch, and thread. Trash auto-purges after about 30 days, so adding it would be delayed deletion. |
| Label deletion is recoverable | `delete_label` removes a label only, never mail. It requires the exact current name, refuses unless the caller confirms the number of Gmail filters that reference the label, and journals the label's settings and every member id **before** deleting. `undo_label_change` recreates it (with a new id) and reapplies the recorded memberships. Labels with nested labels are refused. |
| Label changes are crash-safe | The journal is append-only, sequenced and fsynced. A change is recorded before it is sent, and its outcome after. An interrupted operation is reconciled, never guessed. An unknown outcome is never undone blindly. A corrupt or tampered journal refuses all label administration. |
| Cannot send (by default) | The server, twice: no send tool is registered unless BOTH `"enable_send": true` (config) AND `GMAIL_MCP_ALLOW_SEND=1` (environment) are set. Google has **no** scope that permits drafts but not send, so scope-level enforcement is impossible; that is exactly why the gate is two-factor. |
| Cannot touch the wrong account | An explicit `account` on every tool; aliases and addresses validated unique; the sign-in CLI refuses a token whose real identity doesn't match the configured address; the server re-verifies token identity at runtime before first use. Export folders, journal entries and pagination tokens bind to the verified address, never to an alias. |
| Writes only where you said | Exports go only under roots named in `export_roots`. Each root is resolved and pinned at startup, and must be an existing directory you own that isn't group- or world-writable. Names and subfolders are sanitized, and symlinks are refused at every level. Files are created no-clobber with `O_EXCL`, at `0600`, quarantined, and published by hard link only after a durable intent record. A root that is moved or replaced after startup disables that destination. |
| Rendering can't phone home or run code | The `.html` view is built by an allowlist sanitizer with a restrictive CSP. The PDF is rendered by headless Chrome over a private DevTools pipe, with: scripts disabled; every request intercepted and failed; a dead proxy; resolver rules; no extensions, sync, component updates or background networking; a mock keychain; and the profile, home, temp and crash folders inside a private render folder. The release gates verify each of these against a positive control on the machine's exact Chrome build. |
| A runaway render is stopped | An independent supervisor enforces the render deadline (at most 45 s) and the configured memory and scratch-disk budgets, and kills Chrome's whole process group. A page that would exceed the page limit or the page width is refused, never silently truncated. |
| PDF can't drift onto an unverified Chrome | PDF output is enabled only by a gate record bound to the Chrome binary, its version, the render recipe and the renderer's code, plus measured budgets in the config. Any change switches PDF off until the gates pass again. |
| Tokens unreadable at rest | Fernet (authenticated encryption), with the key in the macOS Keychain and an atomic `0600` file fallback. The runtime folder is `0700`, files are `0600`, and writes are atomic. Decryption tries every reachable key, so sessions where the Keychain is locked can't strand tokens written elsewhere. |
| Email can't easily hijack the assistant | Untrusted-content fencing: a trusted first line that holds only aliases, validated ids, fixed codes and counts; everything else inside a per-call random-nonce envelope, with marker forgery stripped and CR/LF stripped from header values. This is defense in depth, **not** a guarantee. The hard backstops are drafts-only, no mail deletion, and journaled label changes. |
| Tamper-evident usage | An append-only audit log with one JSON line per call, metadata only (tool, alias, ids, counts, export file extensions; never content, queries, subjects, file names or recipients), `0600` including rotated files. A failed audit write is reported in the tool result. |
| Dependencies can't drift | `requirements.lock` is hash-pinned; install with `--require-hashes`. Only official Anthropic and Google libraries plus mainstream PyPA-ecosystem crypto and keyring. |
| AI can't self-authorize | OAuth sign-in lives in `authenticate.py`, a CLI a human runs. The server can only read and refresh tokens that already exist. |

## Residual risks (accept these knowingly)

- **Same-user malware.** Anything running as your OS user can read the Keychain entry the
  same way the server does and decrypt tokens. This is true of every local credential
  store (`gh`, `gcloud`, the AWS CLI). Mitigations: OS user separation, disk encryption,
  and not running untrusted code.
- **Draft exfiltration needs your finger.** A prompt-injected assistant could create a
  draft addressed to an attacker containing sensitive content. Nothing leaves unless you
  press send in Gmail, so glance at the recipient and content before sending drafts you
  didn't ask for.
- **Exports are a second exit.** An injected session can save mail content into your
  export folders. If a root is synced or shared (a cloud-drive folder, a network share),
  that content leaves the machine without a send. Keep export roots local, and give each
  a narrow purpose.
- **Saved `.eml` files keep the original active HTML.** Opening one in Mail or Quick Look
  is outside the renderer's controls. Spotlight and Quick Look may parse files in indexed
  folders without a click; a root whose path ends in `.noindex` is not indexed.
- **Chrome's browser process runs unsandboxed as you.** The renderer contains it (no
  network, no scripts, private folders, a supervised process group), but a Chrome
  vulnerability reachable from static HTML and CSS would run with your user's rights.
  Keep Chrome updated; every update switches PDF off until the gates pass again.
- **Budgets are monitored, not hard caps.** Memory can grow between two samples before the
  supervisor kills the render, so set budgets with headroom on machines with little RAM.
- **Message parsing runs in the server process.** Parsing is bounded in time and size, but
  a crafted message can still cost seconds and gigabytes on the export path, and a long
  call blocks that session's server until it finishes.
- **Fencing is best-effort.** Treat returned email text as data. The architecture assumes
  fencing will sometimes fail, and limits what a hijacked session could do instead.
- **Label undo is best-effort for memberships.** A deletion's undo reapplies recorded
  member ids in chunks and reports how many were accepted, missing or unresolved; it does
  not read every membership back. Filters that referenced the old label id are not
  repaired.
- **Arming send is a local decision.** The two-factor gate stops accidents and config-only
  tampering; it cannot stop the machine's owner. Protect the machine.
- **Workspace trust is org-wide.** If a Workspace admin marks the OAuth client trusted,
  guard `oauth_client.json` accordingly.

## Reporting

Found something? Open an issue, or a private security advisory, on the repository.
