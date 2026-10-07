# multi-gmail-mcp

A self-hosted MCP server that gives Claude **read, triage, draft, export, and label
management** access to **several Gmail / Google Workspace accounts at once**, in one
connector.

Claude's official Gmail connector supports one Google account per Claude account. This
server takes as many as you configure. It runs on your machine over stdio, your mail
travels only between your machine and Google's API, and no third-party service sits in
the middle.

```
   you, on any device
         |
       Claude            (desktop app / Claude Code / any stdio MCP client)
         |  MCP · stdio · local-only
         v
   +--------------------------------------------------------+
   |  multi-gmail-mcp  (Python)                             |
   |  search · read · label · archive · draft               |
   |  save attachments · export .eml / .html / PDF          |
   |  create / rename / delete / undo labels (journaled)    |
   |  NO send by default · NO mail deletion, ever           |
   |  per-account encrypted tokens · metadata-only audit    |
   +--------------------------------------------------------+
         |  one OAuth token per account (Fernet-encrypted,
         |  key in the macOS Keychain)
         v
   account-1   account-2   account-3   ...
         \         |         /
          Gmail API (scope: gmail.modify, which cannot permanently delete)
```

## Tools

Every tool takes an explicit `account` (an alias from your config, or the full address).
There is no default account.

| Tool | What it does |
|---|---|
| `list_accounts` | Configured accounts and whether each is authorized (read-only) |
| `search_emails` | Gmail search syntax, `max_results` 1 to 50, paginated with `page_token` / `next_page_token` |
| `read_email` | One message, plus its attachment list with the indexes `save_attachments` accepts |
| `read_thread` | A full conversation |
| `list_labels` | Label names and ids |
| `modify_labels` | Add or remove labels on one message, a batch of 2 to 100 messages (`message_ids`), or a whole thread (`thread_id`). Archive = remove `INBOX`; mark read = remove `UNREAD` |
| `create_draft` | A draft (optionally a threaded reply) that you review and send yourself in Gmail |
| `save_attachments` | One message's attachments, byte-for-byte, into a folder you configured |
| `export_email` | One message as `.eml` (the exact raw bytes), a sanitized `.html` view, and/or a PDF of that view |
| `create_label` | A new user label (nested with `/`); an existing exact name is returned unchanged |
| `update_label` | Rename a user label or change its visibility or color; journaled, undoable |
| `delete_label` | Delete a user label, **never mail**; journaled, undoable |
| `undo_label_change` | Revert a journaled `update_label` or recreate a deleted label and reapply its recorded memberships |
| `list_label_operations` | Recent journaled label operations and their op ids (read-only) |

The five label-administration tools are registered only while `"label_admin": true` (the
default). A `send_email` tool exists but is **not registered** unless you arm it (below).

### What it deliberately can't do

- **Send mail, by default.** Arming send is two-factor: `"enable_send": true` in the config
  file AND `GMAIL_MCP_ALLOW_SEND=1` in the server's environment. Google has no OAuth scope
  that allows drafts without send, so drafts-only is enforced by the server, and a config
  edit alone (accidental or injected) can never enable sending.
- **Delete mail.** There is no mail-deletion tool, the `gmail.modify` scope cannot
  permanently delete, and adding `TRASH` or `SPAM` is refused on every path (single, batch,
  and thread). Trash auto-purges after about 30 days, so adding it would be deletion on a
  delay. Removing them (untrash, not-spam) is allowed.
- **Sign itself in.** Authorization is `authenticate.py`, a CLI a human runs.
- **Touch an account you didn't configure,** or write files anywhere except the export
  folders you named.

### Exports

- **`save_attachments`** saves attachments exactly as Gmail stores them: `"all"` or a list
  of indexes from `read_email`. Inline parts (such as images shown in the body) are saved
  only with `include_inline: true`.
- **`export_email`** writes any of three formats (default: `pdf` and `eml`), and each format
  reports its own result:
  - `eml`: the exact RAW message bytes Gmail returns;
  - `html`: a sanitized, policy-wrapped view. Scripts, remote content and active markup
    are removed, and embedded `cid:` images are inlined;
  - `pdf`: that same view, rendered offline by headless Chrome over a private DevTools
    pipe. Remote images are never fetched. PDF is off until you enable it (below).
- **Where files go.** `destination` names a root from `export_roots` in your config, never
  a path, and `subfolder` is an optional relative folder inside it. The layout is
  `<root>/<alias>-<12 hex of the account address's SHA-256>/<subfolder>/<message id>/`,
  with `attachments/`, `views/`, and a `.gmail-mcp/manifest.json`.
- **How they're written.** Files are never overwritten (a numbered name is used instead),
  are created `0600`, carry the macOS quarantine attribute, and are published only after
  a durable record, so a crash never leaves a half-written file under a final name.
- **Limits.** 50 MiB per file, and 50 files or 200 MiB per call. At least 1 GiB of disk is
  kept free. A message too long for the page limit is refused (`too-many-pages`), never
  truncated.
- **Roots** must already exist, be owned by you, and not be group- or world-writable. The
  server never creates them. `setup.sh` creates the configured ones for you.

### Label management

- **`update_label` and `delete_label` are journaled before they act,** in
  `~/.gmail-mcp-private/label-journal/`, and return an operation id for
  `undo_label_change`. A changed field is reverted only if it still holds the value the
  change set; a third state is reported as a conflict, never overwritten.
- **`delete_label`** needs `confirm_name` equal to the label's current name. It first
  counts the Gmail filters that reference the label and refuses unless
  `confirm_filter_references` equals that count. It then snapshots the label's settings
  and every member message id. A label with more members than
  `label_delete_max_messages` (default 10,000) is refused.
- **Undoing a deletion** recreates the label with a **new** id and reapplies the recorded
  memberships. Filters that pointed at the old id are not repaired.
- **Refused, for now:** renaming or deleting a label that has nested labels
  (`unsupported-cascade`), and case-only name collisions.
- **Not journaled:** `modify_labels` changes on a batch or a thread.

## Security model (the short version)

- **Official libraries only.** Anthropic's `mcp` SDK, Google's API and auth clients,
  `cryptography`, and `keyring`. No community MCP code to vet or be poisoned through.
- **Per-account encrypted tokens.** Fernet (authenticated encryption), with the key in the
  macOS Keychain and an atomic `0600` key-file fallback. Decryption tries every reachable
  key, so a locked-Keychain session can't strand your tokens.
- **Strict account isolation.** Every call names an account, and the server re-verifies
  the token's real signed-in address against your config before first use. Export
  folders and journal entries bind to that verified address, never to an alias.
- **Prompt-injection fencing.** Each result starts with a trusted line that holds only
  aliases, validated ids, fixed codes and counts. Everything from email, or echoed from
  arguments, is inside an UNTRUSTED envelope with a per-call random nonce. This is
  defense in depth, not a guarantee; drafts-only and no-delete are the backstop.
- **Contained rendering.** Chrome runs headless with scripts off, every request
  intercepted, a dead proxy, a restrictive CSP and resolver rules, in its own process
  group. Its home, temp and crash folders are inside a private render folder. An
  independent supervisor enforces the time, memory and scratch-disk budgets and kills the
  whole group.
- **Metadata-only audit log.** One JSON line per call (tool, alias, ids, counts) in
  `~/.gmail-mcp-private/audit.log` (`0600`, rotating). Never content, queries, subjects or
  recipients. If an audit write fails, the result says so.
- **Local only.** stdio transport; the server never opens a network port.
- **Pinned supply chain.** `requirements.lock` is hash-pinned (`pip --require-hashes`).

Full guarantees, enforcement layers and residual risks: [SECURITY.md](SECURITY.md).

## Requirements

- **macOS.** Reading, search and labels may work on Linux through `keyring`'s Secret
  Service backend or the key-file fallback, but that is untested. Exports need macOS,
  because every exported file must carry the macOS quarantine attribute. FileVault is
  strongly recommended.
- **Python 3.10 or newer** for the server. **Python 3.14.6** for the export view, which is
  the sanitized `.html`, the PDF, and inline-image detection:
  - The view relies on eleven CPython 3.14.6 internals, which are fingerprinted.
  - On any other version they report `stdlib-changed`: `html` and `pdf` exports are
    unavailable, and inline images are saved as ordinary attachments. Reading, search,
    labels, attachments and `.eml` keep working.
  - Pin the interpreter so an update can't switch the view off, for example Homebrew's
    `python@3.14` with `brew pin python@3.14`.
- **Google Chrome**, for PDF only, at `/Applications/Google Chrome.app` or wherever
  `pdf.chrome_path` points.
- **A Google Cloud project** with a Desktop-app OAuth client. It's free, and you create it
  once (below).
- **Claude Code or the Claude desktop app** as the client, or any stdio MCP client.

**Runtime state** lives in one private folder, `~/.gmail-mcp-private/` (`0700`):

- `accounts.json` and `oauth_client.json`;
- `tokens/`, holding the encrypted tokens;
- `audit.log`;
- `label-journal/`;
- the `locks/`, `render-gates/` and `render-tmp/` folders.

`GMAIL_MCP_RUNTIME_DIR` (an absolute path) moves the whole folder, and `GMAIL_MCP_CONFIG`
points at a different `accounts.json`.

## Setup: the AI-assisted way (recommended)

This repo ships a [CLAUDE.md](CLAUDE.md) that briefs Claude Code on the whole setup:

```bash
git clone https://github.com/dkaleganov/multi-gmail-mcp
cd multi-gmail-mcp
claude
```

Then say:

> Set up this Gmail MCP server for my accounts.

Claude Code walks you through everything: the Google Cloud project, the OAuth client,
your `accounts.json`, the export folder, the venv and locked dependencies, each browser
sign-in, registration, and verification. **You** do the parts only a human should:
creating credentials in the Google console, and clicking *Allow* once per account. Claude
never sees a secret. Tokens are written encrypted by the sign-in CLI, and the OAuth client
JSON is a file you download yourself.

## Setup: the manual way

1. **Google Cloud (once).**
   - At console.cloud.google.com, create a project and enable the **Gmail API**.
   - Configure the **OAuth consent screen**: External, then fill in the app name and your
     email. Then **Publish to production**, or refresh tokens expire every 7 days.
   - Under **Credentials**, choose **Create credentials → OAuth client ID → Application
     type: Desktop app**, then **Download JSON**.
2. **Place the client file:**
   ```bash
   mkdir -p ~/.gmail-mcp-private && chmod 700 ~/.gmail-mcp-private
   mv ~/Downloads/client_secret_*.json ~/.gmail-mcp-private/oauth_client.json
   chmod 600 ~/.gmail-mcp-private/oauth_client.json
   ```
3. **Configure your accounts:** copy `accounts.example.json` to
   `~/.gmail-mcp-private/accounts.json` and put in your own aliases and addresses.
4. **Run the setup script:**
   ```bash
   ./setup.sh
   ```
   It does the rest, in order:
   - picks Python (3.14 if present) and builds a venv;
   - installs the hash-pinned dependencies;
   - creates any missing export folder;
   - opens a browser sign-in for each configured account. Pick the matching inbox. On the
     "Google hasn't verified this app" screen (it's *your* app), click **Advanced →
     Continue**;
   - registers the server with Claude Code as `multi-gmail-mcp`;
   - verifies the setup and shows the PDF readiness state.
5. **Test:** in a new Claude session, ask for `list_accounts`.

### Google Workspace accounts

If an account is on Google Workspace, the admin may need to allow the app: Admin console →
Security → API controls → App access control, then mark your OAuth client trusted. The
trade-off is that this trusts the client org-wide, so guard your `oauth_client.json`.

## Configuration

`accounts.json` (see [`accounts.example.json`](accounts.example.json)):

| Key | Default | Meaning |
|---|---|---|
| `accounts` | | One entry per account: `alias` (`[A-Za-z0-9_-]+`, unique), `email` (unique), `scope` (`modify` or `readonly`) |
| `enable_send` | `false` | Half of the two-factor send arming; also needs `GMAIL_MCP_ALLOW_SEND=1` |
| `export_roots` | `{"default": "~/Downloads/gmail-exports"}` | Named export folders (up to 16; names `[A-Za-z0-9_-]{1,32}`) |
| `pdf.chrome_path` | `null` | Absolute path to Chrome; `null` uses the standard macOS location |
| `pdf.max_pages` | `50` | 1 to 1000; a longer message is refused, never truncated |
| `pdf.render_timeout_seconds` | `45` | 10 to 45, for the whole render |
| `pdf.memory_budget_mb` | `null` | 64 to 65536; must be set, from measurements, before PDF can turn on |
| `pdf.scratch_budget_mb` | `null` | 16 to 65536; same |
| `pdf.monitor_interval_ms` | `null` | 10 to 5000; same |
| `label_admin` | `true` | Registers the five label-administration tools |
| `label_delete_max_messages` | `10000` | 1 to 100000; `delete_label` refuses larger labels |

An invalid value never crashes the server. It turns off only the feature it governs and
prints a fixed warning to stderr. For example, an invalid `label_admin` registers no
admin tools, and an invalid `label_delete_max_messages` refuses every deletion.

## Enabling PDF (optional)

PDF output stays off (`pdf-unavailable`) until **both** of these are true.

1. **The renderer release gates pass on this machine's exact Chrome build.** The suite
   starts real Chrome with synthetic fixtures. Its only network target is a local
   listener on `127.0.0.1` / `::1`. Each protective layer is tested against a positive
   control: scripts, network, local files, page limit, wide content, supervisor, process
   containment and resources. PDFs are checked with macOS PDFKit. It takes a few minutes:
   ```bash
   .venv/bin/python tools/render_gates.py --out .test-tmp/gates-$(date +%Y%m%d) --write-record
   ```
   `--write-record` writes the gate record into `~/.gmail-mcp-private/render-gates/`, and
   only if every gate passed.
2. **Memory budgets are measured and set.** The same run writes `gates.json`, and its
   `results.resources.measurements` section shows each fixture's peak memory footprint and
   scratch use on your machine. Then:
   - set `pdf.memory_budget_mb` above the largest peak you want to allow, with headroom;
   - set `pdf.scratch_budget_mb` well above the observed scratch use;
   - set `pdf.monitor_interval_ms` to a short sampling interval, such as 50.

   These are monitored limits, not hard caps: memory can overshoot between two samples
   before the group is killed.

Then check the state and start a new Claude session:

```bash
.venv/bin/python tools/pdf_readiness.py
```

**PDF turns itself off after every Chrome update.** The gate record is bound to the
Chrome binary and version, the render recipe, and the renderer's own code. After any
change, readiness reports `gates-not-passed` until you re-run step 1. The other formats
keep working meanwhile.

## Using it

Some examples to ask Claude (`home` and `team` are aliases from your config):

- "Search **team** for unread invoices from the last week, and show me the next page too."
- "Read that thread and draft a reply saying we'll confirm by Friday."
- "Archive everything from that newsletter in **home**."
- "Save the PDF attachment from that message, and export the message itself as `.eml`."
- "Rename the label `Receipts/2025` to `Receipts/Archive`, then undo it."

Drafts land in the account's Drafts folder; you review and send them from Gmail yourself.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

The suite runs offline against a fake Gmail and a fake Chrome. It uses a throwaway
runtime folder under `.test-tmp/` (gitignored) with a Keychain tripwire, so it never
touches your real folder, tokens or Keychain. Run it with Python 3.14.6, the version the
export view is fingerprinted against.

## Known limits

- **A long export or label operation blocks that session's server.** That can be up to a
  45 s render, plus lock waits of up to 60 s (render, label admin) or 120 s (one message).
- **Parsing a crafted message is bounded, not cheap.** On the export path it can cost up
  to about 20 s and over 2 GB of memory before the view is refused. Message parsing does
  not yet run in a supervised child process.
- **PDF budgets are monitored, not hard caps** (see above).
- **A saved `.eml` keeps the message's original active HTML.** Opening it in Mail or
  previewing it with Quick Look is outside the renderer's controls. Spotlight and
  Quick Look may also parse files in `~/Downloads` without a click; an export root whose
  path ends in `.noindex` avoids indexing.
- **Export roots are shared by all accounts.** A synced or shared root gives a
  prompt-injected session a way to move mail content out of the machine.
- **Chrome's browser process runs unsandboxed as you.** Keep Chrome updated and re-run the
  gates.
- **The export view's inline-image prediction is conservative.** For very large or unusual
  messages, some embedded images are saved as attachments even though the view might
  show them.
- **Undo can't verify memberships individually.** Batch and thread label changes aren't
  journaled, and `undo_label_change` counts accepted, missing, unresolved and conflicting
  ids rather than reading each membership back.
- **Pagination tokens are valid only in the server process that issued them.** A new
  session restarts its search.

## More machines

Each install is independent, with its own encrypted tokens: set it up on another machine
and the two never conflict. Re-run the PDF gates and measurements on each machine.

## Kill switch

- **Disable:** `claude mcp remove multi-gmail-mcp`
- **Revoke one account:** delete `~/.gmail-mcp-private/tokens/<alias>.enc` and/or revoke the
  app at <https://myaccount.google.com/permissions>
- **Remove everything:** delete `~/.gmail-mcp-private/` (exported files stay in the folders
  you configured)

## Files to audit

| File | What it is |
|---|---|
| `server.py` | The MCP server and the exact tools Claude can call |
| `gmail.py` | Gmail API wrapper, MIME parsing, label resolution, header-injection guards |
| `auth.py`, `authenticate.py` | OAuth loopback flow, encrypted atomic token storage, account validation; the sign-in CLI a human runs |
| `auditlog.py` | Metadata-only audit logging (`0600`, rotating) |
| `runtime.py`, `config.py`, `output.py` | Runtime folder, settings validation, the trusted-line and fence contract |
| `mime.py`, `names.py` | Attachment enumeration and inline prediction; file-name rules |
| `exportfs.py`, `exports.py`, `exporttools.py` | Write controls (pinned roots, no-clobber, quarantine), the export identity and recovery protocol, the export tools |
| `htmlview.py` | The sanitized view |
| `renderer.py`, `procinfo.py` | Chrome over a pipe, with the supervisor; process inspection |
| `journal.py`, `labels.py`, `locks.py` | The label recovery journal, label administration, host-wide locks |
| `tools/render_gates.py`, `tools/pdf_readiness.py` | The renderer release gates; the readiness report |
| `tests/` | The offline suite |
| `setup.sh`, `CLAUDE.md` | One-command install; the brief that lets Claude Code run your setup |

## License and author

MIT, see [LICENSE](LICENSE). Built by [Dima Kaleganov](https://github.com/dkaleganov)
with Claude Code.
