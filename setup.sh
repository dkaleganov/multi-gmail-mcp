#!/usr/bin/env bash
# One-command setup for multi-gmail-mcp. Run from inside this folder:  ./setup.sh
# Builds the venv from the hash-pinned lock, checks your config and OAuth client, creates
# your export folders, runs one browser sign-in per account, registers the server with
# Claude Code, and verifies. Safe to re-run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CFG_DIR="$HOME/.gmail-mcp-private"
CFG="${GMAIL_MCP_CONFIG:-$CFG_DIR/accounts.json}"

echo "==> 1/7  Python (3.10+; 3.14.6 for the export view)"
PY="$(command -v python3.14 || true)"
[ -n "$PY" ] || [ ! -x /opt/homebrew/opt/python@3.14/bin/python3.14 ] || PY=/opt/homebrew/opt/python@3.14/bin/python3.14
[ -n "$PY" ] || PY="$(command -v python3 || true)"
[ -n "$PY" ] || { echo "ERROR: python3 not found. Install Python 3.14 (or at least 3.10) first."; exit 1; }
"$PY" - <<'P'
import sys
v = sys.version.split()[0]
assert sys.version_info >= (3, 10), f"Need Python 3.10+, have {v}"
print("   ok:", v, sys.executable)
if v != "3.14.6":
    print("   NOTE: the export view (.html, PDF, inline images) is fingerprinted against CPython 3.14.6;")
    print("         on this version it reports stdlib-changed. Reading, search, labels, attachments")
    print("         and .eml are unaffected.")
P

echo "==> 2/7  virtualenv + dependencies (hash-pinned)"
"$PY" -m venv "$HERE/.venv"
if "$HERE/.venv/bin/pip" -q install --require-hashes -r "$HERE/requirements.lock" 2>/dev/null; then
  echo "   installed from the hash-pinned lock"
else
  echo "   WARNING: the lock didn't match this platform — installing UNPINNED from requirements.txt"
  "$HERE/.venv/bin/pip" -q install -r "$HERE/requirements.txt"
fi

echo "==> 3/7  config ($CFG)"
mkdir -p "$CFG_DIR/tokens"; chmod 700 "$CFG_DIR" "$CFG_DIR/tokens"
if [ ! -f "$CFG" ]; then
  cp "$HERE/accounts.example.json" "$CFG"; chmod 600 "$CFG"
  echo "   ERROR: wrote a template to $CFG — edit it with YOUR aliases and addresses, then re-run."
  echo "   (Tip: open this folder in Claude Code and ask it to set the server up for you.)"
  exit 1
fi
chmod 600 "$CFG"
if grep -q "you@example\.com\|you@example\.org" "$CFG"; then
  echo "   ERROR: $CFG still contains the placeholder addresses — put your real accounts in, then re-run."
  exit 1
fi
echo "   accounts.json present"

echo "==> 4/7  OAuth client"
if [ ! -f "$CFG_DIR/oauth_client.json" ]; then
  cat <<EOF
   MISSING: $CFG_DIR/oauth_client.json
   Create a Desktop-app OAuth client (free, ~5 min) and put its JSON there:
     1. console.cloud.google.com -> create/pick a project
     2. enable the Gmail API
     3. OAuth consent screen: External -> fill name/email -> PUBLISH TO PRODUCTION
     4. Credentials -> Create credentials -> OAuth client ID -> type: Desktop app -> Download JSON
     5. mv ~/Downloads/client_secret_*.json $CFG_DIR/oauth_client.json
   Then re-run this script. (Full steps: README.md)
EOF
  exit 1
fi
chmod 600 "$CFG_DIR/oauth_client.json"
echo "   oauth_client.json present (0600)"

echo "==> 5/7  export folders (export_roots)"
CFG="$CFG" "$HERE/.venv/bin/python" - <<'P'
import json, os, stat
cfg = json.load(open(os.environ["CFG"]))
roots = cfg.get("export_roots", {"default": "~/Downloads/gmail-exports"})
if not isinstance(roots, dict):
    raise SystemExit("   ERROR: export_roots must be an object of name -> folder")
for name, path in roots.items():
    p = os.path.expanduser(str(path))
    if not os.path.exists(p):
        os.makedirs(p, mode=0o700)
        os.chmod(p, 0o700)
        print(f"   created {name}: {p} (0700)")
        continue
    st = os.stat(p)
    if not stat.S_ISDIR(st.st_mode):
        print(f"   WARNING {name}: {p} is not a folder; exports to it will fail")
    elif st.st_uid != os.getuid() or st.st_mode & 0o022:
        print(f"   WARNING {name}: {p} must be yours and not group/world-writable (chmod go-w)")
    else:
        print(f"   ok {name}: {p}")
P

echo "==> 6/7  authorize each account (a browser opens per account — sign in to the MATCHING inbox)"
ALIASES="$(CFG="$CFG" "$HERE/.venv/bin/python" -c 'import json, os; print(" ".join(a["alias"] for a in json.load(open(os.environ["CFG"]))["accounts"]))')"
for a in $ALIASES; do
  echo "   --- $a ---"
  "$HERE/.venv/bin/python" "$HERE/authenticate.py" "$a" \
    || echo "   (failed/skipped for $a — re-run later: $HERE/.venv/bin/python $HERE/authenticate.py $a)"
done

echo "==> 7/7  register with Claude Code (user scope) + verify"
CLAUDE="$(command -v claude || echo "$HOME/.local/bin/claude")"
"$CLAUDE" mcp add --scope user multi-gmail-mcp -- "$HERE/.venv/bin/python" "$HERE/server.py" 2>&1 || true
"$HERE/.venv/bin/python" "$HERE/authenticate.py" --list
echo "   PDF readiness (PDF stays off until you enable it; see README):"
"$HERE/.venv/bin/python" "$HERE/tools/pdf_readiness.py" || true

echo
echo "Done. Open a NEW Claude session and try:  list_accounts"
echo "Kill switch: claude mcp remove multi-gmail-mcp   (or delete ~/.gmail-mcp-private)"
