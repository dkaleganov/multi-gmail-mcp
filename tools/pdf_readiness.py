#!/usr/bin/env python3
"""Print PDF renderer readiness for this host's configuration (section 12 version recording).

    python tools/pdf_readiness.py            # uses $GMAIL_MCP_RUNTIME_DIR / $GMAIL_MCP_CONFIG if set

Reports the Chrome binary, its version, the render recipe, the readiness code, and whether a
gate record exists for this exact Chrome build. Starts Chrome only for `--version`, and only
when the budget settings are configured.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import config  # noqa: E402
import renderer  # noqa: E402
import runtime  # noqa: E402


def main():
    path = runtime.config_path()
    cfg = json.loads(path.read_text()) if path.exists() else {}
    st = config.parse(cfg).pdf
    r = renderer.readiness(st, use_cache=False)
    print(json.dumps({"ready": r.ready, "code": r.code, "detail": r.detail, "chrome_path": r.chrome_path,
                      "chrome_version": r.chrome_version or (renderer.chrome_version(r.chrome_path) if r.chrome_path else None),
                      "render_recipe": renderer.RENDER_RECIPE, "max_pages": st.max_pages,
                      "render_timeout_seconds": st.render_timeout_seconds, "memory_budget_mb": st.memory_budget_mb,
                      "scratch_budget_mb": st.scratch_budget_mb, "monitor_interval_ms": st.monitor_interval_ms}, indent=1))
    return 0 if r.ready else 1


if __name__ == "__main__":
    sys.exit(main())
