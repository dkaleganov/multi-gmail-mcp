"""Subprocess worker for export crash and concurrency tests.

usage: python -m tests.export_worker <root_dir> <message_id> <spec-json>
spec: {"items": [{"key": str, "kind": str, "namespace": str, "name": str, "data": hex | null,
                  "random": int | null, "sleep": float}], "crash_at": stage | null}
Prints one JSON line with the per-item results. With crash_at set, the process dies with
os._exit(97) at that protocol boundary (no cleanup runs, like a real crash).
"""
from tests import support  # noqa: F401  (isolated runtime root)

import json
import os
import sys
import time

import exportfs
import exports
import names


def main():
    root_dir, mid, spec = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
    if spec.get("crash_at"):
        stage = spec["crash_at"]

        def crash(s):
            if s == stage:
                sys.stdout.flush()
                os._exit(97)

        exports._checkpoint = crash
    root = exportfs.pin_root("default", root_dir)
    target = exports.Target(root=root, alias="alpha", identity=exports.identity_hash("alpha@example.test"),
                            account_ns=exports.account_namespace("alpha", "alpha@example.test"),
                            subfolder=spec.get("subfolder", []), message_id=mid)
    reqs = []
    for it in spec["items"]:
        def produce(fd, _it=it):
            if _it.get("sleep"):
                time.sleep(_it["sleep"])
            data = bytes.fromhex(_it["data"]) if _it.get("data") is not None else os.urandom(_it["random"])
            return exportfs.write_temp(fd, [data], exports.PER_FILE_CAP, expected_size=len(data))

        plan = names.plan_name(it["name"], "fallback.bin", names.sniff(bytes.fromhex(it["data"])[:16]) if it.get("data") else None)
        reqs.append(exports.Request(it["key"], it["kind"], it["namespace"], plan, produce, {"n": it["name"]}))
    with exports.ExportSession(target, {"subject": "synthetic"}) as s:
        res = s.publish(reqs)
        print(json.dumps({"results": [{"key": r.key, "state": r.state, "code": r.code, "name": r.name,
                                       "sha256": r.sha256} for r in res],
                          "recovered": s.recovered, "conflicts": s.conflicts, "orphans": len(s.orphans)}))


if __name__ == "__main__":
    main()
