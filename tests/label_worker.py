"""Subprocess worker for the label crash gates.

usage: python -m tests.label_worker <fake-state.json> <action-json>
action: {"fn": "update_label"|"delete_label"|"undo_label_change"|"create_label", "args": {...},
         "crash_at": stage-or-null, "lost": [method, ...]}
The fake Gmail state persists in <fake-state.json> after every mutating call, so a crash
leaves the 'remote' side exactly as Gmail would. crash_at kills the process with
os._exit(97) at that checkpoint (labels._checkpoint or journal._checkpoint).
"""
from tests import support  # noqa: F401

import json
import os
import sys

import gmail
import journal
import labels
from output import ToolError
from tests.fakegmail import PersistentFake


def main():
    state, action = sys.argv[1], json.loads(sys.argv[2])
    fake = PersistentFake(state)
    for m in action.get("lost") or []:
        fake.fail(m, lost=True)
    for m, status in (action.get("fail") or {}).items():
        fake.fail(m, status)
    gmail.service = lambda creds: fake
    stage = action.get("crash_at")
    if stage:
        def crash(s):
            if s == stage:
                sys.stdout.flush()
                os._exit(97)
        labels._checkpoint = crash
        journal._checkpoint = crash
    a = {"alias": "alpha", "email": "alpha@example.test"}
    fn = getattr(labels, action["fn"])
    try:
        out, meta = fn(object(), a, **action["args"])
        print(json.dumps({"ok": True, "out": out, "meta": meta}))
    except ToolError as e:
        print(json.dumps({"ok": False, "code": e.code, "message": e.message}))


if __name__ == "__main__":
    main()
