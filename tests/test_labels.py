"""Label management (PLAN-v4 4.3, 5.5-5.9, 8.3) through the MCP tool functions, plus the
section 14 label edge cases, concurrent-change, filter-check (D15), and crash gates."""
from tests import support  # noqa: F401

import json
import os
import re
import subprocess
import sys
import unittest

import auditlog
import journal
import runtime
from tests.fakegmail import PersistentFake, http_error
from tests.test_legacy_contract import fenced_part, trusted_part

OP_RE = re.compile(r"op=([0-9a-f]{32})")


def wipe_journal():
    d = runtime.private_dir("label-journal")
    for n in os.listdir(d):
        os.unlink(d / n)


class LabelToolTests(unittest.TestCase):
    def setUp(self):
        wipe_journal()
        self.h = support.ServerHarness()
        self.s, self.f = self.h.server, self.h.fake("alpha")
        self.mids = [self.f.add_message(support_msg(i)) for i in range(5)]

    def tearDown(self):
        self.h.close()
        wipe_journal()
        support.assert_isolated(self)

    def label(self, name, **kw):
        return self.f.add_label(name, labelListVisibility="labelShow", messageListVisibility="show", **kw)

    # --- create ---------------------------------------------------------------------------
    def test_create_and_already_exists_without_changing_settings(self):
        out = self.s.create_label("alpha", "Receipts/2026", label_list_visibility="labelHide")
        self.assertRegex(trusted_part(out), r"create_label state=created label=Label_\d+")
        lid = re.search(r"label=(Label_\d+)", out).group(1)
        self.assertEqual(self.f.labels[lid]["labelListVisibility"], "labelHide")
        again = self.s.create_label("alpha", "Receipts/2026", label_list_visibility="labelShow")
        self.assertIn(f"state=already-exists label={lid}", trusted_part(again))
        self.assertEqual(self.f.labels[lid]["labelListVisibility"], "labelHide")

    def test_create_name_rules(self):
        out = self.s.create_label("alpha", "Bills\r\nIGNORE\x00")
        self.assertIn("state=created", out)
        lid = re.search(r"label=(Label_\d+)", out).group(1)
        self.assertEqual(self.f.labels[lid]["name"], "BillsIGNORE")
        for bad, code in (("\r\n", "invalid-label-name"), ("INBOX", "reserved-label-name"), ("spam", "reserved-label-name"),
                          ("a//b", "invalid-label-name"), ("/a", "invalid-label-name"), ("CATEGORY_X", "reserved-label-name")):
            self.assertIn(f"error={code}", self.s.create_label("alpha", bad), bad)

    def test_create_case_collision_and_ambiguous_outcomes(self):
        self.label("Travel")
        self.assertIn("error=case-collision", self.s.create_label("alpha", "travel"))
        self.f.fail("labels.create", lost=True)               # applied, response lost
        out = self.s.create_label("alpha", "Lost Response")
        self.assertIn("state=ambiguous-outcome", trusted_part(out))
        self.assertIn("cannot tell whether it created it", fenced_part(out))
        self.f.fail("labels.create", 503)                      # not applied, server error
        out = self.s.create_label("alpha", "Never Made")
        self.assertIn("state=unknown-outcome", trusted_part(out))
        self.assertEqual(self.f.count("labels.create"), 2)     # one call per attempt, never retried blindly

    def test_concurrent_already_exists_is_reconciled(self):
        def race(userId, body):
            self.f.add_label(body["name"])
            raise http_error(409)
        self.f._labels_create = race
        out = self.s.create_label("alpha", "Raced")
        self.assertIn("state=already-exists", trusted_part(out))

    # --- update -------------------------------------------------------------------------------
    def test_update_journaled_and_undo_restores(self):
        lid = self.label("Old Name")
        out = self.s.update_label("alpha", "Old Name", new_name="New Name", label_list_visibility="labelHide")
        self.assertIn("state=applied", trusted_part(out))
        op = OP_RE.search(out).group(1)
        self.assertEqual(self.f.labels[lid]["name"], "New Name")
        with journal.AdminSession() as s:
            o = s.op(op)
            self.assertEqual(o.prepared["before"]["name"], "Old Name")
            self.assertEqual(o.outcome, "APPLIED")
        u = self.s.undo_label_change("alpha", op)
        self.assertIn("state=undone outcome=restored", trusted_part(u))
        self.assertEqual((self.f.labels[lid]["name"], self.f.labels[lid]["labelListVisibility"]), ("Old Name", "labelShow"))
        u2 = self.s.undo_label_change("alpha", op)            # terminal: idempotent
        self.assertIn("state=undone", trusted_part(u2))
        self.assertIn("nothing was repeated", fenced_part(u2))
        self.assertEqual(self.f.count("labels.patch"), 2)

    def test_three_way_rule(self):
        lid = self.label("A")
        op = OP_RE.search(self.s.update_label("alpha", "A", new_name="B")).group(1)
        self.f.labels[lid]["name"] = "A"                       # someone else already restored it
        self.assertIn("outcome=observed-restored", self.s.undo_label_change("alpha", op))
        lid2 = self.label("C")
        op2 = OP_RE.search(self.s.update_label("alpha", "C", new_name="D")).group(1)
        self.f.labels[lid2]["name"] = "E"                      # a third state
        out = self.s.undo_label_change("alpha", op2)
        self.assertIn("state=conflict", trusted_part(out))
        self.assertEqual(self.f.labels[lid2]["name"], "E")      # never overwritten

    def test_update_refuses_system_cascade_and_conflicts(self):
        self.assertIn("error=system-label", self.s.update_label("alpha", "INBOX", new_name="X"))
        self.label("Parent")
        self.label("Parent/Child")
        self.assertIn("error=unsupported-cascade", self.s.update_label("alpha", "Parent", new_name="P2"))
        self.assertIn("state=applied", self.s.update_label("alpha", "Parent", label_list_visibility="labelHide"))
        self.label("Taken")
        self.assertIn("error=name-conflict", self.s.update_label("alpha", "Parent/Child", new_name="taken"))

    def test_update_definitive_rejection_is_not_applied(self):
        self.label("Colorful")
        self.f.fail("labels.patch", 400)
        out = self.s.update_label("alpha", "Colorful", color={"backgroundColor": "#123456", "textColor": "#ffffff"})
        self.assertIn("state=not-applied", trusted_part(out))
        op = OP_RE.search(out).group(1)
        self.assertIn("state=nothing-to-undo", self.s.undo_label_change("alpha", op))

    def test_update_ambiguous_then_reconciled_by_undo(self):
        lid = self.label("Amb")
        self.f.fail("labels.patch", lost=True)
        out = self.s.update_label("alpha", "Amb", new_name="Amb2")
        self.assertIn("state=unknown-outcome", trusted_part(out))
        op = OP_RE.search(out).group(1)
        u = self.s.undo_label_change("alpha", op)             # reconciles to APPLIED, then undoes
        self.assertIn("state=undone outcome=restored", trusted_part(u))
        self.assertEqual(self.f.labels[lid]["name"], "Amb")

    def test_label_resolution_rules(self):
        self.label("Dup")
        self.f.ci_names = False
        self.label("dup")
        self.assertIn("error=ambiguous-label", self.s.update_label("alpha", "DUP", new_name="x"))
        self.assertIn("state=applied", self.s.update_label("alpha", "Dup", label_list_visibility="labelHide"))
        self.assertIn("error=unknown-label", self.s.update_label("alpha", "Nope", new_name="x"))

    # --- delete -------------------------------------------------------------------------------
    def test_delete_snapshot_and_undo_restore_memberships(self):
        lid = self.label("Project X", color={"backgroundColor": "#16a766", "textColor": "#ffffff"})
        for m in self.mids[:3]:
            self.f.messages[m]["labelIds"].add(lid)
        self.f.messages[self.mids[0]]["labelIds"].add("TRASH")  # trash/spam members are included
        out = self.s.delete_label("alpha", "Project X", confirm_name="Project X")
        t = trusted_part(out)
        self.assertIn("state=applied", t)
        self.assertIn("snapshot=3 filter_references=0", t)
        for stmt in ("No mail was deleted.", "to a NEW label id", "not repaired"):
            self.assertIn(stmt, t)
        self.assertNotIn(lid, self.f.labels)
        self.assertEqual(len(self.f.messages), 5)               # no mail deleted
        op = OP_RE.search(out).group(1)
        u = self.s.undo_label_change("alpha", op)
        self.assertIn("state=undone", trusted_part(u))
        self.assertIn("accepted=3 confirmed_missing=0 unresolved=0 conflicting=0 restored_and_verified=0", trusted_part(u))
        new = [l for l in self.f.labels.values() if l["name"] == "Project X"][0]
        self.assertNotEqual(new["id"], lid)
        self.assertEqual(new["color"], {"backgroundColor": "#16a766", "textColor": "#ffffff"})
        self.assertEqual(self.f.members(new["id"]), set(self.mids[:3]))
        self.assertIn("not individually verified", fenced_part(u))

    def test_delete_confirmations_and_filter_check(self):
        lid = self.label("Filtered")
        self.f.filters = [{"id": "f1", "criteria": {"from": "x@example.test"}, "action": {"addLabelIds": [lid]}},
                          {"id": "f2", "criteria": {}, "action": {"removeLabelIds": [lid, "INBOX"]}},
                          {"id": "f3", "criteria": {}, "action": {"addLabelIds": ["STARRED"]}}]
        self.assertIn("error=confirm-name-mismatch", self.s.delete_label("alpha", "Filtered", confirm_name="filtered"))
        out = self.s.delete_label("alpha", "Filtered", confirm_name="Filtered")
        self.assertIn("error=filter-references-unconfirmed", out)
        self.assertIn("2 Gmail filter(s)", out)
        self.assertNotIn("x@example.test", out)
        self.assertIn("error=filter-references-unconfirmed",
                      self.s.delete_label("alpha", "Filtered", confirm_name="Filtered", confirm_filter_references=1))
        self.f.fail("settings.filters.list", 500)
        self.assertIn("error=filter-check-failed",
                      self.s.delete_label("alpha", "Filtered", confirm_name="Filtered", confirm_filter_references=2))
        self.assertIn(lid, self.f.labels)
        ok = self.s.delete_label("alpha", "Filtered", confirm_name="Filtered", confirm_filter_references=2)
        self.assertIn("filter_references=2", trusted_part(ok))
        self.assertNotIn(lid, self.f.labels)
        log = auditlog.LOG_FILE.read_text()
        self.assertNotIn("Filtered", log)
        self.assertNotIn("x@example.test", log)
        rec = [json.loads(l) for l in log.strip().splitlines() if '"delete_label"' in l][-1]
        self.assertEqual((rec["filter_refs"], rec["label_id"]), (2, lid))

    def test_delete_refusals_leave_everything(self):
        self.assertIn("error=system-label", self.s.delete_label("alpha", "INBOX", confirm_name="INBOX"))
        lid = self.label("Big")
        for m in self.mids:
            self.f.messages[m]["labelIds"].add(lid)
        orig = self.s.SETTINGS.label_delete_max_messages
        self.s.SETTINGS.label_delete_max_messages = 3
        try:
            self.assertIn("error=snapshot-too-large", self.s.delete_label("alpha", "Big", confirm_name="Big"))
        finally:
            self.s.SETTINGS.label_delete_max_messages = orig
        self.f.fail("messages.list", 500)
        self.assertIn("error=snapshot-failed", self.s.delete_label("alpha", "Big", confirm_name="Big"))
        self.assertIn(lid, self.f.labels)

    def test_rename_during_deletion_setup_aborts(self):
        lid = self.label("Moving")
        orig = self.f._labels_get
        calls = {"n": 0}

        def get(userId, id):
            calls["n"] += 1
            r = orig(userId, id)
            if calls["n"] == 2:                                  # the post-PREPARED recheck
                self.f.labels[lid]["name"] = "Renamed Elsewhere"
                r = orig(userId, id)
            return r

        self.f._labels_get = get
        out = self.s.delete_label("alpha", "Moving", confirm_name="Moving")
        self.assertIn("error=label-changed", out)
        self.assertIn(lid, self.f.labels)

    def test_membership_churn_restarts_then_aborts(self):
        lid = self.label("Churn")
        orig = self.f._messages_list
        n = {"i": 0}

        def churn(**kw):
            n["i"] += 1
            r = orig(**kw)
            r["messages"] = (r.get("messages") or []) + [{"id": f"{0x18f000 + n['i']:016x}", "threadId": "t"}]
            return r

        self.f._messages_list = churn
        out = self.s.delete_label("alpha", "Churn", confirm_name="Churn")
        self.assertIn("error=membership-churn", out)
        self.assertIn(lid, self.f.labels)
        with journal.AdminSession() as s:
            states = [o.outcome for o in s.ops.values() if o.kind == "delete"]
        self.assertEqual(states, ["NOT_APPLIED"] * 3)            # restarted twice, then aborted

    def test_undo_delete_with_missing_ids_and_permission_errors(self):
        lid = self.label("Mixed")
        for m in self.mids:
            self.f.messages[m]["labelIds"].add(lid)
        op = OP_RE.search(self.s.delete_label("alpha", "Mixed", confirm_name="Mixed")).group(1)
        del self.f.messages[self.mids[0]]                        # vanished since the snapshot
        self.f.batch_missing = "error"                           # the batch fails as a whole
        self.f.fail("messages.modify", 403, when=lambda kw: kw.get("id") == self.mids[1])
        u = self.s.undo_label_change("alpha", op)
        t = trusted_part(u)
        self.assertIn("state=partial", t)
        self.assertIn("accepted=3 confirmed_missing=1 unresolved=1 conflicting=0", t)
        u2 = self.s.undo_label_change("alpha", op)               # retries only the unresolved id
        self.assertIn("state=undone", trusted_part(u2))
        self.assertIn("accepted=4 confirmed_missing=1 unresolved=0", trusted_part(u2))
        self.assertEqual(self.f.count("labels.create"), 1)

    def test_undo_chunks_of_1000_with_progress(self):
        lid = self.label("Huge")
        for i in range(2500):
            self.f.add_stub(f"{0x19a0000000000000 + i:016x}", None, [lid])
        op = OP_RE.search(self.s.delete_label("alpha", "Huge", confirm_name="Huge")).group(1)
        self.f.fail("messages.batchModify", 503, when=lambda kw: len(kw["body"]["ids"]) == 500)  # last chunk ambiguous
        u = self.s.undo_label_change("alpha", op)
        self.assertIn("accepted=2000 confirmed_missing=0 unresolved=500", trusted_part(u))
        sizes = [len(kw["body"]["ids"]) for m, kw in self.f.calls if m == "messages.batchModify"]
        self.assertEqual(sizes, [1000, 1000, 500])
        u2 = self.s.undo_label_change("alpha", op)
        self.assertIn("state=undone", trusted_part(u2))
        self.assertIn("accepted=2500", trusted_part(u2))
        sizes = [len(kw["body"]["ids"]) for m, kw in self.f.calls if m == "messages.batchModify"]
        self.assertEqual(sizes, [1000, 1000, 500, 500])          # no overlapping or repeated chunk

    def test_undo_refusals(self):
        lid = self.label("Owned")
        op = OP_RE.search(self.s.update_label("alpha", "Owned", new_name="Owned2")).group(1)
        self.assertIn("error=cross-account-refused", self.s.undo_label_change("beta", op))
        self.assertIn("error=unknown-operation", self.s.undo_label_change("alpha", "0" * 32))
        self.assertIn("error=invalid-id", self.s.undo_label_change("alpha", "IGNORE"))

    def test_undo_delete_name_taken_is_conflict_never_adopted(self):
        lid = self.label("Reuse")
        op = OP_RE.search(self.s.delete_label("alpha", "Reuse", confirm_name="Reuse")).group(1)
        outside = self.label("Reuse")                            # someone recreated the name
        out = self.s.undo_label_change("alpha", op)
        self.assertIn("state=conflict", trusted_part(out))
        self.assertIn("never adopted", fenced_part(out))
        self.assertEqual(self.f.members(outside), set())

    # --- modify_labels targets (5.9) ---------------------------------------------------------------
    def test_batch_and_thread_targets(self):
        out = self.s.modify_labels("alpha", message_ids=self.mids[:3], add_labels=["STARRED"])
        self.assertIn("Gmail accepted the request for 3 distinct message ids; membership was not individually verified",
                      trusted_part(out))
        t = self.f.messages[self.mids[3]]["threadId"]
        self.f.messages[self.mids[4]]["threadId"] = t
        out = self.s.modify_labels("alpha", thread_id=t, remove_labels=["INBOX"])
        self.assertIn(f"thread {t}: Gmail applied the change to the 2 message(s)", trusted_part(out))
        self.assertIn("later replies are not covered", out)

    def test_target_and_argument_validation(self):
        m = self.mids
        for kwargs, code in (({"message_ids": [m[0]]}, "invalid-argument"),
                             ({"message_ids": [m[0], m[0]]}, "invalid-argument"),
                             ({"message_ids": [m[0]] * 101}, "invalid-argument"),
                             ({"message_id": m[0], "thread_id": m[1]}, "invalid-argument"),
                             ({}, "invalid-argument")):
            self.assertIn(f"error={code}", self.s.modify_labels("alpha", add_labels=["STARRED"], **kwargs), kwargs)
        self.assertIn("error=invalid-argument",
                      self.s.modify_labels("alpha", message_id=m[0], add_labels=["STARRED"], remove_labels=["STARRED"]))

    def test_trash_and_spam_refused_on_every_path(self):
        t = self.f.messages[self.mids[0]]["threadId"]
        for kwargs in ({"message_id": self.mids[0]}, {"message_ids": self.mids[:2]}, {"thread_id": t}):
            for lab in ("TRASH", "SPAM"):
                out = self.s.modify_labels("alpha", add_labels=[lab], **kwargs)
                self.assertIn("error=invalid-argument", out)
        self.assertEqual(self.f.count("messages.modify") + self.f.count("messages.batchModify")
                         + self.f.count("threads.modify"), 0)

    def test_membership_changes_wait_for_the_admin_lock(self):
        holder = subprocess.Popen([sys.executable, "-c",
                                   "from tests import support; import locks, time\n"
                                   "with locks.admin_lock(5):\n    print('held', flush=True); time.sleep(3)"],
                                  cwd=support.REPO, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        import labels
        orig = labels.modify_targets.__defaults__
        labels.modify_targets.__defaults__ = (0.5,)
        try:
            out = self.s.modify_labels("alpha", message_id=self.mids[0], add_labels=["STARRED"])
        finally:
            labels.modify_targets.__defaults__ = orig
        self.assertIn("error=labels-busy", out)
        holder.wait(timeout=30)
        holder.stdout.close()


def support_msg(i):
    from tests import messages as M
    return M.plain(subject=f"label test {i}")


class LabelAdminRegistrationTests(unittest.TestCase):
    def _tools(self, label_admin) -> set[str]:
        d = support.scratch("label-admin")
        cfg = support.default_config(support.EXPORTS_DIR)
        cfg["label_admin"] = label_admin
        support.write_config(d / "accounts.json", cfg)
        env = dict(os.environ, GMAIL_MCP_CONFIG=str(d / "accounts.json"))
        code = "from tests import support; import server; print(','.join(sorted(support.tool_names(server))))"
        out = subprocess.run([sys.executable, "-c", code], cwd=support.REPO, env=env, capture_output=True,
                             text=True, check=True).stdout.strip().splitlines()[-1]
        return set(out.split(","))

    def test_registration_both_ways(self):
        admin = {"create_label", "update_label", "delete_label", "undo_label_change", "list_label_operations"}
        on = self._tools(True)
        off = self._tools(False)
        invalid = self._tools("yes")                              # invalid value fails safe: not registered
        self.assertLessEqual(admin, on)
        self.assertFalse(admin & off)
        self.assertFalse(admin & invalid)
        for tools in (on, off, invalid):
            self.assertIn("modify_labels", tools)                 # membership changes remain, as in v4


# --- crash gates -----------------------------------------------------------------------------------
def worker(state, action):
    p = subprocess.run([sys.executable, "-m", "tests.label_worker", str(state), json.dumps(action)],
                       cwd=support.REPO, capture_output=True, text=True, timeout=120)
    if p.returncode not in (0, 97):
        raise AssertionError(p.stderr)
    lines = [l for l in p.stdout.splitlines() if l.startswith("{")]
    return p.returncode, (json.loads(lines[-1]) if lines else None)


class LabelCrashGateTests(unittest.TestCase):
    """Crash before and after every durable intent and remote mutation."""

    def setUp(self):
        wipe_journal()
        self.state = support.scratch("crash-state") / "fake.json"
        f = PersistentFake(self.state)
        self.lid = f.add_label("Crashy", labelListVisibility="labelShow", messageListVisibility="show")
        for i in range(3):
            f.add_stub(f"{0x18e0000000000000 + i:016x}", None, ["INBOX", self.lid])
        f.save()

    def tearDown(self):
        wipe_journal()

    def fake(self):
        return PersistentFake(self.state)

    def op_of(self):
        with journal.AdminSession() as s:
            return list(s.ops.values())[-1]

    def test_update_crash_after_prepare_reconciles_to_not_applied(self):
        rc, _ = worker(self.state, {"fn": "update_label", "args": {"label": "Crashy", "new_name": "Renamed"},
                                    "crash_at": "update-after-prepared"})
        self.assertEqual(rc, 97)
        op = self.op_of()
        self.assertTrue(op.unresolved)
        self.assertEqual(self.fake().labels[self.lid]["name"], "Crashy")
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op.op_id}})
        self.assertIn("state=nothing-to-undo", out["out"])

    def test_update_crash_after_remote_reconciles_to_applied_then_undo(self):
        rc, _ = worker(self.state, {"fn": "update_label", "args": {"label": "Crashy", "new_name": "Renamed"},
                                    "crash_at": "update-after-remote"})
        self.assertEqual(rc, 97)
        self.assertEqual(self.fake().labels[self.lid]["name"], "Renamed")   # remote applied, outcome lost
        op = self.op_of()
        self.assertTrue(op.unresolved)
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op.op_id}})
        self.assertIn("state=undone outcome=restored", out["out"])
        self.assertEqual(self.fake().labels[self.lid]["name"], "Crashy")

    def test_undo_update_crash_after_remote_before_terminal(self):
        rc, out = worker(self.state, {"fn": "update_label", "args": {"label": "Crashy", "new_name": "Renamed"}})
        op = OP_RE.search(out["out"]).group(1)
        rc, _ = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op},
                                    "crash_at": "undo-update-after-remote"})
        self.assertEqual(rc, 97)
        self.assertEqual(self.fake().labels[self.lid]["name"], "Crashy")    # remote undo applied
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op}})
        self.assertIn("outcome=observed-restored", out["out"])              # three-way rule, no re-patch
        with journal.AdminSession() as s:
            self.assertEqual(s.op(op).undo_terminal, "UNDONE")

    def test_delete_crash_after_prepare_and_after_remote(self):
        rc, _ = worker(self.state, {"fn": "delete_label", "args": {"label": "Crashy", "confirm_name": "Crashy"},
                                    "crash_at": "delete-after-prepared"})
        self.assertEqual(rc, 97)
        self.assertIn(self.lid, self.fake().labels)
        rc, out = worker(self.state, {"fn": "delete_label", "args": {"label": "Crashy", "confirm_name": "Crashy"},
                                      "crash_at": "delete-after-remote"})
        self.assertEqual(rc, 97)                                             # first op reconciled NOT_APPLIED first
        self.assertNotIn(self.lid, self.fake().labels)
        with journal.AdminSession() as s:
            ops = sorted(s.ops.values(), key=lambda o: o.events[0]["seq"])
            self.assertEqual(ops[0].outcome, "NOT_APPLIED")
            self.assertTrue(ops[1].unresolved)
            second = ops[1].op_id
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": second}})
        self.assertIn("state=undone", out["out"])
        self.assertIn("accepted=3", out["out"])
        f = self.fake()
        new = [l for l in f.labels.values() if l["name"] == "Crashy"][0]
        self.assertEqual(len(f.members(new["id"])), 3)

    def _deleted_op(self):
        rc, out = worker(self.state, {"fn": "delete_label", "args": {"label": "Crashy", "confirm_name": "Crashy"}})
        return OP_RE.search(out["out"]).group(1)

    def test_undo_delete_crash_before_replacement_id_is_recorded_is_a_conflict(self):
        for stage in ("undo-delete-after-prepared", "undo-delete-after-create"):
            self.setUp()
            op = self._deleted_op()
            rc, _ = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op}, "crash_at": stage})
            self.assertEqual(rc, 97)
            rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op}})
            self.assertIn("state=conflict", out["out"], stage)
            rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op}})
            self.assertIn("state=conflict", out["out"], stage)                # sticky: never a second replacement
            made = [l for l in self.fake().labels.values() if l["name"] == "Crashy"]
            self.assertEqual(len(made), 0 if stage == "undo-delete-after-prepared" else 1)

    def test_undo_delete_resumes_from_recorded_replacement_and_chunk_progress(self):
        op = self._deleted_op()
        rc, _ = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op},
                                    "crash_at": "undo-delete-after-replacement-recorded"})
        self.assertEqual(rc, 97)
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op},
                                      "crash_at": "undo-delete-after-chunk"})
        self.assertEqual(rc, 97)
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op}})
        self.assertIn("state=undone", out["out"])
        self.assertIn("accepted=3", out["out"])
        f = self.fake()
        made = [l for l in f.labels.values() if l["name"] == "Crashy"]
        self.assertEqual(len(made), 1)                                       # exactly one replacement
        self.assertEqual(len(f.members(made[0]["id"])), 3)

    def test_recorded_replacement_missing_or_replaced_is_a_conflict(self):
        op = self._deleted_op()
        worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op},
                            "crash_at": "undo-delete-after-replacement-recorded"})
        f = self.fake()
        rid = [l["id"] for l in f.labels.values() if l["name"] == "Crashy"][0]
        f.labels[rid]["name"] = "Hijacked"
        f.save()
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op}})
        self.assertIn("state=conflict", out["out"])
        del f.labels[rid]
        f.save()
        rc, out = worker(self.state, {"fn": "undo_label_change", "args": {"operation_id": op}})
        self.assertIn("state=conflict", out["out"])
        self.assertEqual([l for l in self.fake().labels.values() if l["name"] == "Crashy"], [])

    def test_torn_journal_tail_then_new_operation(self):
        rc, _ = worker(self.state, {"fn": "update_label", "args": {"label": "Crashy", "new_name": "Mid"},
                                    "crash_at": "update-after-remote"})
        code = ("from tests import support; import journal, os\n"
                "s = journal.AdminSession().__enter__()\n"
                "orig = journal.AdminSession._write_all\n"
                "journal.AdminSession._write_all = staticmethod(lambda fd, d: (os.write(fd, d[:7]), os._exit(97)))\n"
                "s.append('APPLIED', list(s.ops)[-1], observed={})\n")
        self.assertEqual(subprocess.run([sys.executable, "-c", code], cwd=support.REPO, timeout=60).returncode, 97)
        rc, out = worker(self.state, {"fn": "update_label", "args": {"label": "Mid", "new_name": "After"}})
        self.assertTrue(out["ok"], out)                                     # sealed; earlier op reconciled first
        with journal.AdminSession() as s:
            outcomes = [o.outcome for o in sorted(s.ops.values(), key=lambda o: o.events[0]["seq"])]
        self.assertEqual(outcomes, ["APPLIED", "APPLIED"])


if __name__ == "__main__":
    unittest.main()
