"""Journal durability and replay gates (PLAN-v4 5.8): torn tail followed by a new
operation, corruption in the prefix, symlinks, seal failure, rotation, the host-wide
admin lock across processes, and fail-closed writes."""
from tests import support  # noqa: F401

import json
import os
import subprocess
import sys
import unittest

import journal
import runtime


def jdir():
    return runtime.private_dir("label-journal")


def wipe():
    d = jdir()
    for n in os.listdir(d):
        os.unlink(d / n)


def enter_expect_failure(**kw):
    """Open a session that is expected to fail; if it unexpectedly opens, release it."""
    s = journal.AdminSession(**kw)
    s.__enter__()
    s.__exit__(None, None, None)


def segs():
    return sorted(n for n in os.listdir(jdir()) if n.startswith("seg-"))


class JournalTests(unittest.TestCase):
    def setUp(self):
        wipe()

    def tearDown(self):
        wipe()
        support.assert_isolated(self)

    def _two_ops(self):
        with journal.AdminSession() as s:
            a, b = journal.new_op_id(), journal.new_op_id()
            s.append("PREPARED", a, kind="update", label_id="Label_1", account_id="a" * 64)
            s.append("APPLIED", a, observed={"name": "x"})
            s.append("PREPARED", b, kind="delete", label_id="Label_2", account_id="a" * 64, members=["18c0"])
        return a, b

    def test_replay_restores_state_and_files_are_private(self):
        a, b = self._two_ops()
        with journal.AdminSession() as s:
            self.assertEqual(s.op(a).outcome, "APPLIED")
            self.assertTrue(s.op(b).unresolved)
            self.assertEqual(s.seq, 4)
        st = os.stat(jdir() / segs()[0])
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(jdir()).st_mode & 0o777, 0o700)

    def test_torn_tail_from_a_real_crash_then_a_new_operation(self):
        a, b = self._two_ops()
        code = ("from tests import support; import journal, os\n"
                "orig = journal.AdminSession._write_all\n"
                "def half(fd, data):\n"
                "    os.write(fd, data[: len(data) // 2]); os.fsync(fd); os._exit(97)\n"
                "journal.AdminSession._write_all = staticmethod(half)\n"
                "s = journal.AdminSession().__enter__()\n"
                "s.append('APPLIED', %r, observed={})\n" % b)
        rc = subprocess.run([sys.executable, "-c", code], cwd=support.REPO, timeout=60).returncode
        self.assertEqual(rc, 97)
        torn_name = segs()[-1]
        torn_bytes = (jdir() / torn_name).read_bytes()
        self.assertFalse(torn_bytes.endswith(b"\n"))
        with journal.AdminSession() as s:
            self.assertTrue(s.sealed_on_entry)
            self.assertTrue(s.op(b).unresolved)          # the torn APPLIED is NOT a recovery instruction
            c = journal.new_op_id()
            s.append("PREPARED", c, kind="update", label_id="Label_3", account_id="a" * 64)
        self.assertEqual((jdir() / torn_name).read_bytes(), torn_bytes)   # sealed segment unchanged
        self.assertEqual(len(segs()), 2)
        with journal.AdminSession() as s:                # the whole history still validates
            self.assertFalse(s.sealed_on_entry)
            self.assertIn(c, s.ops)
            self.assertTrue(s.op(b).unresolved)
            hdr = json.loads((jdir() / segs()[1]).read_bytes().split(b"\n")[0])
            self.assertEqual(hdr["pred"], torn_name)
            self.assertEqual(hdr["pred_valid_bytes"], len(torn_bytes) - len(torn_bytes.split(b"\n")[-1]))

    def test_invalid_record_in_the_middle_refuses_administration(self):
        self._two_ops()
        p = jdir() / segs()[0]
        lines = p.read_bytes().split(b"\n")
        self.assertIn(b'"Label_1"', lines[1])
        lines[1] = lines[1].replace(b'"Label_1"', b'"Label_9"')       # checksum no longer matches
        p.write_bytes(b"\n".join(lines))
        with self.assertRaises(journal.JournalError) as cm:
            enter_expect_failure()
        self.assertEqual(cm.exception.code, "journal-corrupt")

    def test_sequence_gap_and_missing_segment_refuse(self):
        self._two_ops()
        p = jdir() / segs()[0]
        lines = p.read_bytes().split(b"\n")
        del lines[2]
        p.write_bytes(b"\n".join(lines))
        with self.assertRaises(journal.JournalError):
            enter_expect_failure()
        wipe()
        self._two_ops()
        os.rename(jdir() / segs()[0], jdir() / "seg-000002.jsonl")
        with self.assertRaises(journal.JournalError):
            enter_expect_failure()

    def test_symlinked_segment_is_refused(self):
        self._two_ops()
        real = jdir() / segs()[0]
        moved = support.scratch("seg") / "elsewhere.jsonl"
        os.rename(real, moved)
        os.symlink(moved, real)
        with self.assertRaises(journal.JournalError) as cm:
            enter_expect_failure()
        self.assertEqual(cm.exception.code, "journal-unreadable")

    def test_seal_failure_refuses_administration(self):
        self._two_ops()
        p = jdir() / segs()[0]
        with open(p, "ab") as f:
            f.write(b'{"v":1,"seq":5,"ty')                      # torn tail
        orig = journal.AdminSession._new_segment

        def cannot_create(self, pred):
            raise OSError("no space")                               # sealing cannot create a segment

        journal.AdminSession._new_segment = cannot_create
        try:
            with self.assertRaises(journal.JournalError) as cm:
                enter_expect_failure()
            self.assertEqual(cm.exception.code, "journal-recovery-failed")
        finally:
            journal.AdminSession._new_segment = orig
        with journal.AdminSession() as s:                          # recovery completes once possible
            self.assertTrue(s.sealed_on_entry)

    def test_write_failure_stops_further_appends(self):
        with journal.AdminSession() as s:
            orig = journal.AdminSession.__dict__["_write_all"]     # the staticmethod descriptor itself

            def boom(fd, data):
                raise OSError("disk full")

            journal.AdminSession._write_all = staticmethod(boom)
            try:
                with self.assertRaises(journal.JournalError):
                    s.append("PREPARED", journal.new_op_id(), kind="update", label_id="Label_1", account_id="a" * 64)
            finally:
                journal.AdminSession._write_all = orig
            with self.assertRaises(journal.JournalError):
                s.append("PREPARED", journal.new_op_id(), kind="update", label_id="Label_1", account_id="a" * 64)

    def test_rotation_keeps_every_record(self):
        orig = journal.SEGMENT_MAX
        journal.SEGMENT_MAX = 2048
        try:
            ids = []
            with journal.AdminSession() as s:
                for i in range(30):
                    op = journal.new_op_id()
                    ids.append(op)
                    s.append("PREPARED", op, kind="update", label_id=f"Label_{i}", account_id="a" * 64, pad="x" * 100)
        finally:
            journal.SEGMENT_MAX = orig
        self.assertGreater(len(segs()), 2)
        with journal.AdminSession() as s:
            self.assertEqual(sorted(s.ops), sorted(ids))

    def test_admin_lock_is_host_wide_and_appends_never_interleave(self):
        code = ("from tests import support; import journal, sys, time\n"
                "for _ in range(15):\n"
                "    with journal.AdminSession(timeout=60) as s:\n"
                "        op = journal.new_op_id()\n"
                "        s.append('PREPARED', op, kind='update', label_id='Label_1', account_id='a'*64)\n"
                "        time.sleep(0.01)\n"
                "        s.append('APPLIED', op, observed={})\n")
        procs = [subprocess.Popen([sys.executable, "-c", code], cwd=support.REPO) for _ in range(3)]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0)
        with journal.AdminSession() as s:
            self.assertEqual(len(s.ops), 45)
            self.assertTrue(all(o.outcome == "APPLIED" for o in s.ops.values()))
        holder = subprocess.Popen([sys.executable, "-c", "from tests import support; import journal, time\n"
                                   "with journal.AdminSession():\n    print('in', flush=True); time.sleep(3)"],
                                  cwd=support.REPO, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), "in")
        with self.assertRaises(journal.JournalError) as cm:
            enter_expect_failure(timeout=0.5)
        self.assertEqual(cm.exception.code, "admin-busy")
        holder.wait(timeout=30)
        holder.stdout.close()


if __name__ == "__main__":
    unittest.main()
