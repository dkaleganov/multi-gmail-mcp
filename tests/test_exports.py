"""C1/C3/C4 write controls and the section 6 export identity protocol, including the
section 14 export crash and concurrency gates."""
from tests import support  # noqa: F401

import json
import os
import stat
import subprocess
import sys
import threading
import unicodedata
import unittest

import exportfs
import exports
import locks
import names
from tests import messages as M


def make_root(tag: str):
    d = support.scratch(tag)
    os.chmod(d, 0o700)
    return d, exportfs.pin_root("default", str(d))


def target(root, mid="18c0000000000001", sub=()):
    return exports.Target(root=root, alias="alpha", identity=exports.identity_hash("alpha@example.test"),
                          account_ns=exports.account_namespace("alpha", "alpha@example.test"),
                          subfolder=list(sub), message_id=mid)


def req(key, data: bytes, name="file.pdf", kind="attachment", ns="attachments"):
    plan = names.plan_name(name, "fallback.bin", names.sniff(data[:16]))
    return exports.Request(key, kind, ns, plan,
                           lambda fd: exportfs.write_temp(fd, [data], exports.PER_FILE_CAP, expected_size=len(data)),
                           {"n": name})


def run_worker(root_dir, mid, spec, check=True):
    p = subprocess.run([sys.executable, "-m", "tests.export_worker", str(root_dir), mid, json.dumps(spec)],
                       cwd=support.REPO, capture_output=True, text=True, timeout=120)
    if check and p.returncode not in (0, 97):
        raise AssertionError(p.stderr)
    out = [l for l in p.stdout.splitlines() if l.startswith("{")]
    return p.returncode, (json.loads(out[-1]) if out else None)


def manifest(root_dir, mid="18c0000000000001", sub=()):
    ns = exports.account_namespace("alpha", "alpha@example.test")
    p = os.path.join(root_dir, ns, *sub, mid, exports.META_DIR, exports.MANIFEST)
    with open(p) as f:
        return json.load(f)


def msg_dir(root_dir, mid="18c0000000000001", sub=()):
    return os.path.join(root_dir, exports.account_namespace("alpha", "alpha@example.test"), *sub, mid)


class RootPinningTests(unittest.TestCase):
    def test_missing_and_unsafe_roots_disable_only_that_destination(self):
        d = support.scratch("roots")
        self.assertEqual(exportfs.pin_root("x", str(d / "missing")).problem, "destination-missing")
        f = d / "file"
        f.write_text("x")
        self.assertEqual(exportfs.pin_root("x", str(f)).problem, "destination-not-a-directory")
        shared = d / "shared"
        shared.mkdir()
        os.chmod(shared, 0o777)
        self.assertEqual(exportfs.pin_root("x", str(shared)).problem, "destination-shared-writable")
        ok = exportfs.pin_root("x", str(d))
        self.assertTrue(ok.available)

    def test_pinned_root_is_never_reopened_by_path(self):
        d, root = make_root("pinned")
        moved = str(d) + "-moved"
        os.rename(d, moved)                 # the configured path now points nowhere
        os.symlink("/", str(d))             # ...or somewhere hostile
        with exports.ExportSession(target(root), {}) as s:
            res = s.publish([req("k1", M.PDF)])
        self.assertEqual(res[0].state, "saved")
        self.assertTrue(os.path.exists(os.path.join(msg_dir(moved), "attachments", "file.pdf")))
        os.unlink(str(d))

    def test_deleted_root_is_unavailable_not_redirected(self):
        d, root = make_root("deleted")
        os.rmdir(d)
        self.assertEqual(root.check_live(), "destination-removed")
        with self.assertRaises(exports.ManifestError):
            exports.ExportSession(target(root), {}).__enter__()


class WriteControlTests(unittest.TestCase):
    def test_saved_file_mode_quarantine_and_no_exec(self):
        d, root = make_root("mode")
        with exports.ExportSession(target(root), {}) as s:
            r = s.publish([req("k1", M.PDF)])[0]
        st = os.stat(r.path)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        fd = os.open(r.path, os.O_RDONLY)
        try:
            self.assertTrue(exportfs.has_quarantine(fd))
        finally:
            os.close(fd)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(r.path)).st_mode), 0o700)

    def test_symlink_at_every_directory_level_is_refused(self):
        evil = support.scratch("evil-target")
        mid = "18c0000000000002"
        levels = [[exports.account_namespace("alpha", "alpha@example.test")], ["receipts"], [mid],
                  [mid, "attachments"], [mid, exports.META_DIR]]
        for i, _ in enumerate(levels):
            d, root = make_root(f"symlink-{i}")
            chain = [exports.account_namespace("alpha", "alpha@example.test"), "receipts", mid]
            path = d
            plan = {0: chain[:1], 1: chain[:2], 2: chain[:3], 3: chain + ["attachments"], 4: chain + [exports.META_DIR]}[i]
            for comp in plan[:-1]:
                path = path / comp
                path.mkdir(exist_ok=True)
            os.symlink(evil, path / plan[-1])
            with self.assertRaises(exportfs.UnsafePath, msg=f"level {i}"):
                with exports.ExportSession(target(root, mid, ["receipts"]), {}) as s:
                    s.publish([req("k", M.PDF)])
            self.assertEqual(os.listdir(evil), [], f"level {i} wrote through a symlink")

    def test_planted_symlink_or_fifo_at_final_name_is_never_touched(self):
        d, root = make_root("collide")
        with exports.ExportSession(target(root), {}) as s:
            pass
        att = os.path.join(msg_dir(d), "attachments")
        secret = support.scratch("secret") / "secret.txt"
        secret.write_text("do not overwrite")
        os.symlink(secret, os.path.join(att, "file.pdf"))
        os.mkfifo(os.path.join(att, "file (2).pdf"))
        with exports.ExportSession(target(root), {}) as s:
            r = s.publish([req("k1", M.PDF)])[0]
        self.assertEqual(r.state, "saved")
        self.assertEqual(r.name, "file (3).pdf")
        self.assertEqual(secret.read_text(), "do not overwrite")
        self.assertTrue(stat.S_ISFIFO(os.lstat(os.path.join(att, "file (2).pdf")).st_mode))
        self.assertIsNotNone(exportfs.inspect_existing(os.open(att, os.O_RDONLY), "file (2).pdf", 1024))

    def test_fifo_inspection_does_not_block(self):
        d = support.scratch("fifo")
        os.mkfifo(d / "pipe")
        fd = os.open(d, os.O_RDONLY)
        try:
            ex = exportfs.inspect_existing(fd, "pipe", 1024)
        finally:
            os.close(fd)
        self.assertEqual(ex.kind, "non-regular")

    def test_apfs_case_and_normalization_collisions(self):
        d, root = make_root("apfs")
        nfd = unicodedata.normalize("NFD", "Résumé.pdf")
        with exports.ExportSession(target(root), {}) as s:
            r1 = s.publish([req("k1", M.PDF, name="Résumé.pdf")])[0]
            r2 = s.publish([req("k2", M.PDF + b"2", name=nfd)])[0]
            r3 = s.publish([req("k3", M.PDF + b"3", name="RÉSUMÉ.PDF")])[0]
        self.assertEqual(r1.name, "Résumé.pdf")
        self.assertEqual(r2.name, "Résumé (2).pdf")       # NFC'd, and the NFC name is taken
        self.assertEqual(r3.name, "RÉSUMÉ (3).PDF")       # case-insensitive collision
        self.assertEqual(len([n for n in os.listdir(os.path.dirname(r1.path)) if not n.startswith(".")]), 3)

    def test_reserved_metadata_names_cannot_be_hit(self):
        d, root = make_root("reserved")
        with exports.ExportSession(target(root), {}) as s:
            rs = s.publish([req("k1", b"{}", name="manifest.json"), req("k2", b"x", name=".gmail-mcp"),
                            req("k3", b"y", name="../.gmail-mcp/manifest.json")])
        self.assertEqual([r.state for r in rs], ["saved"] * 3)
        m = manifest(d)
        self.assertEqual(m["schema"], exports.SCHEMA)
        self.assertEqual(len(m["entries"]), 3)
        self.assertTrue(all("/attachments/" in r.path for r in rs))

    def test_free_space_and_size_limits(self):
        d, root = make_root("limits")
        big = exports.Request("big", "attachment", "attachments", names.plan_name("b.bin", "b.bin", None),
                              lambda fd: exportfs.write_temp(fd, [b"x" * 1024] * 5, 4096), {})
        orig = exportfs.free_bytes
        exportfs.free_bytes = lambda fd: 10
        try:
            with exports.ExportSession(target(root), {}) as s:
                rs = s.publish([big, req("k2", M.PDF)])
        finally:
            exportfs.free_bytes = orig
        self.assertEqual((rs[0].state, rs[0].code), ("refused", "too-large"))
        self.assertEqual((rs[1].state, rs[1].code), ("failed", "insufficient-space"))
        att = os.path.join(msg_dir(d), "attachments")
        self.assertEqual([n for n in os.listdir(att)], [])     # temps removed, nothing published

    def test_quarantine_failure_leaves_nothing_published(self):
        d, root = make_root("qfail")
        orig = exportfs.set_quarantine

        def boom(fd):
            raise exportfs.QuarantineError("not-verified")

        exportfs.set_quarantine = boom
        try:
            with exports.ExportSession(target(root), {}) as s:
                r = s.publish([req("k1", M.PDF)])[0]
        finally:
            exportfs.set_quarantine = orig
        self.assertEqual((r.state, r.code), ("failed", "quarantine-failed"))
        self.assertEqual(os.listdir(os.path.join(msg_dir(d), "attachments")), [])


class ProtocolTests(unittest.TestCase):
    def test_rerun_is_already_present_and_never_duplicates(self):
        d, root = make_root("rerun")
        for _ in range(3):
            with exports.ExportSession(target(root), {}) as s:
                r = s.publish([req("k1", M.PDF)])[0]
        self.assertEqual(r.state, "already-present")
        self.assertEqual(os.listdir(os.path.join(msg_dir(d), "attachments")), ["file.pdf"])

    def test_modified_file_is_not_trusted_and_not_rewritten(self):
        d, root = make_root("modified")
        with exports.ExportSession(target(root), {}) as s:
            r = s.publish([req("k1", M.PDF)])[0]
        os.chmod(r.path, 0o600)
        with open(r.path, "ab") as f:
            f.write(b"tampered")
        with exports.ExportSession(target(root), {}) as s:
            r2 = s.publish([req("k1", M.PDF)])[0]
        self.assertEqual((r2.state, r2.name), ("saved", "file (2).pdf"))
        with open(r.path, "rb") as f:
            self.assertTrue(f.read().endswith(b"tampered"))
        e = manifest(d)["entries"]["k1"]
        self.assertEqual(e["previous"]["stale_reason"], "modified")

    def test_same_bytes_without_binding_is_not_adopted(self):
        d, root = make_root("orphan-adopt")
        with exports.ExportSession(target(root), {}) as s:
            pass
        att = os.path.join(msg_dir(d), "attachments")
        with open(os.path.join(att, "file.pdf"), "wb") as f:
            f.write(M.PDF)                       # identical bytes, but no durable binding
        with exports.ExportSession(target(root), {}) as s:
            r = s.publish([req("k1", M.PDF)])[0]
        self.assertEqual((r.state, r.name), ("saved", "file (2).pdf"))

    def test_lock_order_is_enforced(self):
        with locks.render_lock(5):
            with self.assertRaises(locks.LockOrderError):
                with locks.message_lock("ab" * 32, 1):
                    pass
        with locks.message_lock("ab" * 32, 5):
            with locks.render_lock(5):
                pass
            with self.assertRaises(locks.LockOrderError):
                with locks.admin_lock(1):
                    pass

    def test_message_lock_excludes_other_processes(self):
        d, root = make_root("lockx")
        t = target(root)
        fd = exportfs.open_dir_chain(root.fd, t.components, create=True)
        key = exports.lock_key_for(fd)
        os.close(fd)
        code = ("from tests import support; import locks, sys; "
                "import time\ntry:\n  locks.message_lock(sys.argv[1], 0.3).__enter__(); print('got')\n"
                "except locks.LockTimeout:\n  print('timeout')")
        with locks.message_lock(key, 5):
            out = subprocess.run([sys.executable, "-c", code, key], cwd=support.REPO, capture_output=True,
                                 text=True, timeout=60).stdout.strip()
        self.assertEqual(out, "timeout")


class CrashGateTests(unittest.TestCase):
    """Crash before and after the artifact intent, the final link, and manifest completion."""

    def _spec(self, crash_at=None, key="k1"):
        return {"items": [{"key": key, "kind": "attachment", "namespace": "attachments", "name": "receipt.pdf",
                           "data": M.PDF.hex()}], "crash_at": crash_at}

    def _after_recovery(self, d, mid):
        rc, out = run_worker(d, mid, self._spec())
        self.assertEqual(rc, 0)
        return out

    def test_crash_after_temp_before_intent(self):
        d, root = make_root("crash-temp")
        mid = "18c00000000000c1"
        rc, _ = run_worker(d, mid, self._spec("after-temp"))
        self.assertEqual(rc, 97)
        out = self._after_recovery(d, mid)
        self.assertEqual(out["results"][0]["state"], "saved")
        self.assertEqual(out["orphans"], 1)            # the unbound temp is reported, never adopted
        names_ = os.listdir(os.path.join(msg_dir(d, mid), "attachments"))
        self.assertIn("receipt.pdf", names_)
        self.assertEqual(sum(1 for n in names_ if n.startswith(".tmp-")), 1)

    def test_crash_after_intent_before_link(self):
        d, root = make_root("crash-intent")
        mid = "18c00000000000c2"
        rc, _ = run_worker(d, mid, self._spec("after-intent"))
        self.assertEqual(rc, 97)
        self.assertEqual(manifest(d, mid)["entries"]["k1"]["state"], "intent")
        out = self._after_recovery(d, mid)
        self.assertEqual(out["recovered"], 1)           # published from the verified temp
        self.assertEqual(out["results"][0]["state"], "already-present")
        self.assertEqual(os.listdir(os.path.join(msg_dir(d, mid), "attachments")), ["receipt.pdf"])

    def test_crash_after_link_before_completion(self):
        d, root = make_root("crash-link")
        mid = "18c00000000000c3"
        rc, _ = run_worker(d, mid, self._spec("after-link"))
        self.assertEqual(rc, 97)
        self.assertEqual(manifest(d, mid)["entries"]["k1"]["state"], "intent")
        out = self._after_recovery(d, mid)
        self.assertEqual(out["recovered"], 1)           # final file verified against the intent
        self.assertEqual(out["results"][0]["state"], "already-present")
        self.assertEqual(manifest(d, mid)["entries"]["k1"]["state"], "complete")

    def test_crash_after_completion(self):
        d, root = make_root("crash-complete")
        mid = "18c00000000000c4"
        rc, _ = run_worker(d, mid, self._spec("after-complete"))
        self.assertEqual(rc, 97)
        out = self._after_recovery(d, mid)
        self.assertEqual((out["recovered"], out["results"][0]["state"]), (0, "already-present"))

    def test_intent_whose_final_name_was_replaced_is_a_conflict(self):
        d, root = make_root("crash-conflict")
        mid = "18c00000000000c5"
        run_worker(d, mid, self._spec("after-link"))
        with open(os.path.join(msg_dir(d, mid), "attachments", "receipt.pdf"), "r+b") as f:
            f.write(b"X")
        out = self._after_recovery(d, mid)
        self.assertEqual(out["conflicts"], 1)
        self.assertEqual(out["results"][0]["state"], "saved")
        self.assertEqual(out["results"][0]["name"], "receipt (2).pdf")
        self.assertEqual(manifest(d, mid)["entries"]["k1"]["previous"]["state"], "conflict")

    def test_lost_temp_after_intent_regenerates_under_the_same_name(self):
        d, root = make_root("crash-lost-temp")
        mid = "18c00000000000c6"
        run_worker(d, mid, self._spec("after-intent"))
        att = os.path.join(msg_dir(d, mid), "attachments")
        for n in os.listdir(att):
            os.unlink(os.path.join(att, n))
        out = self._after_recovery(d, mid)
        self.assertEqual((out["results"][0]["state"], out["results"][0]["name"]), ("saved", "receipt.pdf"))


class ConcurrencyGateTests(unittest.TestCase):
    def test_same_nondeterministic_key_from_two_processes(self):
        d, root = make_root("concurrent-same")
        mid = "18c00000000000d1"
        spec = {"items": [{"key": "pdf-key", "kind": "pdf", "namespace": "views", "name": "view.pdf",
                           "data": None, "random": 4096, "sleep": 0.5}]}
        procs = [subprocess.Popen([sys.executable, "-m", "tests.export_worker", str(d), mid, json.dumps(spec)],
                                  cwd=support.REPO, stdout=subprocess.PIPE, text=True) for _ in range(2)]
        outs = [json.loads(p.communicate(timeout=120)[0].strip().splitlines()[-1]) for p in procs]
        states = sorted(o["results"][0]["state"] for o in outs)
        self.assertEqual(states, ["already-present", "saved"])
        self.assertEqual([n for n in os.listdir(os.path.join(msg_dir(d, mid), "views"))], ["view.pdf"])
        self.assertEqual(list(manifest(d, mid)["entries"]), ["pdf-key"])
        self.assertEqual(outs[0]["results"][0]["sha256"], outs[1]["results"][0]["sha256"])

    def test_different_keys_from_two_processes_drop_no_entry(self):
        d, root = make_root("concurrent-diff")
        mid = "18c00000000000d2"
        specs = [{"items": [{"key": f"k{i}", "kind": "attachment", "namespace": "attachments",
                             "name": "same-name.bin", "data": None, "random": 1000 + i, "sleep": 0.3}]} for i in range(4)]
        procs = [subprocess.Popen([sys.executable, "-m", "tests.export_worker", str(d), mid, json.dumps(s)],
                                  cwd=support.REPO, stdout=subprocess.PIPE, text=True) for s in specs]
        for p in procs:
            p.communicate(timeout=120)
        m = manifest(d, mid)
        self.assertEqual(sorted(m["entries"]), ["k0", "k1", "k2", "k3"])
        self.assertTrue(all(e["state"] == "complete" for e in m["entries"].values()))
        self.assertEqual(len({e["name"] for e in m["entries"].values()}), 4)


if __name__ == "__main__":
    unittest.main()
