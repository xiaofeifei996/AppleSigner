#!/usr/bin/env python3
"""Reference tests for AppleSigner 1.30.0 transactional extraction policy.

These tests model the transaction contract and do not execute Objective-C.
"""
import pathlib
import tempfile
import unittest
import shutil

def transaction_extract(parent, entries, fail_after=None):
    staging = pathlib.Path(tempfile.mkdtemp(prefix="AppleSigner-Unpacked-", dir=parent))
    try:
        for index, (relative, payload) in enumerate(entries):
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            if fail_after is not None and index == fail_after:
                raise OSError("simulated write failure")
        return staging
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

class TransactionTests(unittest.TestCase):
    def test_success_keeps_completed_staging_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            result=transaction_extract(parent,[("Payload/A",b"a"),("Payload/B",b"b")])
            self.assertTrue(result.is_dir())
            self.assertEqual((result/"Payload/A").read_bytes(),b"a")

    def test_failure_rolls_back_partial_staging_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            with self.assertRaises(OSError):
                transaction_extract(parent,[("Payload/A",b"a"),("Payload/B",b"b")],fail_after=0)
            self.assertEqual(list(pathlib.Path(parent).glob("AppleSigner-Unpacked-*")),[])

    def test_empty_transaction_has_no_partial_output(self):
        with tempfile.TemporaryDirectory() as parent:
            with self.assertRaises(OSError):
                transaction_extract(parent,[("Payload/A",b"a")],fail_after=0)
            self.assertEqual(list(pathlib.Path(parent).glob("AppleSigner-Unpacked-*")),[])

    def test_file_directory_prefix_conflict(self):
        existing={"payload/a": False}  # False means regular file.
        candidate="payload/a/b"
        self.assertTrue(any(candidate.startswith(p+"/") and not is_dir
                            for p,is_dir in existing.items()))

    def test_normal_directory_parent_is_allowed(self):
        existing={"payload/demo.app": True}
        candidate="payload/demo.app/info.plist"
        self.assertFalse(any(candidate.startswith(p+"/") and not is_dir
                             for p,is_dir in existing.items()))

if __name__ == "__main__":
    unittest.main(verbosity=2)
