#!/usr/bin/env python3
"""Reference tests for stale staging cleanup policy; not Objective-C execution tests."""
import pathlib, tempfile, time, unittest

MARKER=".applesigner-staging-marker"
PREFIX="AppleSigner-Unpacked-"

def cleanup(parent, age_seconds, now=None):
    now=now or time.time()
    removed=[]
    for item in pathlib.Path(parent).iterdir():
        if not item.name.startswith(PREFIX) or not item.is_dir() or item.is_symlink():
            continue
        marker=item/MARKER
        if not marker.is_file():
            continue
        if marker.read_text() != item.name[len(PREFIX):]:
            continue
        if now-item.stat().st_mtime < age_seconds:
            continue
        import shutil
        shutil.rmtree(item)
        removed.append(item.name)
    return removed

class StaleCleanupTests(unittest.TestCase):
    def test_old_marked_directory_removed(self):
        with tempfile.TemporaryDirectory() as parent:
            d=pathlib.Path(parent)/(PREFIX+"11111111-1111-4111-8111-111111111111"); d.mkdir()
            (d/MARKER).write_text("11111111-1111-4111-8111-111111111111")
            old=time.time()-90000
            import os; os.utime(d,(old,old))
            self.assertEqual(cleanup(parent,86400),[d.name])

    def test_recent_marked_directory_kept(self):
        with tempfile.TemporaryDirectory() as parent:
            d=pathlib.Path(parent)/(PREFIX+"22222222-2222-4222-8222-222222222222"); d.mkdir()
            (d/MARKER).write_text("22222222-2222-4222-8222-222222222222")
            self.assertEqual(cleanup(parent,86400),[])
            self.assertTrue(d.exists())

    def test_mismatched_marker_kept(self):
        with tempfile.TemporaryDirectory() as parent:
            d=pathlib.Path(parent)/(PREFIX+"33333333-3333-4333-8333-333333333333"); d.mkdir()
            (d/MARKER).write_text("different-token")
            self.assertEqual(cleanup(parent,0),[])
            self.assertTrue(d.exists())

    def test_unmarked_directory_kept(self):
        with tempfile.TemporaryDirectory() as parent:
            d=pathlib.Path(parent)/(PREFIX+"44444444-4444-4444-8444-444444444444"); d.mkdir()
            (d/"important.txt").write_text("keep")
            self.assertEqual(cleanup(parent,0),[])
            self.assertTrue((d/"important.txt").exists())

    def test_unrelated_directory_kept(self):
        with tempfile.TemporaryDirectory() as parent:
            d=pathlib.Path(parent)/"Unpacked"; d.mkdir()
            (d/MARKER).write_text("not ours")
            self.assertEqual(cleanup(parent,0),[])
            self.assertTrue(d.exists())

if __name__=="__main__":
    unittest.main(verbosity=2)
