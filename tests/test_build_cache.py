import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.build_cache import (CachePolicy, cache_lock, clean_build_cache,
                                mark_entry, prune_build_cache)


class BuildCacheTests(unittest.TestCase):
    def test_prune_uses_shorter_staging_ttl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / "staging/old"
            bootstrap = root / "bootstrap/base"
            mark_entry(staging, "staging", now=100)
            mark_entry(bootstrap, "bootstrap", now=100)

            report = prune_build_cache(root, now=100 + 3 * 24 * 60 * 60)

            self.assertEqual(1, report.removed_entries)
            self.assertFalse(staging.exists())
            self.assertTrue(bootstrap.exists())

    def test_dry_run_reports_without_removing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = root / "bootstrap/base"
            mark_entry(entry, "bootstrap", now=10)
            (entry / "rootfs.tar").write_bytes(b"payload")

            report = prune_build_cache(root, now=10 + 8 * 24 * 60 * 60,
                                       dry_run=True)

            self.assertEqual(1, report.removed_entries)
            self.assertGreater(report.reclaimed_bytes, 0)
            self.assertTrue(entry.exists())

    def test_size_limit_evicts_oldest_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "bootstrap/old"
            new = root / "bootstrap/new"
            mark_entry(old, "bootstrap", now=100)
            mark_entry(new, "bootstrap", now=200)
            (old / "rootfs.tar").write_bytes(b"a" * 100)
            (new / "rootfs.tar").write_bytes(b"b" * 100)

            prune_build_cache(root, now=300,
                              policy=CachePolicy(reusable_ttl=1000, size_limit=200))

            self.assertFalse(old.exists())
            self.assertTrue(new.exists())

    def test_busy_cache_is_never_pruned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = root / "staging/build"
            mark_entry(entry, "staging", now=1)
            with cache_lock(root, blocking=False) as acquired:
                self.assertTrue(acquired)
                report = prune_build_cache(root, now=10 * 24 * 60 * 60)
            self.assertTrue(report.busy)
            self.assertTrue(entry.exists())

    def test_clean_removes_only_managed_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "apt/archives").mkdir(parents=True)
            (root / "apt/archives/pkg.deb").write_bytes(b"deb")
            (root / "unmanaged").write_text("keep", encoding="utf-8")

            clean_build_cache(root)

            self.assertFalse((root / "apt").exists())
            self.assertTrue((root / "unmanaged").exists())


if __name__ == "__main__":
    unittest.main()
