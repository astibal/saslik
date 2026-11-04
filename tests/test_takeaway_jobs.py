import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from saslik.takeaway_jobs import (cancel_unit, create_job, disk_preflight, job_path,
                                  list_jobs, prune_jobs, prune_workdirs, start_unit,
                                  update_job, work_root)


class TakeawayJobTests(unittest.TestCase):
    def test_job_state_is_persistent_and_ordered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = create_job(root, ["lab1"])
            second = create_job(root, ["default", "demo_two"])
            update_job(root, first["id"], state="done", artifact="bundle.tar.zst")

            jobs = list_jobs(root)

            self.assertEqual(second["id"], jobs[0]["id"])
            self.assertEqual("done", jobs[1]["state"])
            self.assertEqual(0o600, job_path(root, first["id"], "state.json").stat().st_mode & 0o777)

    def test_paths_and_workspace_names_are_not_browser_controlled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                create_job(root, ["../../root"])
            with self.assertRaises(ValueError):
                job_path(root, "../../root", "state.json")
            with self.assertRaises(ValueError):
                job_path(root, "valid-job", "../../secret")

    def test_preflight_blocks_missing_rootfs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()

            result = disk_preflight(root, source)

            self.assertFalse(result["ok"])
            self.assertIn("rootfs", result["errors"][0])

    @patch("saslik.takeaway_jobs.subprocess.run")
    def test_systemd_job_is_background_and_resource_throttled(self, run):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = create_job(root, ["lab1"])

            start_unit(root, job["id"], 1000)

            command = run.call_args.args[0]
            self.assertIn("--property=Nice=15", command)
            self.assertIn("--property=CPUWeight=10", command)
            self.assertIn("--property=IOWeight=10", command)
            self.assertIn("--property=IOSchedulingClass=idle", command)
            self.assertIn("--property=OOMScoreAdjust=500", command)
            self.assertNotIn("--wait", command)

    def test_retention_removes_only_finished_old_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = create_job(root, ["lab1"])
            active = create_job(root, ["lab1"])
            update_job(root, old["id"], state="done", updated_at=1)
            update_job(root, active["id"], state="running", updated_at=1)
            # Rewrite timestamps because update_job always records wall time.
            for job in (old, active):
                path = job_path(root, job["id"], "state.json")
                value = json.loads(path.read_text())
                value["updated_at"] = 1
                path.write_text(json.dumps(value))

            removed = prune_jobs(root, now=10_000, max_age=100)

            self.assertEqual([old["id"]], removed)
            self.assertEqual([active["id"]], [item["id"] for item in list_jobs(root)])

    def test_stale_staging_is_removed_but_unrelated_directories_are_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = work_root(root)
            old = staging / "saslik-takeaway.old"
            unrelated = staging / "something-else"
            old.mkdir(parents=True)
            unrelated.mkdir()
            import os
            os.utime(old, (1, 1))
            os.utime(unrelated, (1, 1))

            removed = prune_workdirs(root, now=10_000, max_age=100)

            self.assertEqual([old.name], removed)
            self.assertFalse(old.exists())
            self.assertTrue(unrelated.exists())

    @patch("saslik.takeaway_jobs.subprocess.run")
    def test_cancelled_job_is_acknowledged_and_not_presented_as_done(self, run):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = create_job(root, ["lab1"])
            update_job(root, job["id"], state="running")

            cancel_unit(root, job["id"])

            state = list_jobs(root)[0]
            self.assertEqual("cancelled", state["state"])
            self.assertTrue(state["acknowledged"])
