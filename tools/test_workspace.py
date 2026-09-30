"""Regression tests for the workspace tool sandbox. Run: python3 tools/test_workspace.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import workspace_server as ws  # noqa: E402


class SandboxTests(unittest.TestCase):
    def test_reads_inside_sandbox(self):
        self.assertIn("Quarterly", ws.run_shell("cat notes.txt"))

    def test_rejects_parent_traversal(self):
        for cmd in ("cat ../../.env", "cat ../common.py", "ls ..", "ls ../.."):
            self.assertIn("outside the workspace sandbox", ws.run_shell(cmd), cmd)

    def test_rejects_absolute_paths(self):
        for cmd in ("cat /etc/passwd", "cat /proc/self/environ", "ls /"):
            self.assertIn("outside the workspace sandbox", ws.run_shell(cmd), cmd)

    def test_rejects_unlisted_commands(self):
        for cmd in ("rm -rf .", "curl http://x", "sh -c ls", "python3 -V"):
            self.assertIn("rejected", ws.run_shell(cmd), cmd)

    def test_read_file_confined(self):
        self.assertIn("SIMULATED", ws.read_file("../../etc/passwd"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
