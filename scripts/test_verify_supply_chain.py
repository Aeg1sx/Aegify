"""Guard coordinated updates that previously failed dependency PR CI."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_supply_chain as policy


class CoordinatedVersions(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / "scanner").mkdir()
        (self.root / "scanner/pyproject.toml").write_text('[tool.uv]\nrequired-version = "==0.12.17"\n')
        self.workflow = self.root / "action.yml"
        self.workflow.write_text(f'uses: astral-sh/setup-uv@{"a" * 40}\n  with:\n    version: "0.12.17"\n')
        self.image = self.root / "scanner/Dockerfile"
        self.image.write_text(f'FROM ghcr.io/astral-sh/uv:0.12.17@sha256:{"a" * 64}\n')
        self.patch_root = patch.object(policy, "ROOT", self.root)
        self.patch_root.start()
        self.addCleanup(self.patch_root.stop)

    def test_matching_uv_versions(self):
        errors = []
        policy.verify_uv_versions(errors)
        self.assertEqual(errors, [])

    def test_docker_and_ci_drift_are_rejected(self):
        self.image.write_text(self.image.read_text().replace("0.12.17", "0.12.9"))
        self.workflow.write_text(self.workflow.read_text().replace("0.12.17", "0.12.9"))
        errors = []
        policy.verify_uv_versions(errors)
        self.assertEqual(len(errors), 2)

    def test_all_codeql_steps_share_one_revision(self):
        self.workflow.write_text(f'uses: github/codeql-action/init@{"a" * 40}\n')
        other = self.root / ".github/workflows/code-scanning.yml"
        other.write_text(f'uses: github/codeql-action/analyze@{"b" * 40}\n')
        errors = []
        policy.verify_actions(errors)
        self.assertEqual(len(errors), 1)
        self.assertIn("same action revision", errors[0])
        other.write_text(other.read_text().replace("b" * 40, "a" * 40))
        errors = []
        policy.verify_actions(errors)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
