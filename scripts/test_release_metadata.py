"""Release gates must reject mislabeled or inconsistent publication inputs."""

import json
import tempfile
import unittest
from pathlib import Path

from release_metadata import release_metadata


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.seed("0.3.0b1", "0.3.0-beta.1")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def seed(self, python_version, public_version):
        self.write("scanner/pyproject.toml", f'[project]\nversion = "{python_version}"\n')
        self.write("scanner/src/aegify/__init__.py", f'__version__ = "{python_version}"\n')
        self.write(
            "scanner/uv.lock",
            f'[[package]]\nname = "aegify-sast"\nversion = "{python_version}"\n',
        )
        for directory in ("dashboard", "docs"):
            self.write(f"{directory}/package.json", json.dumps({"version": public_version}))
            self.write(
                f"{directory}/package-lock.json",
                json.dumps(
                    {
                        "version": public_version,
                        "packages": {"": {"version": public_version}},
                    }
                ),
            )
        self.write("dashboard/src/components/sidebar.tsx", f"<p>v{public_version}</p>")
        self.write("dashboard/scripts/scan-worker.mjs", f'version: "{public_version}"')
        self.write(f"docs/releases/v{public_version}.md", "Reviewed release notes")

    def test_beta_remains_prerelease(self):
        result = release_metadata(self.root, "v0.3.0-beta.1")
        self.assertEqual(result["prerelease"], "true")
        self.assertEqual(result["notes"], "docs/releases/v0.3.0-beta.1.md")

    def test_stable_tag_cannot_publish_beta_package(self):
        with self.assertRaisesRegex(ValueError, "Release tag must"):
            release_metadata(self.root, "v0.3.0")

    def test_stable_package_maps_to_stable_tag(self):
        self.seed("0.3.0", "0.3.0")
        self.assertEqual(release_metadata(self.root, "v0.3.0")["prerelease"], "false")

    def test_rejects_drift_in_every_package_and_runtime_surface(self):
        for name in (
            "scanner/src/aegify/__init__.py",
            "scanner/uv.lock",
            "dashboard/package.json",
            "dashboard/package-lock.json",
            "docs/package.json",
            "docs/package-lock.json",
            "dashboard/src/components/sidebar.tsx",
            "dashboard/scripts/scan-worker.mjs",
        ):
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_text()
                path.write_text(original.replace("0.3.0", "0.2.0"))
                with self.assertRaises(ValueError):
                    release_metadata(self.root)
                path.write_text(original)

    def test_requires_reviewed_notes(self):
        (self.root / "docs/releases/v0.3.0-beta.1.md").unlink()
        with self.assertRaisesRegex(ValueError, "Missing reviewed release notes"):
            release_metadata(self.root)

    def test_rejects_noncanonical_and_pathlike_tags(self):
        for tag in (
            "v0.3.0-beta.1/../../other",
            "v0.3.0-beta.1\nprerelease=false",
            "v0.3.0b1",
        ):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_metadata(self.root, tag)


if __name__ == "__main__":
    unittest.main()
