"""Regression cases for empty, incomplete and misleading release inventories."""

import copy
import unittest

from verify_sbom import verify_sbom


class VerifySbomTests(unittest.TestCase):
    def setUp(self):
        self.project = {"name": "app", "version": "1.0"}
        self.lock = {
            "package": [
                {
                    **self.project,
                    "source": {"editable": "."},
                    "dependencies": [{"name": "direct"}],
                    "optional-dependencies": {
                        "storage": [{"name": "optional", "extra": ["binary"]}]
                    },
                    "dev-dependencies": {"dev": [{"name": "dev"}]},
                }
            ]
        }
        root = {**self.project, "type": "library", "bom-ref": "root"}
        self.bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": root},
            "components": [],
            "dependencies": [{"ref": "root", "dependsOn": ["direct", "optional", "dev"]}],
        }
        for name in ("direct", "transitive", "optional", "binary", "dev"):
            url = f"https://example.test/{name}-1.0.whl"
            self.lock["package"].append(
                {
                    "name": name,
                    "version": "1.0",
                    "source": {"registry": "https://pypi.org/simple"},
                    "wheels": [{"url": url, "hash": "sha256:" + "a" * 64}],
                }
            )
            self.bom["components"].append(
                {
                    "name": name,
                    "version": "1.0",
                    "bom-ref": name,
                    "purl": f"pkg:pypi/{name}@1.0",
                    "externalReferences": [
                        {
                            "type": "distribution",
                            "url": url,
                            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                        }
                    ],
                }
            )
            self.bom["dependencies"].append({"ref": name})
        self.lock["package"][1]["dependencies"] = [
            {"name": "transitive", "marker": "sys_platform == 'win32'"}
        ]
        self.bom["dependencies"][1]["dependsOn"] = ["transitive"]
        self.lock["package"][3]["optional-dependencies"] = {"binary": [{"name": "binary"}]}
        self.bom["dependencies"][3]["dependsOn"] = ["binary"]

    def verify(self):
        return verify_sbom(self.bom, self.lock, self.project)

    def test_includes_transitive_optional_development_and_platform_dependencies(self):
        self.assertEqual(self.verify(), (5, 5))

    def test_rejects_original_directory_only_sbom(self):
        self.bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "file", "name": "scanner/dist"}},
        }
        with self.assertRaisesRegex(ValueError, "project version"):
            self.verify()

    def test_rejects_empty_inventory(self):
        self.bom["components"] = []
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.verify()

    def test_rejects_each_missing_package_and_wrong_version(self):
        original = copy.deepcopy(self.bom)
        for index in range(len(original["components"])):
            for mutation in ("missing", "version"):
                with self.subTest(index=index, mutation=mutation):
                    self.bom = copy.deepcopy(original)
                    if mutation == "missing":
                        self.bom["components"].pop(index)
                    else:
                        self.bom["components"][index]["version"] = "2.0"
                    with self.assertRaisesRegex(ValueError, "inventory"):
                        self.verify()

    def test_rejects_wrong_root_version(self):
        self.bom["metadata"]["component"]["version"] = "2.0"
        with self.assertRaisesRegex(ValueError, "project version"):
            self.verify()

    def test_rejects_missing_or_wrong_purl(self):
        for purl in (None, "pkg:pypi/wrong@1.0"):
            self.bom["components"][0]["purl"] = purl
            with self.assertRaisesRegex(ValueError, "package URL"):
                self.verify()

    def test_rejects_missing_and_tampered_artifact_hashes(self):
        reference = self.bom["components"][0]["externalReferences"][0]
        for hashes in ([], [{"alg": "SHA-256", "content": "b" * 64}]):
            reference["hashes"] = hashes
            with self.assertRaisesRegex(ValueError, "hashes differ"):
                self.verify()

    def test_rejects_partial_graph_and_missing_edges(self):
        original = copy.deepcopy(self.bom)
        for index in range(len(original["dependencies"])):
            self.bom = copy.deepcopy(original)
            self.bom["dependencies"].pop(index)
            with self.subTest(node=index), self.assertRaisesRegex(ValueError, "graph nodes"):
                self.verify()
        for index in (0, 1, 3):
            self.bom = copy.deepcopy(original)
            self.bom["dependencies"][index]["dependsOn"].pop()
            with self.subTest(edge=index), self.assertRaisesRegex(ValueError, "edges differ"):
                self.verify()

    def test_rejects_dangling_and_duplicate_refs(self):
        self.bom["dependencies"][0]["dependsOn"].append("missing")
        with self.assertRaisesRegex(ValueError, "Dangling"):
            self.verify()
        self.bom["dependencies"][0]["dependsOn"].pop()
        self.bom["components"][0]["bom-ref"] = "root"
        with self.assertRaisesRegex(ValueError, "BOM refs"):
            self.verify()

    def test_rejects_duplicate_components_and_nodes(self):
        self.bom["components"].append(self.bom["components"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate SBOM"):
            self.verify()
        self.bom["components"].pop()
        self.bom["dependencies"].append(self.bom["dependencies"][0])
        with self.assertRaisesRegex(ValueError, "duplicate dependency node"):
            self.verify()

    def test_rejects_unverified_source_types(self):
        self.lock["package"][1]["source"] = {"git": "https://example.test/direct.git"}
        with self.assertRaisesRegex(ValueError, "Unsupported package source"):
            self.verify()

    def test_preserves_multiple_locked_versions_and_conditional_edges(self):
        alternate = copy.deepcopy(self.lock["package"][2])
        alternate["version"] = "2.0"
        self.lock["package"].append(alternate)
        component = copy.deepcopy(self.bom["components"][1])
        component.update(
            version="2.0", **{"bom-ref": "transitive-v2", "purl": "pkg:pypi/transitive@2.0"}
        )
        self.bom["components"].append(component)
        self.bom["dependencies"].append({"ref": "transitive-v2"})
        dependencies = self.lock["package"][1]["dependencies"]
        dependencies[0]["version"] = "1.0"
        dependencies.append(
            {"name": "transitive", "version": "2.0", "marker": "sys_platform != 'win32'"}
        )
        self.bom["dependencies"][1]["dependsOn"].append("transitive-v2")
        self.assertEqual(self.verify(), (6, 6))
        dependencies[0].pop("version")
        with self.assertRaisesRegex(ValueError, "ambiguous dependency"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
