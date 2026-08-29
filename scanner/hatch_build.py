"""Hatch build hook for reproducible bundled-rule packaging."""

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Include repository rules in both direct wheels and source distributions."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        del version
        root = Path(self.root)
        candidates = (root.parent / "rules", root / "rules")
        rules = next((candidate for candidate in candidates if candidate.is_dir()), None)
        if rules is None:
            raise FileNotFoundError("Aegify bundled rules directory is missing")

        destination = "rules" if self.target_name == "sdist" else "aegify/bundled_rules"
        build_data["force_include"][str(rules)] = destination
