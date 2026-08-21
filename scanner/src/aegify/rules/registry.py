"""Rule loading and initialization."""

from __future__ import annotations

import logging
from pathlib import Path

from aegify.rules.base import RuleRegistry, get_registry

logger = logging.getLogger(__name__)


def load_builtin_rules() -> RuleRegistry:
    """Load all built-in security rules and return the registry.

    Importing the rule modules triggers rule registration via register_rule() calls.
    Also auto-loads YAML rules from the bundled rules/ directory.
    """
    import aegify.rules.command_injection  # noqa: F401
    import aegify.rules.idor  # noqa: F401
    import aegify.rules.path_traversal  # noqa: F401
    import aegify.rules.sql_injection  # noqa: F401
    import aegify.rules.xss  # noqa: F401

    # Auto-load bundled YAML rules from scanner/rules/ directory
    _load_bundled_yaml_rules()

    return get_registry()


def load_custom_rules(path: str | Path) -> int:
    """Load custom YAML rules from a file or directory.

    Returns the number of rules loaded.
    """
    from aegify.rules.yaml_rule import load_and_register_yaml_rules

    rules_path = Path(path)
    if not rules_path.exists():
        logger.warning("Custom rules path does not exist: %s", rules_path)
        return 0

    return load_and_register_yaml_rules(rules_path)


def _load_bundled_yaml_rules() -> int:
    """Load bundled YAML rules from the package or project rules/ directory.

    Resolution order:
    1. Bundled rules inside installed package (aegify/bundled_rules/)
    2. Development mode: rules/ relative to package source tree
    3. Development mode: rules/ relative to working directory
    4. Development mode: rules/ one level up from working directory
    """
    from aegify.rules.yaml_rule import load_and_register_yaml_rules

    # Priority 1: Bundled rules inside installed package
    bundled_dir = Path(__file__).resolve().parent.parent / "bundled_rules"
    if bundled_dir.exists():
        count = load_and_register_yaml_rules(bundled_dir)
        if count > 0:
            logger.info("Loaded %d bundled YAML rules from %s", count, bundled_dir)
        return count

    # Priority 2+: Development mode fallbacks
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "rules",
        Path.cwd() / "rules",
        Path.cwd().parent / "rules",
    ]
    for rules_dir in candidates:
        if rules_dir.exists():
            count = load_and_register_yaml_rules(rules_dir)
            if count > 0:
                logger.info("Loaded %d bundled YAML rules from %s", count, rules_dir)
            return count

    return 0
