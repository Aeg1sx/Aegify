"""Resolve changed and related files for PR-focused scanning."""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from aegify.models import FileAST

logger = logging.getLogger(__name__)

# File extensions the scanner supports
SUPPORTED_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".kt",
        ".swift",
        ".rs",
    }
)


class DiffResolver:
    """Discovers changed files and their related dependencies for PR scanning."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()

    def get_changed_files(
        self,
        base_ref: str | None = None,
        explicit_files: list[str] | None = None,
    ) -> list[Path]:
        """Get the list of changed files for this PR.

        Resolution order:
        1. Explicit file list (--changed-files CLI option)
        2. GITHUB_BASE_SHA environment variable (GitHub Actions)
        3. Git merge-base against origin/main
        """
        if explicit_files:
            return self._resolve_explicit(explicit_files)

        ref = base_ref or os.environ.get("GITHUB_BASE_SHA")
        if not ref:
            ref = self._detect_base_ref()

        if not ref:
            logger.warning("Could not determine base ref, no changed files detected")
            return []

        return self._git_diff_files(ref)

    def find_related_files(
        self,
        changed_files: list[Path],
        file_asts: list[FileAST],
        max_related: int = 150,
    ) -> list[Path]:
        """Find files related to the changed files via imports.

        Looks for:
        - Forward dependencies: files imported by changed files
        - Reverse dependencies: files that import changed modules
        """
        if not changed_files:
            return []

        changed_set = {f.resolve() for f in changed_files}
        related: set[Path] = set()

        # Build module-to-path index from file_asts
        module_to_path: dict[str, Path] = {}
        for ast in file_asts:
            ast_path = Path(ast.file_path).resolve()
            module_name = self._path_to_module(ast_path)
            if module_name:
                module_to_path[module_name] = ast_path

        # Forward deps: parse changed files' imports -> resolve to file paths
        changed_asts = [a for a in file_asts if Path(a.file_path).resolve() in changed_set]
        for ast in changed_asts:
            for imp in ast.imports:
                # Try exact module match first
                if imp.module in module_to_path:
                    dep_path = module_to_path[imp.module]
                    if dep_path not in changed_set:
                        related.add(dep_path)
                # Try parent module (e.g., "foo.bar.baz" -> "foo.bar")
                parts = imp.module.rsplit(".", 1)
                if len(parts) > 1 and parts[0] in module_to_path:
                    dep_path = module_to_path[parts[0]]
                    if dep_path not in changed_set:
                        related.add(dep_path)

        # Reverse deps: find files that import changed modules
        changed_modules: set[str] = set()
        for ast in changed_asts:
            module = self._path_to_module(Path(ast.file_path).resolve())
            if module:
                changed_modules.add(module)
                # Also add short name (last component)
                changed_modules.add(module.rsplit(".", 1)[-1])

        if changed_modules:
            # Search via file ASTs (faster than grep)
            for ast in file_asts:
                ast_path = Path(ast.file_path).resolve()
                if ast_path in changed_set or ast_path in related:
                    continue
                for imp in ast.imports:
                    if imp.module in changed_modules:
                        related.add(ast_path)
                        break
                    for name in imp.names:
                        if name in changed_modules:
                            related.add(ast_path)
                            break

        # Cap at max_related
        result = sorted(related)[:max_related]
        logger.info(
            "Found %d related files for %d changed files (cap=%d)",
            len(result),
            len(changed_files),
            max_related,
        )
        return result

    def _resolve_explicit(self, file_list: list[str]) -> list[Path]:
        """Resolve an explicit comma-separated file list."""
        result: list[Path] = []
        for f in file_list:
            p = (self.repo_root / f).resolve()
            if p.exists() and p.suffix in SUPPORTED_EXTENSIONS:
                result.append(p)
        return result

    def _detect_base_ref(self) -> str | None:
        """Detect the base ref using git merge-base."""
        for remote_branch in ("origin/main", "origin/master"):
            try:
                result = subprocess.run(
                    ["git", "merge-base", remote_branch, "HEAD"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=self.repo_root,
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except subprocess.TimeoutExpired, FileNotFoundError:
                continue
        return None

    def _git_diff_files(self, base_ref: str) -> list[Path]:
        """Get changed files from git diff against base ref."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACMR", base_ref, "HEAD"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=self.repo_root,
            )
            if result.returncode != 0:
                logger.warning("git diff failed: %s", result.stderr.strip())
                return []

            files: list[Path] = []
            for line in result.stdout.strip().splitlines():
                p = (self.repo_root / line).resolve()
                if p.exists() and p.suffix in SUPPORTED_EXTENSIONS:
                    files.append(p)

            logger.info("Git diff found %d changed files (base=%s)", len(files), base_ref[:12])
            return files

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("git diff failed: %s", e)
            return []

    def _path_to_module(self, path: Path) -> str | None:
        """Convert a file path to a Python-style module name."""
        try:
            rel = path.relative_to(self.repo_root)
        except ValueError:
            return None
        parts = list(rel.parts)
        if not parts:
            return None
        # Remove file extension from last part
        parts[-1] = path.stem
        # Remove __init__ (package marker)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            return None
        return ".".join(parts)
