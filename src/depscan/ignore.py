"""Ignore-file support for dependency discovery."""
from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath


def load_ignore_patterns(root: Path) -> list[str]:
    """Load root .gitignore and .npmignore patterns."""
    patterns: list[str] = []
    for name in (".gitignore", ".npmignore"):
        path = root / name
        if not path.is_file():
            continue
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    """Apply ordered gitignore-style patterns to a relative path."""
    relative = path.relative_to(root).as_posix()
    ignored = False
    for raw_pattern in patterns:
        negated = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if negated else raw_pattern
        pattern = pattern.lstrip("/")
        if pattern.endswith("/"):
            pattern += "**"
        candidate = PurePosixPath(relative)
        if pattern.endswith("/**"):
            # PurePath.match treats ``dir/**`` as exactly one descendant.
            # Gitignore uses it for the complete subtree.
            matched = relative.startswith(pattern[:-2])
        else:
            matched = (
                fnmatchcase(relative, pattern)
                or candidate.match(pattern)
                or candidate.match(f"**/{pattern}")
            )
        if matched:
            ignored = not negated
    return ignored
