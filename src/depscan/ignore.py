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


def _match_parts(pattern: list[str], parts: list[str]) -> bool:
    """Match path segments against pattern segments; ``**`` spans directories."""
    if not pattern:
        return not parts
    if pattern[0] == "**":
        if len(pattern) == 1:
            # A trailing ``/**`` matches everything inside, not the directory itself.
            return bool(parts)
        return any(_match_parts(pattern[1:], parts[i:]) for i in range(len(parts) + 1))
    return bool(parts) and fnmatchcase(parts[0], pattern[0]) and _match_parts(pattern[1:], parts[1:])


def is_ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    """Apply ordered gitignore-style patterns to a file below *root*.

    As in git, a pattern with a slash at the start or in the middle is anchored
    to *root*; a pattern without one matches at any depth. A trailing slash
    restricts the pattern to directories, and a match on a directory covers
    everything below it.
    """
    parts = list(PurePosixPath(path.relative_to(root).as_posix()).parts)
    ignored = False
    for raw_pattern in patterns:
        negated = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if negated else raw_pattern
        dir_only = pattern.endswith("/")
        pattern = pattern.rstrip("/")
        if not pattern:
            continue
        segments = pattern.lstrip("/").split("/")
        if "/" not in pattern:
            segments.insert(0, "**")
        # Try every ancestor directory, then the file itself unless dir-only.
        last = len(parts) - 1 if dir_only else len(parts)
        if any(_match_parts(segments, parts[:end]) for end in range(1, last + 1)):
            ignored = not negated
    return ignored
