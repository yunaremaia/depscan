"""SHA256 lockfile integrity manifests."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


INTEGRITY_FILE = ".depscan-integrity.json"


@dataclass(frozen=True)
class IntegrityViolation:
    file: str
    expected: str
    actual: str


def sha256_file(path: Path) -> str:
    """Hash a file without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(root: Path, files: Iterable[Path]) -> Path:
    """Write known-good hashes relative to root."""
    entries = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(files)
    }
    target = root / INTEGRITY_FILE
    target.write_text(json.dumps({"files": entries}, indent=2) + "\n", encoding="utf-8")
    return target


def verify_manifest(root: Path) -> list[IntegrityViolation]:
    """Compare files against a stored integrity manifest."""
    manifest_path = root / INTEGRITY_FILE
    if not manifest_path.is_file():
        raise FileNotFoundError(f"{INTEGRITY_FILE} not found")
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = data.get("files", data)
    if not isinstance(entries, dict):
        raise ValueError("integrity manifest must contain a files object")

    violations = []
    for relative, expected in entries.items():
        path = root / relative
        actual = sha256_file(path) if path.is_file() else ""
        if actual != expected:
            violations.append(IntegrityViolation(relative, str(expected), actual))
    return violations
