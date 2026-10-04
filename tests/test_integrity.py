"""Tests for lockfile integrity verification."""

import json

from depscan.integrity import (
    INTEGRITY_FILE,
    sha256_file,
    verify_manifest,
    write_manifest,
)


def test_integrity_manifest_accepts_unchanged_file(tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.31.0\n")
    write_manifest(tmp_path, [lockfile])
    assert verify_manifest(tmp_path) == []


def test_integrity_manifest_reports_tampered_file(tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.31.0\n")
    write_manifest(tmp_path, [lockfile])
    lockfile.write_text("requests==0.1.0\n")
    violations = verify_manifest(tmp_path)
    assert len(violations) == 1
    assert violations[0].file == "requirements.txt"
    assert violations[0].actual == sha256_file(lockfile)


def test_integrity_manifest_reports_missing_file(tmp_path):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.31.0\n")
    write_manifest(tmp_path, [lockfile])
    lockfile.unlink()
    assert verify_manifest(tmp_path)[0].actual == ""


def test_write_manifest_preserves_sibling_sections(tmp_path):
    """`verify --write` must only replace "files", not rebuild the document.

    The manifest is a shared file: a user or another tool can keep $schema,
    ownership notes or extra sections alongside the hashes. Rewriting the whole
    file from a fresh {"files": ...} dict deleted them with no warning.
    """
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.31.0\n")
    manifest = tmp_path / INTEGRITY_FILE
    manifest.write_text(
        json.dumps(
            {
                "$schema": "https://example.invalid/integrity.json",
                "reviewed_by": "sec-team",
                "files": {"stale.txt": "0" * 64},
            }
        ),
        encoding="utf-8",
    )

    write_manifest(tmp_path, [lockfile])

    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["$schema"] == "https://example.invalid/integrity.json"
    assert data["reviewed_by"] == "sec-team"
    # Only "files" is regenerated: the stale entry is gone, the new one is in.
    assert data["files"] == {"requirements.txt": sha256_file(lockfile)}
    assert verify_manifest(tmp_path) == []


def test_write_manifest_ignores_unreadable_existing_manifest(tmp_path):
    """A corrupt manifest is replaced, not merged with garbage."""
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.31.0\n")
    (tmp_path / INTEGRITY_FILE).write_text("{not json", encoding="utf-8")

    write_manifest(tmp_path, [lockfile])

    assert verify_manifest(tmp_path) == []
