"""Tests for lockfile integrity verification."""
from pathlib import Path

from depscan.integrity import sha256_file, verify_manifest, write_manifest


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
