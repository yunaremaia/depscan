"""Tests for ignore-file dependency discovery."""
from depscan.scanner import MultiScanner


def write_requirement(directory, package):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "requirements.txt").write_text(f"{package}==1.0\n")


def test_scan_respects_gitignore(tmp_path):
    write_requirement(tmp_path / "generated", "ignored")
    write_requirement(tmp_path / "source", "included")
    (tmp_path / ".gitignore").write_text("generated/\n")
    deps = MultiScanner().scan_directory(str(tmp_path))
    assert [dep.name for dep in deps] == ["included"]


def test_scan_respects_npmignore_and_negation(tmp_path):
    write_requirement(tmp_path / "fixtures" / "keep", "kept")
    write_requirement(tmp_path / "fixtures" / "drop", "dropped")
    (tmp_path / ".npmignore").write_text("fixtures/**\n!fixtures/keep/**\n")
    deps = MultiScanner().scan_directory(str(tmp_path))
    assert [dep.name for dep in deps] == ["kept"]


def test_scan_can_disable_ignores_and_add_custom_pattern(tmp_path):
    write_requirement(tmp_path / "ignored", "visible")
    write_requirement(tmp_path / "custom", "custom")
    (tmp_path / ".gitignore").write_text("ignored/\n")
    deps = MultiScanner().scan_directory(
        str(tmp_path),
        respect_ignores=False,
        exclude_patterns=["custom/**"],
    )
    assert [dep.name for dep in deps] == ["visible"]
