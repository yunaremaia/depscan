"""Tests for ignore-file dependency discovery."""
import os
import shutil
import subprocess

import pytest

from depscan.ignore import is_ignored
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


DIFFERENTIAL_PATHS = [
    "Cargo.toml",
    "Cargo.lock",
    "crates/app/Cargo.toml",
    "crates/app/Cargo.lock",
    "package.json",
    "web/package.json",
    "build/o.txt",
    "crates/app/build/o.txt",
    "buildfoo/o.txt",
    "docs/build",
    "dist/a/b.js",
    "node_modules/pkg/package.json",
    "web/node_modules/pkg/package.json",
    "src/main.log",
    "logs/debug.log",
]


# Each case is one .gitignore. The oracle is git itself, not a fixed table.
@pytest.mark.parametrize("gitignore", [
    "/Cargo.toml",
    "/package.json",
    "build",
    "build/",
    "/build/",
    "**/build",
    "dist/**",
    "node_modules/",
    "*.log",
    "Cargo.lock",
    "crates/*/Cargo.toml",
    "crates/**/o.txt",
    "*.log\n!debug.log",
    "Cargo.toml\n!/Cargo.toml",
    "*.json\n!web/*.json",
])
def test_is_ignored_agrees_with_git_check_ignore(tmp_path, gitignore):
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    for rel in DIFFERENTIAL_PATHS:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("")
    (tmp_path / ".gitignore").write_text(gitignore + "\n")
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True, env=env)
    result = subprocess.run(
        [git, "-c", "core.ignorecase=false", "check-ignore", "--no-index", "--stdin"],
        cwd=tmp_path, input="\n".join(DIFFERENTIAL_PATHS), capture_output=True,
        text=True, env=env,
    )
    assert result.returncode in (0, 1), result.stderr
    expected = set(result.stdout.split())
    patterns = gitignore.split("\n")
    actual = {rel for rel in DIFFERENTIAL_PATHS if is_ignored(tmp_path / rel, tmp_path, patterns)}
    assert actual == expected
