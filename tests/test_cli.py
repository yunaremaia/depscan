"""Tests for depscan CLI exit codes and output formats."""
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from depscan.cli import cli
from depscan.scanner import Dependency, MultiScanner


def run_depscan(*args, cwd=None):
    return subprocess.run(
        ["depscan", *args],
        capture_output=True,
        text=True,
        cwd=cwd or ".",
    )


def test_scan_exit_code_0_no_typosquats(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    result = run_depscan("scan", "--no-typosquat", str(tmp_path))
    assert result.returncode == 0, f"exit={result.returncode}\n{result.stdout}\n{result.stderr}"


def test_scan_json_output_valid(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    result = run_depscan("scan", "--json-output", "--no-typosquat", str(tmp_path))
    assert result.returncode == 0, f"exit={result.returncode}\n{result.stdout}\n{result.stderr}"
    output = json.loads(result.stdout)
    assert "total" in output
    assert "typosquats" in output
    assert "by_ecosystem" in output


def test_scan_markdown_output(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    result = run_depscan("scan", "--markdown", "--no-typosquat", str(tmp_path))
    assert result.returncode == 0, f"exit={result.returncode}\n{result.stdout}\n{result.stderr}"
    assert "# Dependency Scan Report" in result.stdout


def test_check_invalid_name_rejects_injection(tmp_path):
    """Security: malformed package names must be rejected without spawning subprocess."""
    result = run_depscan("check", "foo; rm -rf /", "1.0.0")
    assert result.returncode == 2, f"exit={result.returncode}\n{result.stderr}"

def test_check_invalid_name_rejects_uri_scheme(tmp_path):
    """Security: URI scheme names must be rejected."""
    result = run_depscan("check", "file://etc/passwd", "1.0.0")
    assert result.returncode == 2, f"exit={result.returncode}\n{result.stderr}"

def test_check_valid_name_succeeds(tmp_path):
    """Normal package names must work."""
    result = run_depscan("check", "requests", "2.31.0")
    assert result.returncode == 0, f"exit={result.returncode}\n{result.stderr}"


def test_ci_exits_one_for_typosquat():
    dep = Dependency(name="reqests", version="1.0", ecosystem="pypi")
    dep.typosquat_target = "requests"
    results = {"total": 1, "typosquats": [dep], "vulnerable": [], "by_ecosystem": {"pypi": 1}}
    with patch.object(MultiScanner, "scan_and_check", return_value=results):
        result = CliRunner().invoke(cli, ["ci", "."])
    assert result.exit_code == 1
    assert "TYPOSQUAT" in result.output


def test_ci_allow_known_ignores_vulnerabilities():
    dep = Dependency(name="package", version="1.0", ecosystem="npm")
    results = {"total": 1, "typosquats": [], "vulnerable": [dep], "by_ecosystem": {"npm": 1}}
    with patch.object(MultiScanner, "scan_and_check", return_value=results):
        result = CliRunner().invoke(cli, ["ci", ".", "--allow-known"])
    assert result.exit_code == 0
    assert "No blocking dependency findings" in result.output
