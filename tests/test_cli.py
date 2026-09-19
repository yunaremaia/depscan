"""Tests for depscan CLI exit codes and output formats."""
import json
import subprocess
from pathlib import Path


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
