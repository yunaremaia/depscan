"""Tests for depscan CLI exit codes and output formats."""
import json
import subprocess
from unittest.mock import patch

from click.testing import CliRunner

from depscan import __version__
from depscan.cli import cli, _should_fail
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


def test_info_shows_version_and_output_formats():
    result = CliRunner().invoke(cli, ["info"])

    assert result.exit_code == 0
    assert __version__ in result.output
    assert "terminal (default)" in result.output
    assert "JSON" in result.output
    assert "Markdown" in result.output
    assert "SARIF" in result.output


def test_list_deps_json_includes_source_file():
    dependency = Dependency(
        name="requests",
        version="2.31.0",
        ecosystem="pypi",
        source_file="requirements.txt",
    )
    with patch.object(MultiScanner, "scan_directory", return_value=[dependency]):
        result = CliRunner().invoke(cli, ["list-deps", "--json-output", "."])

    assert result.exit_code == 0
    assert json.loads(result.output) == [{
        "name": "requests",
        "version": "2.31.0",
        "ecosystem": "pypi",
        "source_file": "requirements.txt",
    }]


def test_init_creates_valid_relaxed_config(tmp_path):
    config_path = tmp_path / ".depscan.yml"
    runner = CliRunner()

    created = runner.invoke(cli, ["init", str(config_path)])
    validated = runner.invoke(cli, ["validate", str(config_path)])

    assert created.exit_code == 0
    assert validated.exit_code == 0
    assert "output_format: text" in config_path.read_text()


def test_init_profiles_and_force(tmp_path):
    config_path = tmp_path / ".depscan.yml"
    runner = CliRunner()

    first = runner.invoke(cli, ["init", str(config_path), "--profile", "strict"])
    duplicate = runner.invoke(cli, ["init", str(config_path), "--profile", "ci"])
    forced = runner.invoke(
        cli, ["init", str(config_path), "--profile", "ci", "--force"]
    )

    assert first.exit_code == 0
    assert duplicate.exit_code != 0
    assert forced.exit_code == 0
    assert "output_format: sarif" in config_path.read_text()


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


def test_ci_exits_one_for_real_typosquat(tmp_path):
    """Control test: a real typosquat on disk must fail ``depscan ci``.

    ``test_ci_exits_one_for_typosquat`` patches ``scan_and_check``, so it only
    proves the exit-code wiring.  This one scans a real requirements.txt with
    no mocking at all, which is the only way to catch a regression that makes
    ``check_typosquat`` silently stop flagging anything.
    """
    req = tmp_path / "requirements.txt"
    req.write_text("reqests==1.0.0\n")
    result = run_depscan("ci", str(tmp_path))
    assert result.returncode == 1, (
        f"exit={result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    assert "TYPOSQUAT" in result.stderr
    assert "reqests" in result.stderr
    assert "requests" in result.stderr


def test_ci_passes_for_known_good_packages(tmp_path):
    """The other half: the packages the ordering bug used to flag must pass.

    ``black``, ``rack``, ``rake`` and ``orjson`` are all on depscan's own
    known-good list, yet each sits within edit distance 2 of an earlier entry
    (``flask``, ``rich``, ``rack``, ``ujson``).  Before the allowlist-ordering
    fix, scanning them made ``depscan ci`` exit 1.
    """
    req = tmp_path / "requirements.txt"
    req.write_text("black==24.1.0\nrack==3.0.0\nrake==13.0.0\norjson==3.9.0\n")
    result = run_depscan("ci", str(tmp_path))
    assert result.returncode == 0, (
        f"exit={result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    assert "TYPOSQUAT" not in result.stderr


def test_fail_on_policies():
    typo = {"typosquats": [object()], "vulnerable": []}
    vulnerable = {"typosquats": [], "vulnerable": [object()]}
    both = {"typosquats": [object()], "vulnerable": [object()]}

    assert _should_fail(typo, None) is False
    assert _should_fail(typo, "typosquat") is True
    assert _should_fail(typo, "vulnerable") is False
    assert _should_fail(vulnerable, "vulnerable") is True
    assert _should_fail(both, "any") is True


def test_list_deps_finds_cargo_workspace_dependencies(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["app"]\n\n'
        '[workspace.dependencies]\ntokio = "1.37"\n'
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\n\n'
        '[dependencies]\ntokio = { workspace = true }\n\n'
        "[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n"
    )
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "tokio"\nversion = "1.37.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    result = CliRunner().invoke(cli, ["list-deps", "--json-output", str(tmp_path)])

    assert result.exit_code == 0
    found = sorted((d["name"], d["version"]) for d in json.loads(result.output))
    assert found == [("libc", "0.2"), ("tokio", "1.37"), ("tokio", "1.37.0")]
