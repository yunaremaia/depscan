"""Tests for depscan SARIF 2.1.0 output."""
import json
from depscan.sarif import to_sarif, SARIF_SCHEMA
from depscan.scanner import Dependency, Vulnerability


def test_to_sarif_empty():
    results = {"total": 0, "dependencies": [], "typosquats": [], "vulnerable": []}
    sarif = to_sarif(results, version="0.1.0")
    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "depscan"
    assert run["tool"]["driver"]["semanticVersion"] == "0.1.0"
    assert len(run["results"]) == 0


def test_to_sarif_with_typosquat_and_vulnerability():
    typo_dep = Dependency(
        name="reqeusts",
        version="2.31.0",
        ecosystem="pypi",
        source_file="requirements.txt",
        is_typosquat=True,
        typosquat_target="requests",
    )

    vuln = Vulnerability(
        id="CVE-2023-32681",
        description="Unintended leak of Proxy-Authorization header in requests",
        severity="medium",
    )
    vuln_dep = Dependency(
        name="requests",
        version="2.30.0",
        ecosystem="pypi",
        source_file="setup.py",
        known_vulnerabilities=[vuln],
    )

    results = {
        "total": 2,
        "dependencies": [typo_dep, vuln_dep],
        "typosquats": [typo_dep],
        "vulnerable": [vuln_dep],
    }

    sarif = to_sarif(results, version="0.1.0")
    run = sarif["runs"][0]
    assert len(run["results"]) == 2

    # Check typosquat result
    r0 = run["results"][0]
    assert r0["ruleId"] == "depscan-typosquat"
    assert "reqeusts" in r0["message"]["text"]
    assert "requests" in r0["message"]["text"]
    assert r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"

    # Check vulnerability result
    r1 = run["results"][1]
    assert r1["ruleId"] == "depscan-vulnerability"
    assert "CVE-2023-32681" in r1["message"]["text"]
    assert r1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "setup.py"


def test_cli_format_sarif_stdout_pure(tmp_path):
    import subprocess
    cmd = [
        "/Users/liuwenjian/.hermes/hermes-agent/venv/bin/python",
        "src/depscan/cli.py",
        "scan",
        str(tmp_path),
        "--format",
        "sarif",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, env={"PYTHONPATH": "src"})
    assert proc.returncode == 0
    assert proc.stderr == ""  # Zero progress bar leakage on stderr/stdout
    data = json.loads(proc.stdout)
    assert data["$schema"] == SARIF_SCHEMA
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "depscan"
