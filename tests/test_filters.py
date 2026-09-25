"""Tests for severity and ecosystem filtering."""
from depscan.filters import filter_results
from depscan.scanner import Dependency, Vulnerability


def dependency(name, ecosystem, severity=None):
    dep = Dependency(name=name, version="1.0", ecosystem=ecosystem)
    if severity:
        dep.known_vulnerabilities.append(
            Vulnerability(id=f"CVE-{name}", severity=severity, description="")
        )
    return dep


def test_filter_results_by_ecosystem():
    npm = dependency("npm-package", "npm")
    pypi = dependency("pypi-package", "pypi")
    results = {
        "typosquats": [npm, pypi], "vulnerable": [],
        "by_ecosystem": {"npm": 1, "pypi": 1},
    }
    filtered = filter_results(results, ecosystems={"npm"})
    assert filtered["typosquats"] == [npm]
    assert filtered["by_ecosystem"] == {"npm": 1}


def test_filter_results_by_exact_and_minimum_severity():
    medium = dependency("typo", "npm")
    high = dependency("high", "npm", "HIGH")
    critical = dependency("critical", "pypi", "CRITICAL")
    results = {
        "typosquats": [medium], "vulnerable": [high, critical],
        "by_ecosystem": {"npm": 2, "pypi": 1},
    }
    assert filter_results(results, severities={"high"})["vulnerable"] == [high]
    assert filter_results(results, min_severity="high")["vulnerable"] == [
        high, critical
    ]
    assert filter_results(results, min_severity="high")["typosquats"] == []
