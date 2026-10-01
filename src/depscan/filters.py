"""Finding filters shared by CLI output formats."""
from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def dependency_severity(dependency: Any) -> str:
    """Return the highest known severity, defaulting typosquats to medium."""
    severities = [
        str(vulnerability.severity).lower()
        for vulnerability in getattr(dependency, "known_vulnerabilities", [])
    ]
    return max(severities, key=lambda value: SEVERITY_ORDER.get(value, -1)) if severities else "medium"


def filter_results(
    results: dict,
    severities: set[str] | None = None,
    ecosystems: set[str] | None = None,
    min_severity: str | None = None,
) -> dict:
    """Filter findings without mutating the original scan result."""
    filtered = dict(results)

    def keep(dependency: Any) -> bool:
        severity = dependency_severity(dependency)
        if ecosystems and dependency.ecosystem.lower() not in ecosystems:
            return False
        if severities and severity not in severities:
            return False
        if min_severity and (
            SEVERITY_ORDER.get(severity, -1)
            < SEVERITY_ORDER[min_severity]
        ):
            return False
        return True

    filtered["typosquats"] = [
        dep for dep in results.get("typosquats", []) if keep(dep)
    ]
    filtered["vulnerable"] = [
        dep for dep in results.get("vulnerable", []) if keep(dep)
    ]
    if ecosystems:
        filtered["by_ecosystem"] = {
            ecosystem: count
            for ecosystem, count in results.get("by_ecosystem", {}).items()
            if ecosystem.lower() in ecosystems
        }
    return filtered
