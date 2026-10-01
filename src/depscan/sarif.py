"""SARIF 2.1.0 output for GitHub Code Scanning integration.

SARIF (Static Analysis Results Interchange Format) is the standard format
consumed by GitHub Code Scanning.  This module provides:

- :class:`Finding` — a normalised finding (typosquat or vulnerability) that
  bridges depscan's internal data model to SARIF concepts.
- :func:`to_sarif` — converts a list of :class:`Finding` objects into a fully
  valid SARIF 2.1.0 document, including ``originalUriBaseIds`` for GitHub
  Code Scanning compatibility.

References
----------
- SARIF 2.1.0 spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- GitHub Code Scanning SARIF requirements:
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

#: Rule IDs used in the SARIF output.  Each maps to a human-readable name and
#: a help URI so that developers can follow the link in GitHub's UI.
_RULE_DEFINITIONS: dict[str, dict[str, str]] = {
    "DEPSCAN001": {
        "name": "PotentialTyposquat",
        "shortDescription": "Potential typosquat package detected",
        "fullDescription": (
            "The dependency name is suspiciously similar to a well-known package. "
            "This may indicate a supply-chain typosquatting attack."
        ),
        "helpUri": "https://github.com/Ts-Boom/depscan/blob/main/SECURITY.md",
        "defaultLevel": "warning",
    },
    "DEPSCAN002": {
        "name": "KnownVulnerability",
        "shortDescription": "Dependency has a known vulnerability",
        "fullDescription": (
            "A CVE or advisory has been published for this dependency version. "
            "Upgrade to the fixed version as soon as possible."
        ),
        "helpUri": "https://github.com/Ts-Boom/depscan/blob/main/SECURITY.md",
        "defaultLevel": "error",
    },
}

#: Map depscan severity strings to SARIF notification levels.
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "warning",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A normalised security finding produced by depscan.

    This class bridges depscan's :class:`~depscan.scanner.Dependency` /
    :class:`~depscan.scanner.Vulnerability` model to the concepts expected by
    SARIF consumers such as GitHub Code Scanning.

    Attributes
    ----------
    rule_id:
        SARIF rule identifier (e.g. ``"DEPSCAN001"``).
    package_name:
        The affected dependency name.
    package_version:
        The affected dependency version.
    ecosystem:
        Package ecosystem (``"npm"``, ``"pypi"``, ``"cargo"``, ``"go"``…).
    message:
        Human-readable description of the finding.
    severity:
        Severity label: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
        ``"info"``, or ``"unknown"``.
    source_file:
        Path to the lock-/manifest file that declared the dependency, relative
        to the repository root.  Empty string if unknown.
    cve:
        CVE identifier when applicable (e.g. ``"CVE-2021-44228"``).
    fix_version:
        Version that resolves the vulnerability, when known.
    typosquat_target:
        The well-known package that the typosquat resembles (for DEPSCAN001).
    """

    rule_id: str
    package_name: str
    package_version: str
    ecosystem: str
    message: str
    severity: str = "unknown"
    source_file: str = ""
    cve: str = ""
    fix_version: str = ""
    typosquat_target: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def to_sarif(findings: list[Finding], repo_root: str = ".") -> dict[str, Any]:
    """Convert *findings* into a SARIF 2.1.0 document.

    The returned dict is directly serialisable with :func:`json.dumps` and is
    accepted by GitHub Code Scanning when written to a ``.sarif`` file and
    uploaded via the ``upload-sarif`` action.

    Parameters
    ----------
    findings:
        List of :class:`Finding` objects produced by depscan.
    repo_root:
        The repository root path used to populate ``originalUriBaseIds``.
        Defaults to ``"."``.  GitHub Code Scanning uses this to resolve
        relative artifact URIs back to source files.

    Returns
    -------
    dict
        A fully valid SARIF 2.1.0 document.
    """
    # Collect the subset of rules that are actually referenced.
    referenced_rule_ids: list[str] = sorted(
        {f.rule_id for f in findings} & _RULE_DEFINITIONS.keys()
    )

    rules = [_build_rule(rule_id) for rule_id in referenced_rule_ids]
    results = [_build_result(finding) for finding in findings]

    # Ensure repo_root URI ends with "/" as required by the SARIF spec for
    # originalUriBaseIds values.
    root_uri = repo_root.replace("\\", "/").rstrip("/") + "/"
    if not root_uri.startswith(("http://", "https://", "file://")):
        root_uri = root_uri  # keep as a relative URI

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depscan",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Ts-Boom/depscan",
                        "rules": rules,
                    }
                },
                # Required for GitHub Code Scanning to resolve file paths.
                "originalUriBaseIds": {
                    "REPOROOT": {"uri": root_uri},
                },
                "results": results,
            }
        ],
    }
    return sarif_doc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_rule(rule_id: str) -> dict[str, Any]:
    """Build a SARIF ``reportingDescriptor`` object for *rule_id*."""
    defn = _RULE_DEFINITIONS[rule_id]
    return {
        "id": rule_id,
        "name": defn["name"],
        "shortDescription": {"text": defn["shortDescription"]},
        "fullDescription": {"text": defn["fullDescription"]},
        "defaultConfiguration": {"level": defn["defaultLevel"]},
        "helpUri": defn["helpUri"],
        "help": {
            "text": defn["fullDescription"],
            "markdown": f"**{defn['shortDescription']}**\n\n{defn['fullDescription']}\n\nSee [{defn['helpUri']}]({defn['helpUri']}) for remediation guidance.",
        },
        "properties": {
            "tags": ["security", "supply-chain"],
        },
    }


def _build_result(finding: Finding) -> dict[str, Any]:
    """Build a SARIF ``result`` object for a single *finding*."""
    level = _SEVERITY_TO_LEVEL.get(finding.severity.lower(), "warning")

    # Build the message with contextual detail.
    message_lines = [finding.message]
    if finding.typosquat_target:
        message_lines.append(
            f"Similar to well-known package: {finding.typosquat_target!r}"
        )
    if finding.cve:
        message_lines.append(f"CVE: {finding.cve}")
    if finding.fix_version:
        message_lines.append(f"Fix version: {finding.fix_version}")

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": " ".join(message_lines)},
        "properties": {
            "package": finding.package_name,
            "version": finding.package_version,
            "ecosystem": finding.ecosystem,
        },
    }

    # Add a location only when we have a source file.  GitHub Code Scanning
    # uses this to annotate the exact file in the PR diff.
    if finding.source_file:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.source_file.replace("\\", "/"),
                        "uriBaseId": "REPOROOT",
                    },
                    # SARIF requires a region even if we don't know the line.
                    "region": {"startLine": 1},
                }
            }
        ]

    # Populate optional fingerprint fields used for deduplication.
    result["partialFingerprints"] = {
        "primaryLocationLineHash": f"{finding.rule_id}/{finding.package_name}/{finding.package_version}"
    }

    return result


# ---------------------------------------------------------------------------
# Conversion helpers — depscan domain → Finding
# ---------------------------------------------------------------------------


def findings_from_scan_results(results: dict[str, Any]) -> list[Finding]:
    """Convert a ``scan_and_check`` result dict into a list of :class:`Finding`.

    This is a convenience adapter so that the CLI doesn't need to know the
    internal SARIF data model.

    Parameters
    ----------
    results:
        The dict returned by :meth:`~depscan.scanner.MultiScanner.scan_and_check`.

    Returns
    -------
    list[Finding]
        One :class:`Finding` per typosquat / vulnerability entry.
    """
    findings: list[Finding] = []

    for dep in results.get("typosquats", []):
        findings.append(
            Finding(
                rule_id="DEPSCAN001",
                package_name=dep.name,
                package_version=dep.version,
                ecosystem=dep.ecosystem,
                message=(
                    f"Package '{dep.name}' ({dep.version}) is a potential typosquat "
                    f"of '{dep.typosquat_target}'."
                ),
                severity="medium",
                source_file=getattr(dep, "source_file", ""),
                typosquat_target=dep.typosquat_target,
            )
        )

    for dep in results.get("vulnerable", []):
        for vuln in getattr(dep, "known_vulnerabilities", []):
            findings.append(
                Finding(
                    rule_id="DEPSCAN002",
                    package_name=dep.name,
                    package_version=dep.version,
                    ecosystem=dep.ecosystem,
                    message=(
                        f"Package '{dep.name}' ({dep.version}) has a known vulnerability: "
                        f"{vuln.description}"
                    ),
                    severity=vuln.severity.lower() if vuln.severity else "unknown",
                    source_file=getattr(dep, "source_file", ""),
                    cve=getattr(vuln, "cve", ""),
                    fix_version=getattr(vuln, "fixed_version", ""),
                )
            )

    return findings
