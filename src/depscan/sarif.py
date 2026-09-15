"""SARIF 2.1.0 output generator for depscan.

Converts depscan scan results to OASIS SARIF 2.1.0 format
for GitHub Code Scanning, GitLab Security Dashboard, and CI systems.
"""
from __future__ import annotations

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def to_sarif(results: dict, version: str = "0.1.0") -> dict:
    """Convert depscan scan results to a SARIF 2.1.0 compliant dictionary."""
    rules = []
    sarif_results = []
    rule_ids = set()

    # Rule: typosquat detection
    typosquats = results.get("typosquats", [])
    if typosquats and "depscan-typosquat" not in rule_ids:
        rule_ids.add("depscan-typosquat")
        rules.append({
            "id": "depscan-typosquat",
            "name": "TyposquatDependency",
            "shortDescription": {
                "text": "Potential typosquatting dependency detected"
            },
            "fullDescription": {
                "text": "A dependency matches a known popular package name with slight typographical variations, indicating potential malicious spoofing."
            },
            "defaultConfiguration": {
                "level": "warning"
            },
            "properties": {
                "tags": ["security", "supply-chain", "typosquat"]
            }
        })

    for dep in typosquats:
        sarif_results.append({
            "ruleId": "depscan-typosquat",
            "level": "warning",
            "message": {
                "text": f"Dependency '{dep.name}' (v{dep.version}) in {dep.ecosystem} appears to be a typosquat of popular package '{dep.typosquat_target}'."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": getattr(dep, "source_file", None) or "dependencies"
                        }
                    }
                }
            ]
        })

    # Rule: known vulnerabilities
    vulnerable = results.get("vulnerable", [])
    for dep in vulnerable:
        for vuln in getattr(dep, "known_vulnerabilities", []):
            vuln_id = getattr(vuln, "id", "depscan-vulnerability")
            if "depscan-vulnerability" not in rule_ids:
                rule_ids.add("depscan-vulnerability")
                rules.append({
                    "id": "depscan-vulnerability",
                    "name": "VulnerableDependency",
                    "shortDescription": {
                        "text": "Known vulnerability in dependency"
                    },
                    "defaultConfiguration": {
                        "level": "error"
                    },
                    "properties": {
                        "tags": ["security", "vulnerability"]
                    }
                })

            sarif_results.append({
                "ruleId": "depscan-vulnerability",
                "level": "error",
                "message": {
                    "text": f"{dep.name}@{dep.version}: {vuln_id} - {getattr(vuln, 'description', '')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": getattr(dep, "source_file", None) or "dependencies"
                            }
                        }
                    }
                ]
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depscan",
                        "semanticVersion": version,
                        "informationUri": "https://github.com/yunaremaia/depscan",
                        "rules": rules
                    }
                },
                "results": sarif_results
            }
        ]
    }
