"""Tests for SARIF 2.1.0 output (issue #120).

Validates that depscan's SARIF output:
- Is structurally valid SARIF 2.1.0
- Includes required GitHub Code Scanning fields (originalUriBaseIds, etc.)
- Correctly maps depscan findings to SARIF results / rules
- Handles edge cases (empty findings, missing source files, …)
"""
from __future__ import annotations

import json

import pytest

from depscan.sarif import (
    Finding,
    findings_from_scan_results,
    to_sarif,
)
from depscan.scanner import Dependency, Vulnerability


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def typosquat_finding() -> Finding:
    return Finding(
        rule_id="DEPSCAN001",
        package_name="reqeusts",
        package_version="2.28.0",
        ecosystem="pypi",
        message="Package 'reqeusts' (2.28.0) is a potential typosquat of 'requests'.",
        severity="medium",
        source_file="requirements.txt",
        typosquat_target="requests",
    )


@pytest.fixture()
def vuln_finding() -> Finding:
    return Finding(
        rule_id="DEPSCAN002",
        package_name="lodash",
        package_version="4.17.10",
        ecosystem="npm",
        message="Package 'lodash' (4.17.10) has a known vulnerability: Prototype pollution.",
        severity="high",
        source_file="package-lock.json",
        cve="CVE-2019-10744",
        fix_version="4.17.21",
    )


@pytest.fixture()
def empty_sarif() -> dict:
    return to_sarif([])


@pytest.fixture()
def single_finding_sarif(typosquat_finding) -> dict:
    return to_sarif([typosquat_finding])


@pytest.fixture()
def multi_finding_sarif(typosquat_finding, vuln_finding) -> dict:
    return to_sarif([typosquat_finding, vuln_finding])


# ---------------------------------------------------------------------------
# Top-level SARIF document structure
# ---------------------------------------------------------------------------


class TestSarifDocumentStructure:
    """Validate the top-level SARIF 2.1.0 envelope."""

    def test_version_field_is_2_1_0(self, empty_sarif):
        assert empty_sarif["version"] == "2.1.0"

    def test_schema_field_present(self, empty_sarif):
        assert "$schema" in empty_sarif
        assert "sarif" in empty_sarif["$schema"].lower()

    def test_schema_references_2_1_0(self, empty_sarif):
        assert "2.1.0" in empty_sarif["$schema"]

    def test_runs_is_non_empty_list(self, empty_sarif):
        assert isinstance(empty_sarif["runs"], list)
        assert len(empty_sarif["runs"]) >= 1

    def test_is_json_serialisable(self, multi_finding_sarif):
        """to_sarif() must return something that json.dumps() accepts."""
        serialised = json.dumps(multi_finding_sarif)
        assert isinstance(serialised, str)
        # Must round-trip cleanly.
        assert json.loads(serialised) == multi_finding_sarif


# ---------------------------------------------------------------------------
# Tool / driver
# ---------------------------------------------------------------------------


class TestSarifTool:
    """Validate the tool.driver block."""

    def test_tool_name_is_depscan(self, empty_sarif):
        driver = empty_sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "depscan"

    def test_driver_has_version(self, empty_sarif):
        driver = empty_sarif["runs"][0]["tool"]["driver"]
        assert "version" in driver
        assert driver["version"]  # non-empty

    def test_driver_has_information_uri(self, empty_sarif):
        driver = empty_sarif["runs"][0]["tool"]["driver"]
        assert "informationUri" in driver
        assert driver["informationUri"].startswith("https://")

    def test_driver_rules_is_list(self, empty_sarif):
        driver = empty_sarif["runs"][0]["tool"]["driver"]
        assert isinstance(driver["rules"], list)


# ---------------------------------------------------------------------------
# originalUriBaseIds — required for GitHub Code Scanning
# ---------------------------------------------------------------------------


class TestOriginalUriBaseIds:
    """GitHub Code Scanning requires originalUriBaseIds to resolve file paths."""

    def test_key_present_in_run(self, empty_sarif):
        run = empty_sarif["runs"][0]
        assert "originalUriBaseIds" in run, (
            "originalUriBaseIds is required for GitHub Code Scanning compatibility"
        )

    def test_reporoot_key_present(self, empty_sarif):
        uris = empty_sarif["runs"][0]["originalUriBaseIds"]
        assert "REPOROOT" in uris

    def test_reporoot_has_uri(self, empty_sarif):
        reporoot = empty_sarif["runs"][0]["originalUriBaseIds"]["REPOROOT"]
        assert "uri" in reporoot

    def test_reporoot_uri_ends_with_slash(self, empty_sarif):
        """SARIF spec §3.14.14: directory URIs must end with '/'."""
        uri = empty_sarif["runs"][0]["originalUriBaseIds"]["REPOROOT"]["uri"]
        assert uri.endswith("/"), f"REPOROOT uri must end with '/' but got: {uri!r}"

    def test_custom_repo_root_is_respected(self):
        sarif = to_sarif([], repo_root="/workspace/myrepo")
        uri = sarif["runs"][0]["originalUriBaseIds"]["REPOROOT"]["uri"]
        assert "myrepo" in uri

    def test_repo_root_backslashes_converted(self):
        """Windows paths must have backslashes normalised to forward slashes."""
        sarif = to_sarif([], repo_root="C:\\Users\\user\\project")
        uri = sarif["runs"][0]["originalUriBaseIds"]["REPOROOT"]["uri"]
        assert "\\" not in uri


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


class TestSarifResults:
    """Validate the 'results' array within a SARIF run."""

    def test_empty_findings_produce_empty_results(self, empty_sarif):
        results = empty_sarif["runs"][0]["results"]
        assert results == []

    def test_single_finding_produces_one_result(self, single_finding_sarif):
        results = single_finding_sarif["runs"][0]["results"]
        assert len(results) == 1

    def test_multiple_findings_produce_multiple_results(self, multi_finding_sarif):
        results = multi_finding_sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_result_has_rule_id(self, single_finding_sarif):
        result = single_finding_sarif["runs"][0]["results"][0]
        assert "ruleId" in result
        assert result["ruleId"] == "DEPSCAN001"

    def test_result_has_level(self, single_finding_sarif):
        result = single_finding_sarif["runs"][0]["results"][0]
        assert result["level"] in {"error", "warning", "note", "none"}

    def test_result_has_message_text(self, single_finding_sarif):
        result = single_finding_sarif["runs"][0]["results"][0]
        assert "text" in result["message"]
        assert result["message"]["text"]

    def test_result_message_contains_package_name(self, single_finding_sarif, typosquat_finding):
        result = single_finding_sarif["runs"][0]["results"][0]
        assert typosquat_finding.package_name in result["message"]["text"]

    def test_typosquat_result_message_mentions_target(self, single_finding_sarif, typosquat_finding):
        result = single_finding_sarif["runs"][0]["results"][0]
        assert typosquat_finding.typosquat_target in result["message"]["text"]

    def test_vuln_result_message_contains_cve(self, vuln_finding):
        sarif = to_sarif([vuln_finding])
        result = sarif["runs"][0]["results"][0]
        assert vuln_finding.cve in result["message"]["text"]

    def test_vuln_result_message_contains_fix_version(self, vuln_finding):
        sarif = to_sarif([vuln_finding])
        result = sarif["runs"][0]["results"][0]
        assert vuln_finding.fix_version in result["message"]["text"]

    def test_result_properties_contain_package_info(self, single_finding_sarif, typosquat_finding):
        props = single_finding_sarif["runs"][0]["results"][0]["properties"]
        assert props["package"] == typosquat_finding.package_name
        assert props["version"] == typosquat_finding.package_version
        assert props["ecosystem"] == typosquat_finding.ecosystem

    def test_result_has_partial_fingerprints(self, single_finding_sarif):
        result = single_finding_sarif["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert result["partialFingerprints"]  # non-empty

    def test_fingerprint_includes_rule_package_version(self, typosquat_finding):
        sarif = to_sarif([typosquat_finding])
        fp = sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        assert typosquat_finding.rule_id in fp
        assert typosquat_finding.package_name in fp
        assert typosquat_finding.package_version in fp


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


class TestSarifLocations:
    """Validate physical location / artifact URI handling."""

    def test_result_with_source_file_has_locations(self, single_finding_sarif):
        result = single_finding_sarif["runs"][0]["results"][0]
        assert "locations" in result
        assert len(result["locations"]) == 1

    def test_artifact_uri_matches_source_file(self, typosquat_finding):
        sarif = to_sarif([typosquat_finding])
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert "requirements.txt" in uri

    def test_artifact_uri_base_id_is_reporoot(self, single_finding_sarif):
        loc = single_finding_sarif["runs"][0]["results"][0]["locations"][0]
        base_id = loc["physicalLocation"]["artifactLocation"]["uriBaseId"]
        assert base_id == "REPOROOT"

    def test_region_has_start_line(self, single_finding_sarif):
        loc = single_finding_sarif["runs"][0]["results"][0]["locations"][0]
        region = loc["physicalLocation"]["region"]
        assert "startLine" in region
        assert isinstance(region["startLine"], int)
        assert region["startLine"] >= 1

    def test_no_locations_when_source_file_is_empty(self):
        finding = Finding(
            rule_id="DEPSCAN001",
            package_name="pkg",
            package_version="1.0.0",
            ecosystem="npm",
            message="Test",
            source_file="",  # no source file
        )
        sarif = to_sarif([finding])
        result = sarif["runs"][0]["results"][0]
        assert "locations" not in result

    def test_backslash_in_source_file_is_normalised(self):
        finding = Finding(
            rule_id="DEPSCAN001",
            package_name="pkg",
            package_version="1.0.0",
            ecosystem="npm",
            message="Test",
            source_file="subdir\\package-lock.json",
        )
        sarif = to_sarif([finding])
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri
        assert "subdir/package-lock.json" in uri


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


class TestSarifRules:
    """Validate the reportingDescriptor (rules) array."""

    def test_empty_findings_produce_empty_rules(self, empty_sarif):
        rules = empty_sarif["runs"][0]["tool"]["driver"]["rules"]
        assert rules == []

    def test_typosquat_finding_adds_depscan001_rule(self, single_finding_sarif):
        rules = single_finding_sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "DEPSCAN001" in rule_ids

    def test_vuln_finding_adds_depscan002_rule(self, vuln_finding):
        sarif = to_sarif([vuln_finding])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "DEPSCAN002" in rule_ids

    def test_both_findings_add_both_rules(self, multi_finding_sarif):
        rules = multi_finding_sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert {"DEPSCAN001", "DEPSCAN002"} == rule_ids

    def test_duplicate_rule_ids_are_deduplicated(self):
        findings = [
            Finding("DEPSCAN001", "pkg-a", "1.0", "npm", "msg1"),
            Finding("DEPSCAN001", "pkg-b", "2.0", "npm", "msg2"),
        ]
        sarif = to_sarif(findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert rule_ids.count("DEPSCAN001") == 1

    def test_rule_has_short_description(self, single_finding_sarif):
        rule = single_finding_sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]

    def test_rule_has_full_description(self, single_finding_sarif):
        rule = single_finding_sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "fullDescription" in rule
        assert "text" in rule["fullDescription"]

    def test_rule_has_help_uri(self, single_finding_sarif):
        rule = single_finding_sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" in rule
        assert rule["helpUri"].startswith("https://")

    def test_rule_help_uri_points_at_this_project(self, single_finding_sarif):
        """helpUri must not advertise a same-named repo owned by anyone else.

        The owner is hardcoded on purpose: comparing against the module's own
        constant would pass even when that constant is wrong.
        """
        rule = single_finding_sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"].startswith("https://github.com/yunaremaia/depscan")

    def test_driver_information_uri_points_at_this_project(self, single_finding_sarif):
        """Consumers render informationUri; it must be this project's repo."""
        driver = single_finding_sarif["runs"][0]["tool"]["driver"]
        assert driver["informationUri"] == "https://github.com/yunaremaia/depscan"

    def test_no_third_party_urls_in_document(self, single_finding_sarif):
        """No SARIF URL may point at a repository this project does not own."""
        blob = json.dumps(single_finding_sarif)
        assert "Ts-Boom" not in blob

    def test_rule_has_default_configuration_level(self, single_finding_sarif):
        rule = single_finding_sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "defaultConfiguration" in rule
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note", "none"}

    def test_rule_has_security_tag(self, single_finding_sarif):
        rule = single_finding_sarif["runs"][0]["tool"]["driver"]["rules"][0]
        tags = rule.get("properties", {}).get("tags", [])
        assert "security" in tags


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    @pytest.mark.parametrize("severity,expected_level", [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "note"),
        ("unknown", "warning"),
        ("CRITICAL", "error"),   # case-insensitive
        ("HIGH", "error"),
    ])
    def test_severity_maps_to_sarif_level(self, severity, expected_level):
        finding = Finding(
            rule_id="DEPSCAN001",
            package_name="pkg",
            package_version="1.0.0",
            ecosystem="pypi",
            message="Test",
            severity=severity,
        )
        sarif = to_sarif([finding])
        level = sarif["runs"][0]["results"][0]["level"]
        assert level == expected_level


# ---------------------------------------------------------------------------
# findings_from_scan_results adapter
# ---------------------------------------------------------------------------


class TestFindingsFromScanResults:
    """Validate the depscan scan_results → Finding conversion."""

    def _make_dep(self, name="reqeusts", version="1.0", ecosystem="pypi",
                  is_typosquat=True, target="requests"):
        dep = Dependency(name=name, version=version, ecosystem=ecosystem)
        dep.is_typosquat = is_typosquat
        dep.typosquat_target = target
        return dep

    def test_empty_results_give_empty_findings(self):
        results = {"typosquats": [], "vulnerable": []}
        assert findings_from_scan_results(results) == []

    def test_typosquat_dep_creates_depscan001_finding(self):
        dep = self._make_dep()
        results = {"typosquats": [dep], "vulnerable": []}
        findings = findings_from_scan_results(results)
        assert len(findings) == 1
        assert findings[0].rule_id == "DEPSCAN001"

    def test_typosquat_finding_has_correct_package_info(self):
        dep = self._make_dep(name="reqeusts", version="2.28.0", ecosystem="pypi")
        results = {"typosquats": [dep], "vulnerable": []}
        f = findings_from_scan_results(results)[0]
        assert f.package_name == "reqeusts"
        assert f.package_version == "2.28.0"
        assert f.ecosystem == "pypi"
        assert f.typosquat_target == "requests"

    def test_vulnerable_dep_creates_depscan002_finding(self):
        dep = Dependency(name="lodash", version="4.17.10", ecosystem="npm")
        vuln = Vulnerability(
            id="GHSA-x",
            severity="HIGH",
            description="Prototype pollution",
            cve="CVE-2019-10744",
            fixed_version="4.17.21",
        )
        dep.known_vulnerabilities.append(vuln)
        results = {"typosquats": [], "vulnerable": [dep]}
        findings = findings_from_scan_results(results)
        assert len(findings) == 1
        assert findings[0].rule_id == "DEPSCAN002"
        assert findings[0].cve == "CVE-2019-10744"
        assert findings[0].fix_version == "4.17.21"

    def test_multiple_vulns_per_dep_create_multiple_findings(self):
        dep = Dependency(name="pkg", version="1.0.0", ecosystem="npm")
        for i in range(3):
            dep.known_vulnerabilities.append(
                Vulnerability(id=f"GHSA-{i}", severity="HIGH", description=f"vuln {i}")
            )
        results = {"typosquats": [], "vulnerable": [dep]}
        findings = findings_from_scan_results(results)
        assert len(findings) == 3

    def test_results_with_only_total_and_by_ecosystem_keys(self):
        """findings_from_scan_results must tolerate partial result dicts."""
        results = {"total": 5, "by_ecosystem": {"pypi": 5}}
        # Should not raise even though typosquats / vulnerable keys are absent.
        findings = findings_from_scan_results(results)
        assert findings == []


# ---------------------------------------------------------------------------
# Round-trip: to_sarif → json.dumps → json.loads → validates
# ---------------------------------------------------------------------------


class TestSarifRoundTrip:
    def test_full_round_trip(self, typosquat_finding, vuln_finding):
        sarif = to_sarif([typosquat_finding, vuln_finding], repo_root="/repo")
        raw = json.dumps(sarif, indent=2)
        reloaded = json.loads(raw)

        assert reloaded["version"] == "2.1.0"
        assert len(reloaded["runs"][0]["results"]) == 2
        assert len(reloaded["runs"][0]["tool"]["driver"]["rules"]) == 2
        assert "REPOROOT" in reloaded["runs"][0]["originalUriBaseIds"]
