"""Tests for SBOM generation."""
from depscan.sbom import to_cyclonedx, to_spdx
from depscan.scanner import Dependency, Vulnerability


def test_cyclonedx_contains_components_and_vulnerabilities():
    dep = Dependency(
        name="requests", version="2.31.0", ecosystem="pypi",
        source_file="requirements.txt",
    )
    dep.known_vulnerabilities.append(
        Vulnerability(id="CVE-2026-1", severity="HIGH", description="Example")
    )
    document = to_cyclonedx([dep])

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"
    assert document["vulnerabilities"][0]["affects"][0]["ref"] == (
        "pkg:pypi/requests@2.31.0"
    )


def test_spdx_contains_required_document_and_package_fields():
    dep = Dependency(name="react", version="18.2.0", ecosystem="npm")
    document = to_spdx([dep])

    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    assert document["packages"][0]["name"] == "react"
    assert document["packages"][0]["externalRefs"][0]["referenceLocator"] == (
        "pkg:npm/react@18.2.0"
    )


def test_empty_sbom_documents_are_valid_containers():
    assert to_cyclonedx([])["components"] == []
    assert to_spdx([])["packages"] == []
