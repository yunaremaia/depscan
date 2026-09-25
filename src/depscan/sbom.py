"""CycloneDX and SPDX SBOM generation."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

from depscan.scanner import Dependency


PURL_TYPES = {
    "cargo": "cargo",
    "npm": "npm",
    "pypi": "pypi",
    "go": "golang",
    "rubygems": "gem",
}


def _purl(dep: Dependency) -> str:
    package_type = PURL_TYPES.get(dep.ecosystem, dep.ecosystem)
    return f"pkg:{package_type}/{dep.name}@{dep.version}"


def to_cyclonedx(dependencies: Iterable[Dependency]) -> dict:
    """Return a CycloneDX 1.5 JSON document."""
    components = []
    vulnerabilities = []
    for dep in dependencies:
        ref = _purl(dep)
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": dep.name,
            "version": dep.version,
            "purl": ref,
            "properties": [
                {"name": "depscan:ecosystem", "value": dep.ecosystem},
                {"name": "depscan:source_file", "value": dep.source_file},
            ],
        })
        for vuln in dep.known_vulnerabilities:
            vulnerabilities.append({
                "id": vuln.id,
                "description": vuln.description,
                "ratings": [{"severity": vuln.severity.lower()}],
                "affects": [{"ref": ref}],
            })
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "components": components,
    }
    if vulnerabilities:
        document["vulnerabilities"] = vulnerabilities
    return document


def to_spdx(dependencies: Iterable[Dependency]) -> dict:
    """Return an SPDX 2.3 JSON document."""
    packages = []
    for index, dep in enumerate(dependencies, start=1):
        packages.append({
            "SPDXID": f"SPDXRef-Package-{index}",
            "name": dep.name,
            "versionInfo": dep.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl(dep),
            }],
            "comment": f"ecosystem={dep.ecosystem}; source_file={dep.source_file}",
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "depscan-sbom",
        "documentNamespace": f"https://github.com/yunaremaia/depscan/sbom/{uuid4()}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: depscan"],
        },
        "packages": packages,
    }


def dumps(document: dict) -> str:
    """Serialize an SBOM document consistently."""
    return json.dumps(document, indent=2)
