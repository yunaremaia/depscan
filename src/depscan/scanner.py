"""Multi-ecosystem dependency scanner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Vulnerability:
    """A known vulnerability."""

    id: str
    severity: str
    description: str
    affected_versions: str = ""
    fixed_version: str = ""
    cve: str = ""
    source: str = ""


@dataclass
class Dependency:
    """A dependency with version info."""

    name: str
    version: str
    ecosystem: str  # npm, pypi, cargo, go, etc
    source_file: str = ""
    latest_version: str = ""
    known_vulnerabilities: list[Vulnerability] = field(default_factory=list)
    is_typosquat: bool = False
    typosquat_target: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return len(self.known_vulnerabilities) > 0


class DependencyParser:
    """Parse lockfiles and manifest files."""

    @staticmethod
    def parse_cargo_lock(content: str) -> list[Dependency]:
        """Parse Cargo.lock format."""
        deps = []
        current: dict[str, str] = {}
        in_package = False
        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current.get("name"):
                    deps.append(
                        Dependency(
                            name=current.get("name", ""),
                            version=current.get("version", ""),
                            ecosystem="cargo",
                        )
                    )
                current = {}
                in_package = True
                continue
            if in_package and not line.startswith("[") and "=" in line:
                key, _, value = line.partition("=")
                key = key.strip().strip('"')
                value = value.strip().strip('"')
                if key in ("name", "version"):
                    current[key] = value
        if current.get("name"):
            deps.append(
                Dependency(
                    name=current.get("name", ""),
                    version=current.get("version", ""),
                    ecosystem="cargo",
                )
            )
        return deps

    @staticmethod
    def parse_package_lock(content: str) -> list[Dependency]:
        """Parse package-lock.json (npm)."""
        deps = []
        try:
            data = json.loads(content)
            packages = data.get("packages", {})
            for path, info in packages.items():
                if path.startswith("node_modules/"):
                    name = path.replace("node_modules/", "")
                    version = info.get("version", "")
                    if name and version:
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem="npm",
                            )
                        )
        except json.JSONDecodeError:
            pass
        return deps

    @staticmethod
    def parse_requirements_txt(content: str) -> list[Dependency]:
        """Parse requirements.txt."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, _, version = line.partition("==")
                deps.append(
                    Dependency(
                        name=name.strip(),
                        version=version.strip(),
                        ecosystem="pypi",
                    )
                )
            elif ">=" in line:
                name, _, version = line.partition(">=")
                deps.append(
                    Dependency(
                        name=name.strip(),
                        version=version.strip(),
                        ecosystem="pypi",
                    )
                )
        return deps

    @staticmethod
    def parse_go_mod(content: str) -> list[Dependency]:
        """Parse go.mod require block."""
        deps = []
        in_require = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require and " " in line:
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip("v")
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="go",
                        )
                    )
        return deps

    @staticmethod
    def parse_poetry_lock(content: str) -> list[Dependency]:
        """Parse poetry.lock (pyproject.toml companion)."""
        deps = []
        current: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current.get("name"):
                    deps.append(
                        Dependency(
                            name=current.get("name", ""),
                            version=current.get("version", ""),
                            ecosystem="pypi",
                        )
                    )
                current = {}
            elif "=" in line and not line.startswith("["):
                key, _, value = line.partition("=")
                key = key.strip().strip('"')
                value = value.strip().strip('"')
                if key in ("name", "version"):
                    current[key] = value
        if current.get("name"):
            deps.append(
                Dependency(
                    name=current.get("name", ""),
                    version=current.get("version", ""),
                    ecosystem="pypi",
                )
            )
        return deps


class MultiScanner:
    """Scan dependencies across multiple ecosystems."""

    def __init__(self):
        self.parser = DependencyParser()
        self._typosquat_targets = self._load_typosquat_targets()

    def _load_typosquat_targets(self) -> list[str]:
        """Load common package names that are typosquat targets."""
        return [
            "requests",
            "numpy",
            "pandas",
            "django",
            "flask",
            "fastapi",
            "tensorflow",
            "pytorch",
            "transformers",
            "click",
            "rich",
            "pytest",
            "black",
            "isort",
            "mypy",
            "sphinx",
            "jinja",
            "sqlalchemy",
            "alembic",
            "celery",
            "redis",
            "boto3",
            "botocore",
            "urllib3",
            "certifi",
            "idna",
            "charset",
            "packaging",
            "setuptools",
            "wheel",
            "pip",
            "virtualenv",
            "cryptography",
            "pyopenssl",
            "paramiko",
            "fabric",
            "ansible",
            "terraform",
            "pulumi",
            "docker",
            "kubernetes",
            "grpc",
            "protobuf",
            "thrift",
            "avro",
            "msgpack",
            "ujson",
            "orjson",
            "simplejson",
            "pyyaml",
            "toml",
            "httpx",
            "aiohttp",
            "tornado",
            "twisted",
            "gevent",
            "pytest-cov",
            "pytest-xdist",
            "pytest-mock",
            "pytest-asyncio",
            "django-rest-framework",
            "celery-beat",
            "django-celery-beat",
        ]

    def scan_file(self, filepath: str) -> list[Dependency]:
        """Scan a single dependency file."""
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        path = Path(filepath)

        # Try by filename
        filename = path.name.lower()
        if "cargo.lock" in filename:
            return self.parser.parse_cargo_lock(content)
        elif "package-lock" in filename:
            return self.parser.parse_package_lock(content)
        elif "requirements" in filename:
            return self.parser.parse_requirements_txt(content)
        elif filename == "go.mod":
            return self.parser.parse_go_mod(content)
        elif "poetry.lock" in filename:
            return self.parser.parse_poetry_lock(content)

        return []

    def scan_directory(self, root: str = ".") -> list[Dependency]:
        """Scan all dependency files in a directory."""
        deps = []
        patterns = [
            "Cargo.lock",
            "package-lock.json",
            "requirements.txt",
            "go.mod",
            "poetry.lock",
            "*.lock",
        ]

        for pattern in patterns:
            for path in Path(root).rglob(pattern):
                if path.is_file():
                    deps.extend(self.scan_file(str(path)))

        return deps

    def check_typosquat(self, dep: Dependency) -> bool:
        """Check if a dependency name is a potential typosquat."""
        name_lower = dep.name.lower()
        for target in self._typosquat_targets:
            if name_lower == target:
                return False  # Known good package
            # Simple similarity check
            if self._levenshtein(name_lower, target) <= 2:
                dep.is_typosquat = True
                dep.typosquat_target = target
                return True
        return False

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def scan_and_check(self, root: str = ".") -> dict[str, Any]:
        """Full scan with typosquat detection."""
        deps = self.scan_directory(root)
        by_ecosystem: dict[str, int] = {}
        typosquats: list[Dependency] = []
        vulnerable: list[Dependency] = []

        for dep in deps:
            eco = dep.ecosystem
            if eco not in by_ecosystem:
                by_ecosystem[eco] = 0
            by_ecosystem[eco] += 1

            if self.check_typosquat(dep):
                typosquats.append(dep)

        return {
            "total": len(deps),
            "typosquats": typosquats,
            "vulnerable": vulnerable,
            "by_ecosystem": by_ecosystem,
        }
