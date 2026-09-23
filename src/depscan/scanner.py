"""Multi-ecosystem dependency scanner."""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator

# Strict allowlist for package names: only alphanumeric characters, dots, hyphens,
# and underscores are permitted.  Anything else (semicolons, pipes, spaces, …)
# would indicate an injection attempt and is rejected before any subprocess call.
SAFE_PACKAGE_NAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')


def validate_package_name(name: str) -> None:
    """Validate *name* against the safe-package-name allowlist.

    Raises:
        ValueError: If *name* contains characters outside ``[a-zA-Z0-9._-]``.
    """
    if not SAFE_PACKAGE_NAME_RE.match(name):
        raise ValueError("Invalid package name")


LOCK_PATTERNS = [
    "Cargo.lock",
    "package-lock.json",
    "Pipfile.lock",
    "requirements.txt",
    "go.mod",
    "poetry.lock",
    "Gemfile.lock",
    "*.lock",
]


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
        current = {}
        in_package = False
        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current.get("name"):
                    deps.append(Dependency(
                        name=current.get("name", ""),
                        version=current.get("version", ""),
                        ecosystem="cargo",
                    ))
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
            deps.append(Dependency(
                name=current.get("name", ""),
                version=current.get("version", ""),
                ecosystem="cargo",
            ))
        return deps

    @staticmethod
    def parse_package_lock(content: str) -> list[Dependency]:
        """Parse package-lock.json (npm). Supports lockfileVersion 1, 2, and 3."""
        deps: list[Dependency] = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return deps
        if not isinstance(data, dict):
            return deps

        lockfile_version = data.get("lockfileVersion")
        seen: set[tuple[str, str]] = set()

        def _collect_legacy_deps(dependencies_dict: dict) -> None:
            """Recursively collect dependencies from legacy npm dependencies tree."""
            if not isinstance(dependencies_dict, dict):
                return
            queue = [dependencies_dict]
            while queue:
                current_dict = queue.pop(0)
                if not isinstance(current_dict, dict):
                    continue
                for name, info in current_dict.items():
                    if not isinstance(name, str) or not isinstance(info, dict):
                        continue
                    version = info.get("version", "")
                    if isinstance(version, str) and name and version:
                        key = (name, version)
                        if key not in seen:
                            seen.add(key)
                            deps.append(Dependency(
                                name=name,
                                version=version,
                                ecosystem="npm",
                            ))
                    nested = info.get("dependencies")
                    if isinstance(nested, dict):
                        queue.append(nested)

        # For lockfileVersion 1, only legacy `dependencies` exists
        if lockfile_version == 1:
            raw_dependencies = data.get("dependencies")
            if isinstance(raw_dependencies, dict):
                _collect_legacy_deps(raw_dependencies)
            return deps

        # For lockfileVersion 2, 3, or unspecified, check `packages` first (npm v7+)
        packages = data.get("packages")
        if isinstance(packages, dict):
            for path, info in packages.items():
                if not isinstance(path, str) or not isinstance(info, dict):
                    continue
                if path.startswith("node_modules/"):
                    parts = path.split("node_modules/")
                    name = parts[-1]
                    version = info.get("version", "")
                    if isinstance(version, str) and name and version:
                        key = (name, version)
                        if key not in seen:
                            seen.add(key)
                            deps.append(Dependency(
                                name=name,
                                version=version,
                                ecosystem="npm",
                            ))

        # Fallback to legacy `dependencies` if `packages` was absent, empty, or yielded no dependencies
        if not deps:
            raw_dependencies = data.get("dependencies")
            if isinstance(raw_dependencies, dict):
                _collect_legacy_deps(raw_dependencies)

        return deps

    @staticmethod
    def parse_pipfile_lock(content: str) -> list[Dependency]:
        """Parse Pipfile.lock JSON format."""
        deps = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return deps
        if not isinstance(data, dict):
            return deps

        for section in ("default", "develop"):
            section_data = data.get(section)
            if not isinstance(section_data, dict):
                continue
            for name, info in section_data.items():
                if not isinstance(info, dict):
                    continue
                raw_version = info.get("version", "")
                if not isinstance(raw_version, str):
                    continue
                version = raw_version.lstrip("=")
                if not version:
                    continue
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                ))
        return deps

    parse_plfile_lock = parse_pipfile_lock

    @staticmethod
    def parse_requirements_txt(content: str) -> list[Dependency]:
        """Parse requirements.txt."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            line = line.split(";", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, _, version = line.partition("==")
                deps.append(Dependency(
                    name=name.strip(),
                    version=version.strip(),
                    ecosystem="pypi",
                ))
            elif ">=" in line:
                name, _, version = line.partition(">=")
                deps.append(Dependency(
                    name=name.strip(),
                    version=version.strip(),
                    ecosystem="pypi",
                ))
        return deps

    @staticmethod
    def parse_go_mod(content: str) -> list[Dependency]:
        """Parse go.mod require and replace directives."""
        deps = []
        replacements = {}
        in_require = False
        in_replace = False

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            # Replace block
            if line.startswith("replace ("):
                in_replace = True
                continue
            if in_replace:
                if line == ")":
                    in_replace = False
                    continue
                if "=>" in line:
                    parts = line.split("=>")
                    if len(parts) == 2:
                        old_name = parts[0].strip().split()[0]
                        new_target = parts[1].strip()
                        new_parts = new_target.split()
                        if len(new_parts) >= 2:
                            replacements[old_name] = new_parts[1].lstrip("v")
                        elif len(new_parts) == 1:
                            replacements[old_name] = new_target
                continue

            # Single-line replace
            if line.startswith("replace ") and "=>" in line:
                parts = line[8:].split("=>")
                if len(parts) == 2:
                    old_name = parts[0].strip().split()[0]
                    new_target = parts[1].strip()
                    new_parts = new_target.split()
                    if len(new_parts) >= 2:
                        replacements[old_name] = new_parts[1].lstrip("v")
                    elif len(new_parts) == 1:
                        replacements[old_name] = new_target
                continue

            # Require block
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require:
                if line == ")":
                    in_require = False
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip("v")
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="go",
                    ))
                continue

            # Single-line require
            if line.startswith("require ") and "(" not in line:
                parts = line[8:].split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip("v")
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="go",
                    ))

        # Apply replacements to all dependencies
        for dep in deps:
            if dep.name in replacements:
                dep.version = replacements[dep.name]

        return deps

    @staticmethod
    def parse_poetry_lock(content: str) -> list[Dependency]:
        """Parse poetry.lock (pyproject.toml companion)."""
        deps = []
        current = {}
        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current.get("name"):
                    deps.append(Dependency(
                        name=current.get("name", ""),
                        version=current.get("version", ""),
                        ecosystem="pypi",
                    ))
                current = {}
            elif "=" in line and not line.startswith("["):
                key, _, value = line.partition("=")
                key = key.strip().strip('"')
                value = value.strip().strip('"')
                if key in ("name", "version"):
                    current[key] = value
        if current.get("name"):
            deps.append(Dependency(
                name=current.get("name", ""),
                version=current.get("version", ""),
                ecosystem="pypi",
            ))
        return deps

    @staticmethod
    def parse_gemfile_lock(content: str) -> list[Dependency]:
        """Parse Gemfile.lock (Ruby/Bundler).

        Handles both the classic format (bundler 0.9.x, gems listed directly
        under the GEM section) and the modern format (bundler 1.x+, gems
        listed under a ``specs:`` heading).  Only the GEM section is scanned;
        gems resolved from GIT or PATH sources are ignored.
        """
        deps = []
        in_gem_section = False
        in_specs = False
        spec_re = re.compile(r"^ {4}(\S+) \(([^)]+)\)\s*$")

        for line in content.splitlines():
            stripped = line.strip()

            # Section headings start at column 0 (e.g. GEM, PLATFORMS,
            # DEPENDENCIES, GIT, PATH, BUNDLED WITH).
            if stripped and not line[0].isspace():
                in_gem_section = stripped == "GEM"
                in_specs = False
                continue

            if not in_gem_section or not stripped or stripped.startswith("#"):
                continue

            if not in_specs:
                if stripped == "specs:":
                    in_specs = True
                    continue
                # Old 0.9.x format: gems sit directly under GEM.  Skip
                # metadata lines such as "remote: https://rubygems.org/".
                if not line.startswith("    ") or ":" in stripped:
                    continue

            match = spec_re.match(line)
            if match:
                deps.append(Dependency(
                    name=match.group(1),
                    version=match.group(2),
                    ecosystem="rubygems",
                ))
        return deps


class MultiScanner:
    """Scan dependencies across multiple ecosystems."""

    def __init__(self):
        self.parser = DependencyParser()
        self._typosquat_targets = self._load_typosquat_targets()

    def _load_typosquat_targets(self) -> list[str]:
        """Load common package names that are typosquat targets."""
        return [
            "requests", "numpy", "pandas", "django", "flask", "fastapi",
            "tensorflow", "pytorch", "transformers", "click", "rich",
            "pytest", "black", "isort", "mypy", "sphinx", "jinja",
            "sqlalchemy", "alembic", "celery", "redis", "boto3",
            "botocore", "urllib3", "certifi", "idna", "charset",
            "packaging", "setuptools", "wheel", "pip", "virtualenv",
            "cryptography", "pyopenssl", "paramiko", "fabric",
            "ansible", "terraform", "pulumi", "docker", "kubernetes",
            "grpc", "protobuf", "thrift", "avro", "msgpack",
            "ujson", "orjson", "simplejson", "pyyaml", "toml",
            "httpx", "aiohttp", "tornado", "twisted", "gevent",
            "pytest-cov", "pytest-xdist", "pytest-mock", "pytest-asyncio",
            "django-rest-framework", "celery-beat", "django-celery-beat",
            "rails", "rack", "rake", "devise", "puma", "sidekiq",
            "resque", "rspec", "nokogiri", "activerecord",
        ]

    def scan_file(self, filepath: str) -> list[Dependency]:
        """Scan a single dependency file."""
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        path = Path(filepath)

        suffix_map = {
            ".toml": ("cargo", self.parser.parse_cargo_lock),
            ".json": ("npm", self.parser.parse_package_lock),
            ".txt": ("pypi", self.parser.parse_requirements_txt),
            ".mod": ("go", self.parser.parse_go_mod),
        }

        # Try by filename
        filename = path.name.lower()
        if "cargo.lock" in filename:
            return self.parser.parse_cargo_lock(content)
        elif "package-lock" in filename:
            return self.parser.parse_package_lock(content)
        elif "pipfile.lock" in filename:
            return self.parser.parse_pipfile_lock(content)
        elif "requirements" in filename:
            return self.parser.parse_requirements_txt(content)
        elif filename == "go.mod":
            return self.parser.parse_go_mod(content)
        elif "poetry.lock" in filename:
            return self.parser.parse_poetry_lock(content)
        elif "gemfile.lock" in filename:
            return self.parser.parse_gemfile_lock(content)

        return []

    def scan_directory(self, root: str = ".") -> list[Dependency]:
        """Scan all dependency files in a directory."""
        deps = []
        seen = set()

        for pattern in LOCK_PATTERNS:
            for path in Path(root).rglob(pattern):
                if path.is_file():
                    resolved = path.resolve()
                    if resolved in seen:
                        continue
                    seen.add(resolved)
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
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def scan_and_check(self, root: str = ".") -> dict:
        """Full scan with typosquat detection."""
        deps = self.scan_directory(root)
        results = {
            "total": len(deps),
            "typosquats": [],
            "vulnerable": [],
            "by_ecosystem": {},
        }

        for dep in deps:
            eco = dep.ecosystem
            if eco not in results["by_ecosystem"]:
                results["by_ecosystem"][eco] = 0
            results["by_ecosystem"][eco] += 1

            if self.check_typosquat(dep):
                results["typosquats"].append(dep)

        return results


def check(package: str) -> dict:
    """Run ``npm audit`` against a single *package* name and return the parsed JSON.

    The package name is validated with :func:`validate_package_name` before it is
    passed to the subprocess so that shell-injection attacks are impossible even
    when ``shell=False`` is used.

    Args:
        package: The npm package name to audit (e.g. ``"lodash"``).

    Returns:
        The parsed JSON output from ``npm audit``.

    Raises:
        ValueError: If *package* contains characters not allowed by
            :data:`SAFE_PACKAGE_NAME_RE`.
        subprocess.CalledProcessError: If ``npm audit`` exits with a non-zero
            status code.
    """
    validate_package_name(package)
    result = subprocess.run(
        ["npm", "audit", "--json", package],
        shell=False,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": result.stderr or result.stdout, "returncode": result.returncode}
