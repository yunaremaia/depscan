"""Multi-ecosystem dependency scanner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import fnmatch
import json
import os
import re
import subprocess
import warnings

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
from dataclasses import dataclass, field
from pathlib import Path

# Strict allowlist for package names: only alphanumeric characters, dots, hyphens,
# and underscores are permitted.  Anything else (semicolons, pipes, spaces, …)
# would indicate an injection attempt and is rejected before any subprocess call.
SAFE_PACKAGE_NAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')
SCOPED_PACKAGE_NAME_RE = re.compile(r'^[a-zA-Z0-9@][a-zA-Z0-9._@/-]*$')


def validate_package_name(name: str, ecosystem: str = "") -> None:
    """Validate *name* against the safe-package-name allowlist.

    Raises:
        ValueError: If *name* contains characters outside ``[a-zA-Z0-9._-]``.
    """
    pattern = (
        SCOPED_PACKAGE_NAME_RE
        if ecosystem in {"go", "npm"}
        else SAFE_PACKAGE_NAME_RE
    )
    if (
        not pattern.fullmatch(name)
        or name.startswith("-")
        or "://" in name
        or ".." in name.split("/")
    ):
        raise ValueError("Invalid package name")


LOCK_PATTERNS = [
    "Cargo.lock",
    "Cargo.toml",
    "package-lock.json",
    "package.json",
    "Pipfile.lock",
    "requirements.txt",
    "go.mod",
    "go.sum",
    "poetry.lock",
    "pyproject.toml",
    "Gemfile.lock",
    "*.lock",
]

DEFAULT_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "env",
    ".env", "dist", "build", "target", "vendor", ".idea", ".vscode",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
}

# PEP 508 environment markers.  A requirement is only treated as carrying a
# marker when the left-hand side of the comparison is one of these names.
ENVIRONMENT_MARKERS = frozenset({
    "os_name",
    "sys_platform",
    "platform_release",
    "platform_system",
    "platform_version",
    "platform_machine",
    "platform_python_implementation",
    "implementation_name",
    "implementation_version",
    "python_version",
    "python_full_version",
    "platform_python_version",
    "extra",
})

# A PEP 508 marker expression, in either ``<var> <op> <value>`` or
# ``<value> in <var>`` order.  The variable must be a known environment marker.
_ENV_MARKER_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*\s*(?:==|!=|<=|>=|~=|<|>|not\s+in|in)\s*.+"
    r"|.+\s+(?:not\s+in|in)\s+[A-Za-z_][A-Za-z0-9_]*)$"
)
_ENV_MARKER_VARS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# ``"<value>" in <var>`` and ``<var> in "<value>"`` forms.
_ENV_MARKER_IN_RE = re.compile(
    r"^(?:.+)\s+(?:not\s+in|in)\s+(?:\"[^\"]*\"|'[^']*'|[A-Za-z0-9._-]+)$"
)


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
    is_orphaned: bool = False

    source: str = "registry"
    is_local: bool = False

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

        def append_current() -> None:
            if not current.get("name"):
                return
            raw_source = current.get("source", "")
            is_local = not raw_source or raw_source.startswith("path+file://") or raw_source == "workspace"
            source = raw_source or "local"
            deps.append(Dependency(
                name=current.get("name", ""),
                version=current.get("version", ""),
                ecosystem="cargo",
                source=source,
                is_local=is_local,
            ))

        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                append_current()
                current = {}
                in_package = True
                continue
            if in_package and not line.startswith("[") and "=" in line:
                key, _, value = line.partition("=")
                key = key.strip().strip('"')
                value = value.strip().strip('"')
                if key in ("name", "version", "source"):
                    current[key] = value
        append_current()
        return deps

    @staticmethod
    def parse_cargo_toml(content: str, workspace_deps: dict | None = None) -> list[Dependency]:
        """Parse dependency declarations from Cargo.toml.

        Covers the dependency tables, their ``[target.<cfg>.*]`` variants and
        ``[workspace.dependencies]``. ``workspace = true`` takes its version from
        this file's workspace table, else from *workspace_deps* (the root's); if
        neither has the name, the version is the literal string "workspace".
        Each (name, version) pair is reported once, as in parse_pyproject_toml.
        """
        try:
            data = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError):
            return []

        tables = _cargo_dependency_tables(data)
        workspace = data.get("workspace")
        own_ws = workspace.get("dependencies") if isinstance(workspace, dict) else None
        own_ws = own_ws if isinstance(own_ws, dict) else {}
        tables.append(own_ws)
        inherited = own_ws if isinstance(workspace, dict) else workspace_deps
        if not isinstance(inherited, dict):
            inherited = {}

        deps: list[Dependency] = []
        seen: set[tuple[str, str]] = set()
        for section_data in tables:
            if not isinstance(section_data, dict):
                continue
            for name, spec in section_data.items():
                version = ""
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    if spec.get("workspace") is True:
                        base = inherited.get(name)
                        if isinstance(base, dict):
                            base = base.get("version")
                        version = base if isinstance(base, str) else "workspace"
                    elif isinstance(spec.get("version"), str):
                        version = spec["version"]
                if version and (name, version) not in seen:
                    seen.add((name, version))
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="cargo",
                    ))
        return deps

    @staticmethod
    def parse_pyproject_toml(content: str) -> list[Dependency]:
        """Parse PEP 621 and Poetry dependency declarations."""
        try:
            data = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError):
            return []

        deps: list[Dependency] = []
        seen: set[tuple[str, str]] = set()

        def add_pep508(requirement: str) -> None:
            requirement = requirement.split(";", 1)[0].strip()
            match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$", requirement)
            if not match:
                return
            name, version = match.groups()
            key = (name, version)
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(name=name, version=version, ecosystem="pypi"))

        project = data.get("project", {})
        if isinstance(project, dict):
            dependencies = project.get("dependencies", [])
            if isinstance(dependencies, list):
                for requirement in dependencies:
                    if isinstance(requirement, str):
                        add_pep508(requirement)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group in optional.values():
                    if isinstance(group, list):
                        for requirement in group:
                            if isinstance(requirement, str):
                                add_pep508(requirement)

        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        if isinstance(poetry_deps, dict):
            for name, spec in poetry_deps.items():
                if name.lower() == "python":
                    continue
                version = spec if isinstance(spec, str) else spec.get("version", "") if isinstance(spec, dict) else ""
                if isinstance(version, str) and version:
                    key = (name, version)
                    if key not in seen:
                        seen.add(key)
                        deps.append(Dependency(name=name, version=version, ecosystem="pypi"))
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
    def parse_package_json(content: str) -> list[Dependency]:
        """Parse top-level npm dependencies from package.json."""
        deps: list[Dependency] = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return deps
        if not isinstance(data, dict):
            return deps

        seen: set[str] = set()
        for section in ("dependencies", "devDependencies"):
            section_data = data.get(section)
            if not isinstance(section_data, dict):
                continue
            for name, version in section_data.items():
                if (
                    isinstance(name, str)
                    and isinstance(version, str)
                    and name
                    and version
                    and name not in seen
                ):
                    seen.add(name)
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="npm",
                    ))
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
    def _strip_environment_marker(line: str) -> str:
        """Drop a trailing PEP 508 environment marker from a requirement.

        The marker is only removed when the text before the ``;`` is already a
        well-formed requirement.  If the leading part still contains characters
        that are illegal in a distribution name, the line is left untouched so
        that :func:`validate_package_name` rejects it rather than seeing a
        silently sanitised name.
        """
        if ";" not in line:
            return line
        head, _, tail = line.partition(";")
        head = head.strip()
        tail = tail.strip()
        if not tail:
            return head
        if not re.match(r"^[A-Za-z0-9._-]+(?:\[[^\]]*\])?.*$", head) or \
                re.search(r"[^A-Za-z0-9._\[\]<>!=~-]", head.split("[")[0]):
            return line
        if not (_ENV_MARKER_RE.match(tail) or _ENV_MARKER_IN_RE.match(tail)):
            return line
        # Require at least one known environment marker variable in the
        # expression; otherwise this is not a marker we should trust.
        if not any(v in ENVIRONMENT_MARKERS for v in _ENV_MARKER_VARS.findall(tail)):
            return line
        return head

    @staticmethod
    def parse_requirements_txt(content: str) -> list[Dependency]:
        """Parse requirements.txt."""
        deps = []
        version_specifiers = ("==", ">=", "<=", "!=", "~=", ">", "<")
        for line in content.splitlines():
            line = DependencyParser._strip_environment_marker(line.strip())
            if not line or line.startswith("#"):
                continue
            found = False
            for spec in version_specifiers:
                if spec in line:
                    name, _, version = line.partition(spec)
                    deps.append(Dependency(
                        # Strip bracketed extras so typosquat detection compares
                        # the underlying distribution name.
                        name=name.partition("[")[0].strip(),
                        version=version.strip(),
                        ecosystem="pypi",
                    ))
                    found = True
                    break
            if not found:
                # Plain package name without version specifier
                deps.append(Dependency(
                    name=line.partition("[")[0].strip(),
                    version="",
                    ecosystem="pypi",
                ))
        return deps

    @staticmethod
    def parse_go_mod(content: str) -> list[Dependency]:
        """Parse go.mod require and replace directives."""
        deps = []
        replacements = {}
        exclusions: set[tuple[str, str]] = set()
        in_require = False
        in_replace = False
        in_exclude = False

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            # Exclude block
            if line.startswith("exclude ("):
                in_exclude = True
                continue
            if in_exclude:
                if line == ")":
                    in_exclude = False
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    exclusions.add((parts[0], parts[1].lstrip("v")))
                continue

            # Single-line exclude
            if line.startswith("exclude "):
                parts = line[8:].split()
                if len(parts) >= 2:
                    exclusions.add((parts[0], parts[1].lstrip("v")))
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

        deps = [
            dep for dep in deps
            if (dep.name, dep.version) not in exclusions
        ]

        # Apply replacements to targeted dependencies
        for dep in deps:
            if dep.name in replacements:
                dep.version = replacements[dep.name]

        return deps

    @staticmethod
    def parse_go_sum(content: str) -> list[Dependency]:
        """Parse exact module versions from go.sum, deduplicating /go.mod hashes."""
        deps: list[Dependency] = []
        seen: set[tuple[str, str]] = set()
        for raw_line in content.splitlines():
            parts = raw_line.strip().split()
            if len(parts) != 3:
                continue
            name, version, checksum = parts
            if not checksum.startswith("h1:"):
                continue
            if version.endswith("/go.mod"):
                version = version[:-7]
            version = version.lstrip("v")
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="go",
                source_file="go.sum",
                is_orphaned=True,
            ))
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


def _cargo_dependency_tables(data: dict) -> list:
    """Return a manifest's dependency tables, including ``[target.<cfg>.*]`` ones."""
    sections = ("dependencies", "dev-dependencies", "build-dependencies")
    tables = [data.get(section) for section in sections]
    targets = data.get("target")
    for target in targets.values() if isinstance(targets, dict) else ():
        if isinstance(target, dict):
            tables.extend(target.get(section) for section in sections)
    return tables


def _cargo_toml(content: str) -> dict | None:
    """Parse Cargo manifest *content*; None when it is not valid TOML."""
    try:
        return tomllib.loads(content)
    except (tomllib.TOMLDecodeError, TypeError):
        return None


def _cargo_load(directory: Path) -> dict | None:
    """Parse ``directory/Cargo.toml``; None if it is missing or unreadable."""
    try:
        text = (directory / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _cargo_toml(text)


def _cargo_workspace_paths(workspace: dict, key: str) -> list[str]:
    entries = workspace.get(key)
    return [e for e in entries if isinstance(e, str)] if isinstance(entries, list) else []


def _cargo_excluded(root: Path, workspace: dict, directory: Path) -> bool:
    """Cargo's ``is_excluded``: under an ``exclude`` path and not under a literal
    ``members`` path. A glob ``members`` entry never matches here, so
    ``exclude`` wins over it."""
    def under(entry: str) -> bool:
        base = Path(os.path.normpath(root / entry))
        return directory == base or base in directory.parents

    return any(under(e) for e in _cargo_workspace_paths(workspace, "exclude")) and not any(
        under(m) for m in _cargo_workspace_paths(workspace, "members")
    )


def _cargo_members(root: Path, data: dict) -> frozenset[Path]:
    """The member directories of the workspace rooted at *root*.

    Members are the root package, the directories matched by ``members``
    (literal paths or globs), and the path dependencies of members that sit
    inside the root, minus anything ``exclude`` removes. If one of them has
    no readable Cargo.toml, Cargo rejects the whole workspace, so the set is
    empty.
    """
    workspace = data["workspace"]
    inherited = workspace.get("dependencies")
    inherited = inherited if isinstance(inherited, dict) else {}
    queue = [root] if isinstance(data.get("package"), dict) else []
    for pattern in _cargo_workspace_paths(workspace, "members"):
        if not any(char in pattern for char in "*?["):
            queue.append(root / pattern)
            continue
        try:
            queue.extend(match for match in root.glob(pattern.rstrip("/")) if match.is_dir())
        except ValueError:
            continue
    found: set[Path] = set()
    while queue:
        directory = Path(os.path.normpath(queue.pop()))
        if directory in found or _cargo_excluded(root, workspace, directory):
            continue
        if directory != root and root not in directory.parents:
            continue
        manifest = data if directory == root else _cargo_load(directory)
        if manifest is None:
            return frozenset()  # Cargo rejects a workspace with an unloadable member.
        found.add(directory)
        for table in _cargo_dependency_tables(manifest):
            for name, spec in table.items() if isinstance(table, dict) else ():
                base = directory
                if isinstance(spec, dict) and spec.get("workspace") is True:
                    spec, base = inherited.get(name), root
                if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                    queue.append(base / spec["path"])
    return frozenset(found)


def _cargo_workspace_root(
    manifest: Path, stop_at: Path | None = None, cache: dict | None = None
) -> tuple[Path, dict] | None:
    """Return the workspace root manifest and its ``[workspace.dependencies]``.

    Follows Cargo: the root is the first ancestor whose ``[workspace]`` does not
    exclude the package, and the package must be a member of it, otherwise
    Cargo refuses to inherit. An ancestor Cargo.toml that cannot be parsed ends
    the search, since Cargo stops there with an error too. The search never
    goes above *stop_at*, the directory being scanned. *cache* keeps member
    sets by root for the length of one directory scan.
    """
    crate_dir = manifest.resolve().parent
    stop = stop_at.resolve() if stop_at is not None else None
    for directory in crate_dir.parents:
        if stop is not None and directory != stop and stop not in directory.parents:
            break
        if not (directory / "Cargo.toml").is_file():
            continue
        data = _cargo_load(directory)
        if data is None:
            return None
        workspace = data.get("workspace")
        if not isinstance(workspace, dict):
            continue
        if _cargo_excluded(directory, workspace, crate_dir):
            continue
        deps = workspace.get("dependencies")
        if not isinstance(deps, dict):
            return None
        members = cache.get(directory) if cache is not None else None
        if members is None:
            members = _cargo_members(directory, data)
            if cache is not None:
                cache[directory] = members
        return (directory / "Cargo.toml", deps) if crate_dir in members else None
    return None


class MultiScanner:
    """Scan dependencies across multiple ecosystems."""

    def __init__(self, strict: bool = False):
        self.parser = DependencyParser()
        self.strict = strict
        self._cargo_members: dict[Path, frozenset[Path]] = {}
        self._typosquat_targets = self._load_typosquat_targets()
        # Known-good names, precomputed so the allowlist check cannot depend on
        # the iteration order of ``_typosquat_targets``.  Derived from the same
        # list, so the two can never drift apart.
        self._known_good = frozenset(self._typosquat_targets)

    def _validated(self, deps: list[Dependency]) -> list[Dependency]:
        """Reject invalid names in strict mode; otherwise warn and skip them."""
        valid = []
        for dep in deps:
            try:
                validate_package_name(dep.name, dep.ecosystem)
            except ValueError:
                if self.strict:
                    raise
                warnings.warn(
                    f"Skipping invalid {dep.ecosystem} package name: {dep.name!r}",
                    RuntimeWarning,
                )
                continue
            valid.append(dep)
        return valid

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

    def scan_file(
        self, filepath: str, root: str | None = None, scanned: frozenset[Path] | None = None
    ) -> list[Dependency]:
        """Scan a single dependency file.

        *root* bounds the Cargo workspace lookup. *scanned* is the set of resolved
        files in the same scan; a Cargo member drops an inherited entry only when
        its workspace root manifest is in that set and reports the entry itself.
        """
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        path = Path(filepath)

        # Try by filename
        filename = path.name.lower()
        deps: list[Dependency] = []
        if "cargo.lock" in filename:
            deps = self.parser.parse_cargo_lock(content)
        elif filename == "cargo.toml":
            stop_at = Path(root) if root is not None else None
            # A [workspace] table header only counts outside a multi-line string.
            # Parsing is the honest test; a regex cannot tell the two apart.
            own_root = isinstance((_cargo_toml(content) or {}).get("workspace"), dict)
            found = (
                _cargo_workspace_root(
                    path, stop_at, self._cargo_members if scanned is not None else None
                )
                if "workspace" in content and not own_root else None
            )
            deps = self.parser.parse_cargo_toml(content, found[1] if found else None)
            if found and scanned is not None and found[0] in scanned:
                reported = {
                    (dep.name, dep.version)
                    for dep in self.parser.parse_cargo_toml(
                        found[0].read_text(encoding="utf-8", errors="replace")
                    )
                }
                deps = [dep for dep in deps if (dep.name, dep.version) not in reported]
        elif "package-lock" in filename:
            deps = self.parser.parse_package_lock(content)
        elif filename == "package.json":
            deps = self.parser.parse_package_json(content)
        elif "pipfile.lock" in filename:
            deps = self.parser.parse_pipfile_lock(content)
        elif "requirements" in filename:
            deps = self.parser.parse_requirements_txt(content)
        elif filename == "go.mod":
            deps = self.parser.parse_go_mod(content)
            for dep in deps:
                dep.source_file = str(path)
        elif filename == "go.sum":
            deps = self.parser.parse_go_sum(content)
            for dep in deps:
                dep.source_file = str(path)
        elif "poetry.lock" in filename:
            deps = self.parser.parse_poetry_lock(content)
        elif filename == "pyproject.toml":
            deps = self.parser.parse_pyproject_toml(content)
        elif "gemfile.lock" in filename:
            deps = self.parser.parse_gemfile_lock(content)

        return self._validated(deps)

    def _discover_dependency_files(
        self,
        root: str,
        excludes: set[str] | None = None,
        include_hidden: bool = False,
        respect_ignores: bool = True,
        exclude_patterns: list[str] | None = None,
    ) -> list[Path]:
        """Return the unique dependency files below *root*, in walk order.

        Prunes dependency caches, virtual environments, VCS metadata and build
        output (unless ``include_hidden``), and honours ``.gitignore`` /
        ``.npmignore`` rules plus any caller-supplied patterns.
        """
        from depscan.ignore import is_ignored, load_ignore_patterns

        root_path = Path(root).resolve()
        skip_dirs = set(DEFAULT_SKIP_DIRS)
        if include_hidden:
            skip_dirs = {name for name in skip_dirs if not name.startswith(".")}
        skip_dirs.update(excludes or ())

        patterns = load_ignore_patterns(root_path) if respect_ignores else []
        patterns = list(patterns) + list(exclude_patterns or [])

        files: list[Path] = []
        seen: set[Path] = set()
        for current_root, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [
                name
                for name in dirnames
                if not any(fnmatch.fnmatch(name, pattern) for pattern in skip_dirs)
                and (include_hidden or not name.startswith("."))
            ]
            for filename in sorted(filenames):
                if not any(fnmatch.fnmatch(filename, pattern) for pattern in LOCK_PATTERNS):
                    continue
                path = Path(current_root) / filename
                if patterns and is_ignored(path, root_path, patterns):
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(path)
        return files

    def _parse_all(self, paths: list[Path], root: str | None = None) -> list[Dependency]:
        """Parse discovered files, skipping unreadable ones, then mark go.sum orphans."""
        deps: list[Dependency] = []
        scanned = frozenset(path.resolve() for path in paths)
        self._cargo_members = {}
        for path in paths:
            try:
                deps.extend(self.scan_file(str(path), root, scanned))
            except OSError as exc:
                warnings.warn(
                    f"Skipping unreadable dependency file {path}: {exc}",
                    RuntimeWarning,
                )

        go_mod_names = {
            (Path(dep.source_file).parent, dep.name)
            for dep in deps
            if Path(dep.source_file).name == "go.mod"
        }
        for dep in deps:
            if Path(dep.source_file).name == "go.sum":
                dep.is_orphaned = (
                    Path(dep.source_file).parent, dep.name
                ) not in go_mod_names
        return deps

    def scan_directory(
        self,
        root: str = ".",
        excludes: set[str] | None = None,
        include_hidden: bool = False,
        respect_ignores: bool = True,
        exclude_patterns: list[str] | None = None,
    ) -> list[Dependency]:
        """Scan all dependency files in a directory."""
        return self._parse_all(self._discover_dependency_files(
            root,
            excludes=excludes,
            include_hidden=include_hidden,
            respect_ignores=respect_ignores,
            exclude_patterns=exclude_patterns,
        ), root)

    def scan_directory_parallel(
        self,
        root: str = ".",
        max_workers: int = 4,
        excludes: set[str] | None = None,
        include_hidden: bool = False,
        respect_ignores: bool = True,
        exclude_patterns: list[str] | None = None,
    ) -> list[Dependency]:
        """Scan dependency files concurrently while preserving discovery order."""
        paths = self._discover_dependency_files(
            root,
            excludes=excludes,
            include_hidden=include_hidden,
            respect_ignores=respect_ignores,
            exclude_patterns=exclude_patterns,
        )
        scanned = frozenset(path.resolve() for path in paths)
        self._cargo_members = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            parsed = executor.map(lambda path: self.scan_file(str(path), root, scanned), paths)
            return [dep for file_deps in parsed for dep in file_deps]

    def check_typosquat(self, dep: Dependency) -> bool:
        """Check if a dependency name is a potential typosquat."""
        if dep.is_local:
            return False
        name_lower = dep.name.lower()
        # The known-good allowlist is checked *before* the similarity loop.
        # Checking it inside the loop made the verdict depend on the list's
        # ordering: a target sitting within edit distance 2 of an earlier entry
        # (``black``/``flask``, ``rack``/``rich``, ``rake``/``rack``,
        # ``orjson``/``ujson``) returned True before its own exact match could be
        # reached, so depscan's own allowlist flagged legitimate packages.
        if name_lower in self._known_good:
            return False
        for target in self._typosquat_targets:
            # Simple similarity check
            if self._levenshtein(name_lower, target, max_distance=2) <= 2:
                dep.is_typosquat = True
                dep.typosquat_target = target
                return True
        return False

    @lru_cache(maxsize=1024)
    def _levenshtein(self, s1: str, s2: str, max_distance: int | None = None) -> int:
        """Calculate Levenshtein edit distance."""
        if max_distance is not None and abs(len(s1) - len(s2)) > max_distance:
            return max_distance + 1
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1, max_distance=max_distance)
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
            if max_distance is not None and min(curr_row) > max_distance:
                return max_distance + 1
            prev_row = curr_row
        return prev_row[-1]

    def scan_and_check(
        self,
        root: str = ".",
        parallel: bool = True,
        max_workers: int = 4,
        excludes: set[str] | None = None,
        include_hidden: bool = False,
        respect_ignores: bool = True,
        exclude_patterns: list[str] | None = None,
    ) -> dict:
        """Full scan with typosquat detection."""
        deps = (
            self.scan_directory_parallel(
                root,
                max_workers=max_workers,
                excludes=excludes,
                include_hidden=include_hidden,
                respect_ignores=respect_ignores,
                exclude_patterns=exclude_patterns,
            )
            if parallel
            else self.scan_directory(
                root,
                excludes=excludes,
                include_hidden=include_hidden,
                respect_ignores=respect_ignores,
                exclude_patterns=exclude_patterns,
            )
        )
        results = {
            "total": len(deps),
            "typosquats": [],
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
