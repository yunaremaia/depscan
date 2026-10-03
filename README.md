# depscan — Multi-ecosystem Dependency Scanner

[![CI](https://github.com/yunaremaia/depscan/actions/workflows/ci.yml/badge.svg)](https://github.com/yunaremaia/depscan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Stars](https://img.shields.io/github/stars/yunaremaia/depscan)](https://github.com/yunaremaia/depscan)

Scan dependencies across multiple ecosystems with typosquat detection.

## Features

- **Multi-ecosystem**: Cargo, npm, PyPI, Go
- **Typosquat detection**: Levenshtein-based similarity check against known packages
- **Multiple lockfile formats**: Cargo.lock, package-lock.json, requirements.txt, go.mod, poetry.lock, Pipfile.lock
- **JSON output**: For automation and CI integration
- **Rich terminal output**: Tables, panels, progress bars

## Install

depscan is not published on PyPI yet, so install it straight from the repository:

```bash
pip install git+https://github.com/yunaremaia/depscan.git
```

> **A note on the name.** The bare `depscan` name on PyPI is taken by an
> unrelated third-party project by a different author, so this project's
> distribution is published under the name **`depscan-py`**. That collision is
> why the install line above points at git for now, and why the PyPI name will
> differ from the repository name. The command you type after installing is
> still `depscan`.

Or from source:

```bash
git clone https://github.com/yunaremaia/depscan.git
cd depscan
pip install -e .
```

## Quick Start

```bash
# Scan current directory
depscan scan .

# Scan a specific path
depscan scan /path/to/project

# Reject the scan on the first invalid package name
depscan scan . --strict

# Output as JSON
depscan scan . --json-output > deps.json

# List all dependencies
depscan list-deps .

# Generate standard SBOM documents
depscan sbom . --format cyclonedx --output bom.cdx.json
depscan sbom . --format spdx --output bom.spdx.json

# Check a specific package
depscan check requests 2.28.0

# Show supported ecosystems
depscan info
```

## Supported Formats

| Ecosystem | File | Supported Versions / Details | Status |
|-----------|------|------------------------------|--------|
| Cargo | Cargo.lock | Cargo packages | ✅ |
| npm | package-lock.json | `lockfileVersion` 1, 2, and 3 (direct & nested `dependencies`, `packages`) | ✅ |
| PyPI | requirements.txt | Pinned dependencies | ✅ |
| PyPI | poetry.lock | Poetry dependencies | ✅ |
| PyPI | Pipfile.lock | Default & develop dependencies | ✅ |
| Go | go.mod | Require directives & replace blocks | ✅ |

## CLI Reference

### `depscan scan [PATH]`

Scan a directory for dependencies and detect potential issues.

```bash
depscan scan . --typosquat  # Enable typosquat detection (default)
depscan scan . --no-typosquat  # Disable typosquat detection
depscan scan /path/to/project --json-output  # JSON output
```

### `depscan list-deps [PATH]`

List all dependencies found in a directory.

```bash
depscan list-deps .
depscan list-deps /path/to/project --json-output
```

### `depscan check NAME VERSION`

Check a specific dependency name for typosquat potential.

```bash
depscan check raquests 1.0.0  # ⚠ Potential typosquat of "requests"
depscan check requests 2.28.0  # ✓ No issues
```

### `depscan info`

Show supported ecosystems and formats.

## Typosquat Detection

depscan uses Levenshtein edit distance to detect potential typosquats:

- **Distance ≤ 2**: Flagged as potential typosquat
- **Known packages**: Whitelisted to avoid false positives
- **Ecosystem-aware**: Checks against common package names

Example:

```
⚠ Potential typosquat detected!
   raquests is similar to requests
```

## JSON Output

Both JSON outputs include a `$schema` key pointing at the published schema, so consumers can validate before parsing.

### `depscan scan --json-output`

Validated by [schemas/depscan-output.json](schemas/depscan-output.json).

```json
{
  "$schema": "https://raw.githubusercontent.com/yunaremaia/depscan/main/schemas/depscan-output.json",
  "total": 42,
  "typosquats": [
    {
      "name": "raquests",
      "version": "1.0.0",
      "target": "requests"
    }
  ],
  "by_ecosystem": {
    "pypi": 25,
    "npm": 17
  }
}
```

Fields:

- `total` (integer) — total dependencies found across all lockfiles and manifests
- `typosquats` (array) — dependencies whose names are near-misses of popular packages
  - `name` — the dependency name as written in the manifest
  - `version` — pinned version of the dependency
  - `target` — the well-known package name it appears to imitate
- `by_ecosystem` (object) — dependency count per ecosystem (`cargo`, `npm`, `pypi`)

### `depscan list-deps --json-output`

Validated by [schemas/depscan-list-deps.json](schemas/depscan-list-deps.json).

```json
[
  {
    "name": "requests",
    "version": "2.31.0",
    "ecosystem": "pypi"
  }
]
```

Fields:

- `name` — dependency name
- `version` — pinned version from the lockfile or manifest
- `ecosystem` — one of `cargo`, `npm`, `pypi`

### Validating output

```bash
depscan scan . --json-output | python3 -c "
import json, sys, jsonschema
jsonschema.validate(json.load(sys.stdin), json.load(open('schemas/depscan-output.json')))
"
```

## Development

```bash
# Setup
git clone https://github.com/yunaremaia/depscan.git
cd depscan
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=depscan
```

If this tool is useful to you, a star helps other people find it.

## Related tools

- **[driftcheck](https://github.com/yunaremaia/driftcheck)** — detect version drift between docs and toolchain files
- **[taintrace](https://github.com/yunaremaia/taintrace)** — trace and inspect AI agent execution
- **[license-drift](https://github.com/yunaremaia/license-drift)** — detect license drift across a monorepo
- **[agentcost](https://github.com/yunaremaia/agentcost)** — track and attribute LLM spend per agent

Part of a family of focused, single-purpose developer tools — each one does one thing
and does it well.

## Sponsoring / Treasury

depscan is MIT licensed and maintained in the open. Scanning Cargo, npm, PyPI, and Go
dependency trees for typosquats stays free to run, and keeping the similarity
signatures current is ongoing work. If it saves you time, you can support continued
development through GitHub Sponsors or the Solana treasury below.

Funding details are declared in [`.github/FUNDING.yml`](.github/FUNDING.yml), which is
what GitHub reads to render the **Sponsor** button on this repository.

- **GitHub Sponsors:** [@yunaremaia](https://github.com/sponsors/yunaremaia)
- **Solana:** `Eeztv1nCYUt1fwGWpzKC948gaWfjejYCAuLtUMgzDWbW`

Use the Solana address only for intended donations. Anyone can generate a similar
address, so verify the address against `.github/FUNDING.yml` before sending funds.

If this tool is useful to you, a star helps other people find it.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT
