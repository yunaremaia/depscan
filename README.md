# depscan — Multi-ecosystem Dependency Scanner

Scan dependencies across multiple ecosystems with typosquat detection.

## Features

- **Multi-ecosystem**: Cargo, npm, PyPI, Go
- **Typosquat detection**: Levenshtein-based similarity check against known packages
- **Multiple lockfile formats**: Cargo.lock, package-lock.json, requirements.txt, go.mod, poetry.lock
- **JSON output**: For automation and CI integration
- **Rich terminal output**: Tables, panels, progress bars

## Install

```bash
pip install depscan
```

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

# Output as JSON
depscan scan . --format json > deps.json

# Output as SARIF 2.1.0 for GitHub Code Scanning / CI
depscan scan . --format sarif > depscan.sarif

# List all dependencies
depscan list-deps .

# Check a specific package
depscan check requests 2.28.0

# Show supported ecosystems
depscan info
```

## Supported Formats

| Ecosystem | File | Status |
|-----------|------|--------|
| Cargo | Cargo.lock | ✅ |
| npm | package-lock.json | ✅ |
| PyPI | requirements.txt | ✅ |
| PyPI | poetry.lock | ✅ |
| Go | go.mod | ✅ |

## CLI Reference

### `depscan scan [PATH]`

Scan a directory for dependencies and detect potential issues.

```bash
depscan scan . --typosquat  # Enable typosquat detection (default)
depscan scan . --no-typosquat  # Disable typosquat detection
depscan scan /path/to/project --format json  # JSON output
depscan scan /path/to/project --format sarif  # SARIF 2.1.0 output
```

### GitHub Code Scanning Integration

```yaml
- name: Run depscan
  run: |
    pip install depscan
    depscan scan . --format sarif > depscan.sarif

- name: Upload SARIF report
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: depscan.sarif
  if: always()
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

```json
{
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

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT
