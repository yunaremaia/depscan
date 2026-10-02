# Changelog

All notable changes to depscan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- The distribution name is now `depscan-py`. The bare `depscan` name on PyPI
  belongs to an unrelated third-party project (linkedlist771/depscan), so the
  previous name could never be published, and every bare `pip install depscan`
  silently installed that other author's package. The console script, the
  pre-commit hook id and the `depscan` command itself are unchanged.
- `.pre-commit-hooks.yaml` now installs the hook from this repository instead of
  resolving `depscan` through PyPI, which previously made pre-commit run another
  author's `depscan scan` on every commit.
- `--version` no longer resolves the version through the distribution name, so
  it keeps working under the renamed distribution.
- Added a publish workflow triggered on GitHub release publication.

### Added
- Support for `Pipfile.lock` (JSON) format in `DependencyParser` and `MultiScanner`

## [0.1.0] - 2026-09-09

### Added
- Initial release: Multi-ecosystem Dependency Scanner
- Support for multiple ecosystems: Cargo (`Cargo.lock`), npm (`package-lock.json`), PyPI (`requirements.txt`, `poetry.lock`), and Go (`go.mod`)
- Typosquat detection via Levenshtein-based similarity checks against known legitimate packages
- Rich terminal output formatting with tables, progress indicators, and status badges
- Machine-readable JSON output mode (`--json-output`) for CI/CD workflows and automated pipelines
- CLI subcommands: `scan`, `list-deps`, `check`, `info`, and `version`
