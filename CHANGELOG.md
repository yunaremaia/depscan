# Changelog

All notable changes to depscan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-09

### Added
- Initial release: Multi-ecosystem Dependency Scanner
- Support for multiple ecosystems: Cargo (`Cargo.lock`), npm (`package-lock.json`), PyPI (`requirements.txt`, `poetry.lock`), and Go (`go.mod`)
- Typosquat detection via Levenshtein-based similarity checks against known legitimate packages
- Rich terminal output formatting with tables, progress indicators, and status badges
- Machine-readable JSON output mode (`--json-output`) for CI/CD workflows and automated pipelines
- CLI subcommands: `scan`, `list-deps`, `check`, `info`, and `version`
