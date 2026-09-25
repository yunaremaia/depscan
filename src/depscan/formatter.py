"""Output formatters for depscan reports."""
from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any


class MarkdownFormatter:
    """Format scan results as Markdown reports."""

    def __init__(self, safe_output: bool = True):
        self.safe_output = safe_output

    def _escape(self, value: Any) -> str:
        """Escape user-controlled text before embedding it in Markdown."""
        text = str(value)
        return html.escape(text, quote=True) if self.safe_output else text

    def format_summary(self, results: dict[str, Any]) -> str:
        """Return a Markdown summary of the scan report."""
        lines = []
        total = results.get("total", 0)
        typosquats = results.get("typosquats", [])
        by_eco = results.get("by_ecosystem", {})
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines.append(f"# Dependency Scan Report")
        lines.append(f"\n**Scan Date:** {timestamp}")
        lines.append(f"\n**Total Dependencies Scanned:** {total}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **{total}** total dependencies")
        lines.append(f"- **{len(typosquats)}** potential typosquats detected")
        lines.append("")

        if by_eco:
            lines.append("## Dependencies by Ecosystem")
            lines.append("")
            lines.append("| Ecosystem | Count |")
            lines.append("|-----------|-------|")
            for eco, count in sorted(by_eco.items()):
                lines.append(f"| {self._escape(eco)} | {count} |")
            lines.append("")

        if typosquats:
            lines.append("## Potential Typosquats")
            lines.append("")
            lines.append("| Package | Version | Ecosystem | Suspected Target |")
            lines.append("|---------|---------|-----------|-------------------|")
            for dep in typosquats:
                target = dep.typosquat_target or "—"
                lines.append(
                    f"| **{self._escape(dep.name)}** | {self._escape(dep.version)} | "
                    f"{self._escape(dep.ecosystem)} | {self._escape(target)} |"
                )
            lines.append("")

        vulnerable = results.get("vulnerable", [])
        if vulnerable:
            lines.append("## Vulnerability Details")
            lines.append("")
            lines.append("| Package | Version | Vulnerability | Severity | Description |")
            lines.append("|---------|---------|---------------|----------|-------------|")
            for dep in vulnerable:
                for vulnerability in dep.known_vulnerabilities:
                    lines.append(
                        f"| **{self._escape(dep.name)}** | {self._escape(dep.version)} | "
                        f"{self._escape(vulnerability.id)} | "
                        f"{self._escape(vulnerability.severity)} | "
                        f"{self._escape(vulnerability.description)} |"
                    )
            lines.append("")

        if not typosquats and total > 0:
            lines.append("## [OK] Scan Complete")
            lines.append("")
            lines.append("No typosquats detected. All dependencies appear legitimate.")
            lines.append("")

        return "\n".join(lines)

    def format_full(self, results: dict[str, Any]) -> str:
        """Return a full Markdown report including per-ecosystem details."""
        output = self.format_summary(results)
        by_eco = results.get("by_ecosystem", {})

        if not by_eco:
            return output

        lines = [output]
        lines.append("## Detailed Results by Ecosystem")
        lines.append("")

        # We don't have per-dependency details in the current results structure,
        # but we can show the ecosystem breakdown with counts.
        for eco, count in sorted(by_eco.items()):
            lines.append(f"### {self._escape(eco)}")
            lines.append("")
            lines.append(f"**{count}** dependencies found.")
            lines.append("")

        return "\n".join(lines)
