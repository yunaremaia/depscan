"""CLI for depscan — Multi-ecosystem dependency scanner."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from depscan import __version__
from depscan.scanner import MultiScanner, Dependency
from depscan.formatter import MarkdownFormatter
from depscan.sarif import to_sarif, findings_from_scan_results

import re as _re

console = Console(safe_box=True)


def _should_fail(results: dict, fail_on: str | None) -> bool:
    """Return whether the selected finding policy should fail the command."""
    if fail_on is None:
        return False
    has_typosquats = bool(results.get("typosquats"))
    has_vulnerabilities = bool(results.get("vulnerable"))
    if fail_on == "typosquat":
        return has_typosquats
    if fail_on == "vulnerable":
        return has_vulnerabilities
    return has_typosquats or has_vulnerabilities


def _truncate(text: str, length: int = 40) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= length:
        return text
    return text[:length-3] + "..."


@click.group()
@click.version_option(version=__version__, prog_name="depscan")
def cli():
    """depscan — Multi-ecosystem dependency scanner."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON (deprecated: use --format json)")
@click.option("--markdown", "markdown_out", is_flag=True, help="Output as Markdown report (deprecated: use --format markdown)")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "markdown", "sarif"], case_sensitive=False),
    default="text",
    help="Output format: text (default), json, markdown, or sarif (SARIF 2.1.0 for GitHub Code Scanning).",
)
@click.option("--typosquat/--no-typosquat", default=True, help="Check for typosquats")
@click.option("--strict", is_flag=True,
              help="Fail instead of skipping invalid dependency names")
@click.option(
    "--safe-output/--unsafe-output",
    default=True,
    help="Escape HTML in Markdown output (enabled by default)",
)
@click.option("--include-hidden", is_flag=True, help="Scan hidden directories")
@click.option("--exclude", "exclude_dirs", multiple=True,
              help="Additional directory name or glob to skip")
@click.option("--ignore/--no-ignore", "respect_ignores", default=True,
              help="Respect .gitignore and .npmignore files")
@click.option("--exclude-pattern", "exclude_patterns", multiple=True,
              help="Additional path pattern to exclude")
@click.option("--parallel/--no-parallel", default=True,
              help="Parse dependency files concurrently")
@click.option("--max-workers", type=click.IntRange(min=1), default=4, show_default=True,
              help="Worker count for parallel parsing")
@click.option("--severity", help="Comma-separated severities to include")
@click.option("--ecosystem", help="Comma-separated ecosystems to include")
@click.option("--min-severity", type=click.Choice(["low", "medium", "high", "critical"]))
@click.option(
    "--fail-on",
    type=click.Choice(["typosquat", "vulnerable", "any"]),
    help="Exit 1 when selected findings are present",
)
def scan(
    path, json_out, markdown_out, output_format, typosquat, strict, safe_output,
    include_hidden, exclude_dirs, respect_ignores, exclude_patterns,
    parallel, max_workers, severity, ecosystem, min_severity, fail_on,
):
    """Scan a directory for dependencies."""
    scanner = MultiScanner(strict=strict)

    # Normalise legacy flags into output_format so we have a single code path.
    if json_out and output_format == "text":
        output_format = "json"
    if markdown_out and output_format == "text":
        output_format = "markdown"

    def run_scan():
        return scanner.scan_and_check(
            path,
            parallel=parallel,
            max_workers=max_workers,
            excludes=set(exclude_dirs),
            include_hidden=include_hidden,
            respect_ignores=respect_ignores,
            exclude_patterns=list(exclude_patterns),
        )

    def apply_filters(results):
        from depscan.filters import filter_results
        severities = (
            {value.strip().lower() for value in severity.split(",") if value.strip()}
            if severity else None
        )
        ecosystems = (
            {value.strip().lower() for value in ecosystem.split(",") if value.strip()}
            if ecosystem else None
        )
        return filter_results(
            results,
            severities=severities,
            ecosystems=ecosystems,
            min_severity=min_severity,
        )

    def should_fail(results) -> bool:
        return _should_fail(results, fail_on)

    # SARIF output: scan then emit SARIF 2.1.0 to stdout — no progress spinner
    # so the output can be piped directly to a file.
    if output_format == "sarif":
        results = apply_filters(run_scan())
        findings = findings_from_scan_results(results)
        sarif_doc = to_sarif(findings, repo_root=path)
        click.echo(json.dumps(sarif_doc, indent=2))
        if should_fail(results):
            sys.exit(1)
        return

    if output_format == "json":
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            results = apply_filters(run_scan())
        finally:
            sys.stdout = old_stdout

        output = {
            "$schema": "https://raw.githubusercontent.com/yunaremaia/depscan/main/schemas/depscan-output.json",
            "total": results["total"],
            "typosquats": [
                {"name": d.name, "version": d.version, "target": d.typosquat_target}
                for d in results["typosquats"]
            ],
            "vulnerabilities": [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "cves": [
                        {
                            "id": vulnerability.id,
                            "severity": vulnerability.severity,
                            "description": vulnerability.description,
                        }
                        for vulnerability in dep.known_vulnerabilities
                    ],
                }
                for dep in results.get("vulnerable", [])
            ],
            "by_ecosystem": results["by_ecosystem"],
        }
        print(json.dumps(output, indent=2))
        if should_fail(results):
            sys.exit(1)
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {path}...", total=None)
        results = apply_filters(run_scan())
        progress.update(task, completed=True)

    if output_format == "markdown":
        formatter = MarkdownFormatter(safe_output=safe_output)
        click.echo(formatter.format_full(results))
        if should_fail(results):
            sys.exit(1)
        return

    from rich.text import Text
    console.print(Panel(
        Text.assemble(
            ("Scan Results", "bold"),
            "\n",
            ("Total dependencies: ", ""),
            (str(results['total']), "cyan"),
            (" | Typosquats: ", ""),
            (str(len(results['typosquats'])), "red"),
        ),
        title=f"depscan — {path}"
    ))

    if results["typosquats"]:
        table = Table(title="Potential Typosquats")
        table.add_column("Name", style="red")
        table.add_column("Version")
        table.add_column("Ecosystem")
        table.add_column("Suspected Target")

        for dep in results["typosquats"]:
            table.add_row(dep.name, dep.version, dep.ecosystem, dep.typosquat_target)

        console.print(table)

    if results["by_ecosystem"]:
        eco_table = Table(title="By Ecosystem")
        eco_table.add_column("Ecosystem", style="cyan")
        eco_table.add_column("Count", justify="right")

        for eco, count in sorted(results["by_ecosystem"].items()):
            eco_table.add_row(eco, str(count))

        console.print(eco_table)

    if should_fail(results):
        raise click.exceptions.Exit(1)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def list_deps(path, json_out):
    """List all dependencies in a directory."""
    scanner = MultiScanner()
    deps = scanner.scan_directory(path)

    if json_out:
        output = [
            {
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "source_file": d.source_file,
            }
            for d in deps
        ]
        click.echo(json.dumps(output, indent=2))
        return

    console.print(Panel(
        f"[bold]Dependencies in {path}[/bold] — {len(deps)} found",
        title="depscan — List"
    ))

    table = Table()
    table.add_column("Name", width=30)
    table.add_column("Version", width=15)
    table.add_column("Ecosystem", width=10)

    for dep in sorted(deps, key=lambda d: (d.ecosystem, d.name)):
        table.add_row(dep.name, dep.version, dep.ecosystem)

    console.print(table)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--allow-known",
    is_flag=True,
    help="Do not fail for known vulnerabilities; typosquats still fail",
)
@click.option("--sarif", "sarif_out", is_flag=True, help="Emit SARIF 2.1.0")
def ci(path, allow_known, sarif_out):
    """Enforce dependency security in CI."""
    scanner = MultiScanner()
    results = scanner.scan_and_check(path)

    if sarif_out:
        findings = findings_from_scan_results(results)
        click.echo(json.dumps(to_sarif(findings, repo_root=path), indent=2))
    else:
        for dep in results.get("typosquats", []):
            click.echo(
                f"TYPOSQUAT: {dep.name} resembles {dep.typosquat_target}",
                err=True,
            )
        if not allow_known:
            for dep in results.get("vulnerable", []):
                click.echo(
                    f"VULNERABLE: {dep.name}@{dep.version}",
                    err=True,
                )

    has_findings = bool(results.get("typosquats"))
    if not allow_known:
        has_findings = has_findings or bool(results.get("vulnerable"))
    if has_findings:
        raise click.exceptions.Exit(1)
    click.echo("No blocking dependency findings", err=not sarif_out)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--write", is_flag=True, help="Create or replace the known-good manifest")
def verify(path, write):
    """Create or verify SHA256 lockfile integrity data."""
    from depscan.integrity import verify_manifest, write_manifest

    root = Path(path).resolve()
    if write:
        from depscan.scanner import LOCK_PATTERNS

        files = []
        seen = set()
        for pattern in LOCK_PATTERNS:
            for lockfile in root.rglob(pattern):
                resolved = lockfile.resolve()
                if lockfile.is_file() and resolved not in seen:
                    seen.add(resolved)
                    files.append(lockfile)
        target = write_manifest(root, files)
        click.echo(f"Wrote integrity manifest: {target}")
        return
    try:
        violations = verify_manifest(root)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc
    if violations:
        for violation in violations:
            click.echo(
                f"INTEGRITY FAILURE: {violation.file} "
                f"(expected {violation.expected}, got {violation.actual or 'missing'})",
                err=True,
            )
        raise click.exceptions.Exit(2)
    click.echo("Lockfile integrity verified")


@cli.command()
@click.argument("name")
@click.argument("version")
def check(name, version):
    """Check a specific dependency for issues."""
    # Security: strict validation prevents command injection
    # if this function is ever wired into automated CI.
    if not _re.match(r'^[a-zA-Z0-9_.\-/:@]+$', name):
        console.print("[red]Invalid package name[/red]")
        sys.exit(2)
    if "://" in name or ";" in name or "|" in name or "&" in name or "$" in name:
        console.print("[red]Invalid package name[/red]")
        sys.exit(2)
    scanner = MultiScanner()
    dep = Dependency(name=name, version=version, ecosystem="unknown")

    is_typosquat = scanner.check_typosquat(dep)

    if is_typosquat:
        console.print(Panel(
            f"[red][!] Potential typosquat detected![/red]\n"
            f"[bold]{name}[/bold] is similar to [bold]{dep.typosquat_target}[/bold]",
            title="depscan - Check"
        ))
    else:
        console.print(Panel(
            f"[green][OK] {name}@{version} - no issues detected[/green]",
            title="depscan - Check"
        ))


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--format",
    "sbom_format",
    type=click.Choice(["cyclonedx", "spdx"]),
    default="cyclonedx",
    show_default=True,
)
@click.option("--output", type=click.Path(dir_okay=False), help="Write SBOM to a file")
def sbom(path, sbom_format, output):
    """Generate a CycloneDX or SPDX software bill of materials."""
    from depscan.sbom import dumps, to_cyclonedx, to_spdx

    dependencies = MultiScanner().scan_directory(path)
    document = (
        to_cyclonedx(dependencies)
        if sbom_format == "cyclonedx"
        else to_spdx(dependencies)
    )
    rendered = dumps(document)
    if output:
        Path(output).write_text(rendered + "\n", encoding="utf-8")
        click.echo(f"Wrote {sbom_format} SBOM to {output}")
    else:
        click.echo(rendered)


@cli.command()
def info():
    """Show supported ecosystems and formats."""
    from depscan import __version__

    console.print(Panel(
        f"[bold]Version:[/bold] {__version__}\n\n"
        "[bold]Supported Ecosystems:[/bold]\n"
        "• cargo (Cargo.lock)\n"
        "• npm (package-lock.json)\n"
        "• pypi (requirements.txt, poetry.lock, Pipfile.lock)\n"
        "• go (go.mod)\n\n"
        "[bold]Output Formats:[/bold]\n"
        "• terminal (default)\n"
        "• JSON (--format json)\n"
        "• Markdown (--format markdown)\n"
        "• SARIF (--format sarif)\n\n"
        "[bold]Features:[/bold]\n"
        "• Multi-ecosystem scanning\n"
        "• Typosquat detection\n"
        "• JSON output for automation",
        title="depscan — Info"
    ))


@cli.command(name="init")
@click.argument("path", default=".depscan.yml", type=click.Path())
@click.option(
    "--profile",
    type=click.Choice(["strict", "relaxed", "ci"]),
    default="relaxed",
    show_default=True,
)
@click.option("--force", is_flag=True, help="Overwrite an existing configuration")
def init_config(path, profile, force):
    """Create a starter .depscan.yml configuration."""
    from depscan.config import render_profile

    config_path = Path(path)
    if config_path.exists() and not force:
        raise click.ClickException(
            f"{config_path} already exists; use --force to overwrite it"
        )
    config_path.write_text(render_profile(profile), encoding="utf-8")
    click.echo(f"Created {config_path} with the {profile} profile")


@cli.command()
@click.argument(
    "path",
    default=".depscan.yml",
    type=click.Path(exists=True, dir_okay=False),
)
def validate(path):
    """Validate a depscan configuration file."""
    from depscan.config import load_config

    try:
        load_config(path)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{path} is valid")
