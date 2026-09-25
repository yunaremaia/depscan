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

from depscan.scanner import MultiScanner, Dependency
from depscan.formatter import MarkdownFormatter
from depscan.sarif import to_sarif, findings_from_scan_results

import re as _re

console = Console(safe_box=True)


def _truncate(text: str, length: int = 40) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= length:
        return text
    return text[:length-3] + "..."


@click.group()
@click.version_option(package_name="depscan")
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
@click.option(
    "--parallel/--no-parallel",
    default=True,
    help="Parse dependency files concurrently",
)
@click.option("--max-workers", type=click.IntRange(min=1), default=4, show_default=True)
def scan(path, json_out, markdown_out, output_format, typosquat, parallel, max_workers):
    """Scan a directory for dependencies."""
    scanner = MultiScanner()

    # Normalise legacy flags into output_format so we have a single code path.
    if json_out and output_format == "text":
        output_format = "json"
    if markdown_out and output_format == "text":
        output_format = "markdown"

    # SARIF output: scan then emit SARIF 2.1.0 to stdout — no progress spinner
    # so the output can be piped directly to a file.
    if output_format == "sarif":
        results = scanner.scan_and_check(
            path, parallel=parallel, max_workers=max_workers
        )
        findings = findings_from_scan_results(results)
        sarif_doc = to_sarif(findings, repo_root=path)
        click.echo(json.dumps(sarif_doc, indent=2))
        if results.get("typosquats") or results.get("vulnerable"):
            sys.exit(1)
        return

    if output_format == "json":
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            results = scanner.scan_and_check(
                path, parallel=parallel, max_workers=max_workers
            )
        finally:
            sys.stdout = old_stdout

        output = {
            "$schema": "https://raw.githubusercontent.com/yunaremaia/depscan/main/schemas/depscan-output.json",
            "total": results["total"],
            "typosquats": [
                {"name": d.name, "version": d.version, "target": d.typosquat_target}
                for d in results["typosquats"]
            ],
            "by_ecosystem": results["by_ecosystem"],
        }
        print(json.dumps(output, indent=2))
        if results["typosquats"]:
            sys.exit(1)
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {path}...", total=None)
        results = scanner.scan_and_check(
            path, parallel=parallel, max_workers=max_workers
        )
        progress.update(task, completed=True)

    if output_format == "markdown":
        formatter = MarkdownFormatter()
        click.echo(formatter.format_full(results))
        if results["typosquats"]:
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


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def list_deps(path, json_out):
    """List all dependencies in a directory."""
    scanner = MultiScanner()
    deps = scanner.scan_directory(path)

    if json_out:
        output = [
            {"name": d.name, "version": d.version, "ecosystem": d.ecosystem}
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
def info():
    """Show supported ecosystems and formats."""
    console.print(Panel(
        "[bold]Supported Ecosystems:[/bold]\n"
        "• cargo (Cargo.lock)\n"
        "• npm (package-lock.json)\n"
        "• pypi (requirements.txt, poetry.lock, Pipfile.lock)\n"
        "• go (go.mod)\n\n"
        "[bold]Features:[/bold]\n"
        "• Multi-ecosystem scanning\n"
        "• Typosquat detection\n"
        "• JSON output for automation",
        title="depscan — Info"
    ))
