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

console = Console()


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
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
@click.option("--markdown", "markdown_out", is_flag=True, help="Output as Markdown report")
@click.option("--typosquat/--no-typosquat", default=True, help="Check for typosquats")
def scan(path, json_out, markdown_out, typosquat):
    """Scan a directory for dependencies."""
    scanner = MultiScanner()

    if json_out:
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            results = scanner.scan_and_check(path)
        finally:
            sys.stdout = old_stdout

        output = {
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
        results = scanner.scan_and_check(path)
        progress.update(task, completed=True)

    if json_out:
        output = {
            "total": results["total"],
            "typosquats": [
                {"name": d.name, "version": d.version, "target": d.typosquat_target}
                for d in results["typosquats"]
            ],
            "by_ecosystem": results["by_ecosystem"],
        }
        click.echo(json.dumps(output, indent=2))
        return

    if markdown_out:
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
    scanner = MultiScanner()
    dep = Dependency(name=name, version=version, ecosystem="unknown")

    is_typosquat = scanner.check_typosquat(dep)

    if is_typosquat:
        console.print(Panel(
            f"[red]⚠ Potential typosquat detected![/red]\n"
            f"[bold]{name}[/bold] is similar to [bold]{dep.typosquat_target}[/bold]",
            title="depscan — Check"
        ))
    else:
        console.print(Panel(
            f"[green]✓ {name}@{version} — no issues detected[/green]",
            title="depscan — Check"
        ))


@cli.command()
def info():
    """Show supported ecosystems and formats."""
    console.print(Panel(
        "[bold]Supported Ecosystems:[/bold]\n"
        "• cargo (Cargo.lock)\n"
        "• npm (package-lock.json)\n"
        "• pypi (requirements.txt, poetry.lock)\n"
        "• go (go.mod)\n\n"
        "[bold]Features:[/bold]\n"
        "• Multi-ecosystem scanning\n"
        "• Typosquat detection\n"
        "• JSON output for automation",
        title="depscan — Info"
    ))
