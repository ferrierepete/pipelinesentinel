"""PipelineSentinel CLI — Rich Terminal Interface."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown

from src.graph import build_graph, build_graph_with_interrupts
from src.state import PipelineSentinelState

load_dotenv()

console = Console()

STEP_LABELS = [
    (1, 8, "Parsing dependencies"),
    (2, 8, "Identifying AI/ML packages"),
    (3, 8, "Querying OSV database"),
    (4, 8, "Querying GitHub Advisories"),
    (5, 8, "Checking CISA KEV"),
    (6, 8, "Correlating findings"),
    (7, 8, "Assessing risk scores"),
    (8, 8, "Generating briefing"),
]

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}


def print_banner():
    console.print(Panel(
        "[bold cyan]PipelineSentinel[/bold cyan]\n"
        "[dim]AI/ML Dependency Vulnerability Intelligence[/dim]\n"
        "[dim]LangGraph-powered security scanning[/dim]",
        title="🛡️",
        border_style="cyan",
    ))


def print_summary_table(findings: list[dict], ai_ml_deps: list[dict], total_deps: int):
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in summary:
            summary[sev] += 1

    table = Table(title="Scan Summary", show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Total Dependencies", str(total_deps))
    table.add_row("AI/ML Dependencies", str(len(ai_ml_deps)))
    table.add_row("[bold red]Critical[/bold red]", str(summary["CRITICAL"]))
    table.add_row("[red]High[/red]", str(summary["HIGH"]))
    table.add_row("[yellow]Medium[/yellow]", str(summary["MEDIUM"]))
    table.add_row("[green]Low[/green]", str(summary["LOW"]))
    console.print(table)

    # Severity breakdown bar
    if findings:
        total = len(findings)
        bar_parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if summary[sev] > 0:
                pct = summary[sev] / total
                bar_parts.append(f"[{SEVERITY_COLORS[sev]}]{'█' * int(pct * 40)}[/]")
        console.print(f"\n{''.join(bar_parts)}")
        console.print()


def print_findings(findings: list[dict]):
    if not findings:
        console.print("[green]✅ No vulnerabilities found in AI/ML dependencies.[/green]")
        return

    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "INFO")
        color = SEVERITY_COLORS.get(severity, "white")
        kev_badge = "[bold red]⚡ IN KEV[/bold red]" if finding.get("in_kev") else ""

        header = f"[{color}]{severity}[/{color}] {finding['package']} {finding.get('vuln_id', '')} {kev_badge}"

        details = (
            f"  [dim]CVSS:[/dim] {finding.get('cvss', 0):.1f}  "
            f"[dim]Risk Score:[/dim] {finding.get('risk_score', 0):.1f}  "
            f"[dim]Priority:[/dim] {finding.get('priority', 'N/A')}  "
            f"[dim]AI Risk:[/dim] {finding.get('ai_risk_description', 'N/A')}\n"
            f"  [dim]Version:[/dim] {finding.get('current_version', '?')} → "
            f"[green]{finding.get('fix_version', 'N/A')}[/green]\n"
            f"  {finding.get('summary', '')}"
        )

        console.print(Panel(details, title=header, border_style=color, padding=(0, 2)))


def print_briefing(briefing: str):
    console.print(Panel(
        Markdown(briefing),
        title="📋 Remediation Briefing",
        border_style="blue",
        padding=(1, 2),
    ))


def export_json(state: dict, output_path: str):
    """Export scan results to JSON file."""
    export_data = {
        "dependencies": state.get("dependencies", []),
        "ai_ml_deps": state.get("ai_ml_deps", []),
        "osv_vulns": state.get("osv_vulns", []),
        "ghsa_vulns": state.get("ghsa_vulns", []),
        "kev_entries": state.get("kev_entries", []),
        "findings": state.get("findings", []),
        "briefing": state.get("briefing", ""),
    }

    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2, default=str)
    console.print(f"[green]Exported to {output_path}[/green]")


async def scan_file(file_path: str, output_json: str | None = None):
    """Run the full PipelineSentinel scan on a dependency file."""
    print_banner()

    # Read file
    try:
        content = Path(file_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        sys.exit(1)

    # Build graph
    graph = build_graph()

    initial_state = {
        "file_path": file_path,
        "file_content": content,
    }

    console.print(f"\n[bold]Scanning:[/bold] {file_path}\n")

    # Run the graph with progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing scan...", total=8)

        # We'll update progress by streaming the graph
        result = {}
        completed_steps = 0
        async for event in graph.astream_events(initial_state, version="v2"):
            event_name = event.get("event", "")
            event_data = event.get("data", {})
            event_tag = event.get("name", "")

            # Map node completion to progress
            if event_name == "on_chain_end" and "node" in event.get("tags", []):
                node_name = event_tag
                progress_map = {
                    "parse_dependencies": (2, "Dependencies parsed"),
                    "ingest_osv": (3, "OSV query complete"),
                    "ingest_ghsa": (4, "GHSA query complete"),
                    "ingest_kev": (5, "KEV check complete"),
                    "correlate_findings": (6, "Findings correlated"),
                    "assess_risk": (7, "Risk assessed"),
                    "generate_briefing": (8, "Briefing generated"),
                }
                if node_name in progress_map and step_num > completed_steps:
                    step_num, description = progress_map[node_name]
                    advance = step_num - completed_steps
                    if advance > 0:
                        progress.advance(task, advance)
                        progress.update(task, description=description)
                        completed_steps = step_num

            # Capture final state
            if event_name == "on_chain_end" and not event.get("tags"):
                if isinstance(event_data, dict) and "output" in event_data:
                    result = event_data["output"]

        # Ensure progress reaches 100%
        remaining = 8 - completed_steps
        if remaining > 0:
            progress.advance(task, remaining)
        progress.update(task, description="Scan complete ✓")

    if not result:
        console.print("[red]Error: Scan produced no results[/red]")
        sys.exit(1)

    # Display results
    console.print()
    findings = result.get("findings", [])
    ai_ml_deps = result.get("ai_ml_deps", [])
    total_deps = result.get("dependencies", [])

    print_summary_table(findings, ai_ml_deps, len(total_deps))
    print_findings(findings)

    briefing = result.get("briefing", "")
    if briefing:
        print_briefing(briefing)

    if output_json:
        export_json(result, output_json)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="PipelineSentinel — AI/ML Dependency Vulnerability Intelligence",
    )
    parser.add_argument("file", help="Path to requirements.txt, pyproject.toml, or package.json")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    parser.add_argument("--version", action="version", version="PipelineSentinel 0.1.0")

    args = parser.parse_args()

    asyncio.run(scan_file(args.file, args.output))


if __name__ == "__main__":
    main()
