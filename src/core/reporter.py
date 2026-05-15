import csv
import io
import json
import logging
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

logger = logging.getLogger(__name__)
console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim white",
}


def render_table(results: list[dict]) -> None:
    if not results:
        console.print("[dim]No findings to display.[/dim]")
        return

    table = Table(
        title=f"[bold]WRAITH — {len(results)} Finding(s)[/bold]",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Target", style="cyan", no_wrap=True)
    table.add_column("Source", style="blue")
    table.add_column("Type", style="white")
    table.add_column("Value", style="white", max_width=50)
    table.add_column("Severity", justify="center")
    table.add_column("Breach", style="dim")

    for r in results:
        severity = r.get("severity", "LOW")
        color = SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            r.get("target", ""),
            r.get("source_feed", ""),
            r.get("exposure_type", ""),
            r.get("value", "")[:60],
            f"[{color}]{severity}[/{color}]",
            r.get("breach_name", "") or "",
        )

    console.print(table)

    summary = _severity_summary(results)
    console.print(
        f"\n[bold]Summary:[/bold] {len(results)} findings — "
        + " | ".join(f"[{SEVERITY_COLORS[k]}]{v} {k}[/{SEVERITY_COLORS[k]}]" for k, v in summary.items() if v > 0)
    )


def to_json(results: list[dict], output_path: Optional[str] = None) -> str:
    safe = []
    for r in results:
        row = {k: v for k, v in r.items() if k != "raw"}
        safe.append(row)

    output = json.dumps(safe, indent=2, default=str)
    if output_path:
        with open(output_path, "w") as f:
            f.write(output)
        logger.info(f"JSON report written to {output_path}")
    return output


def to_csv(results: list[dict], output_path: Optional[str] = None) -> str:
    fields = ["target", "source_feed", "exposure_type", "value", "severity",
              "breach_name", "breach_date", "description"]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(results)
    output = buf.getvalue()

    if output_path:
        with open(output_path, "w", newline="") as f:
            f.write(output)
        logger.info(f"CSV report written to {output_path}")

    return output


def _severity_summary(results: list[dict]) -> dict:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        s = r.get("severity", "LOW")
        if s in summary:
            summary[s] += 1
    return summary
