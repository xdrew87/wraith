import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from core.config import load_config, setup_logging
from core.database import init_db, get_db, WatchTarget, ExposedCredential, Alert
from core.aggregator import aggregate
from core.reporter import render_table, to_json, to_csv

console = Console()
logger = logging.getLogger(__name__)

BANNER = """
[bold cyan]
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
 ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
 ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
[/bold cyan]
[dim]Credential Exposure Monitor — Authorized use only[/dim]
"""


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[str]) -> None:
    """WRAITH — Credential Exposure Monitor"""
    ctx.ensure_object(dict)
    config = load_config(config_path)
    setup_logging(config)
    ctx.obj["config"] = config


@cli.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Initialize the WRAITH database."""
    console.print(BANNER)
    config = ctx.obj["config"]
    init_db(config)
    console.print("[green]✓ Database initialized[/green]")


@cli.command()
@click.argument("target")
@click.option("--feeds", default=None, help="Comma-separated feed names to use (default: all)")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]))
@click.option("--output", default=None, help="Write output to file")
@click.pass_context
def scan(ctx: click.Context, target: str, feeds: Optional[str], fmt: str, output: Optional[str]) -> None:
    """Scan a domain or email for credential exposures."""
    console.print(BANNER)
    config = ctx.obj["config"]
    init_db(config)

    feed_list = [f.strip() for f in feeds.split(",")] if feeds else None

    console.print(f"[cyan]Scanning:[/cyan] {target}")
    results = asyncio.run(aggregate(target, config, feed_list))

    if not results:
        console.print("[yellow]No findings.[/yellow]")
        return

    if fmt == "table":
        render_table(results)
    elif fmt == "json":
        output_str = to_json(results, output)
        if not output:
            console.print(output_str)
    elif fmt == "csv":
        output_str = to_csv(results, output)
        if not output:
            console.print(output_str)


@cli.command()
@click.argument("target")
@click.pass_context
def watch(ctx: click.Context, target: str) -> None:
    """Add a domain or email to the continuous watch list."""
    config = ctx.obj["config"]
    init_db(config)

    from core.aggregator import detect_target_type
    target_type = detect_target_type(target)

    db = get_db()
    try:
        existing = db.query(WatchTarget).filter_by(target=target).first()
        if existing:
            if not existing.active:
                existing.active = True
                db.commit()
                console.print(f"[green]✓ Reactivated watch target:[/green] {target}")
            else:
                console.print(f"[yellow]Already watching:[/yellow] {target}")
        else:
            wt = WatchTarget(target=target, target_type=target_type, active=True)
            db.add(wt)
            db.commit()
            console.print(f"[green]✓ Now watching:[/green] {target} ({target_type})")
    finally:
        db.close()


@cli.command()
@click.argument("target")
@click.pass_context
def unwatch(ctx: click.Context, target: str) -> None:
    """Remove a target from the watch list."""
    config = ctx.obj["config"]
    init_db(config)

    db = get_db()
    try:
        wt = db.query(WatchTarget).filter_by(target=target).first()
        if not wt:
            console.print(f"[yellow]Not found in watch list:[/yellow] {target}")
        else:
            wt.active = False
            db.commit()
            console.print(f"[green]✓ Removed from watch list:[/green] {target}")
    finally:
        db.close()


@cli.command()
@click.option("--target", default=None, help="Filter by target")
@click.option("--severity", default=None, type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]))
@click.option("--output", default=None, help="Write output to file")
@click.option("--limit", default=100, help="Max results to display")
@click.pass_context
def report(ctx: click.Context, target: Optional[str], severity: Optional[str],
           fmt: str, output: Optional[str], limit: int) -> None:
    """Display credential exposure findings."""
    config = ctx.obj["config"]
    init_db(config)

    db = get_db()
    try:
        query = db.query(ExposedCredential)
        if target:
            query = query.filter(ExposedCredential.target == target)
        if severity:
            query = query.filter(ExposedCredential.severity == severity)

        rows = query.order_by(ExposedCredential.first_seen_at.desc()).limit(limit).all()
        results = [
            {
                "target": r.target,
                "source_feed": r.source_feed,
                "exposure_type": r.exposure_type,
                "value": r.value or "",
                "severity": r.severity,
                "breach_name": r.breach_name,
                "breach_date": r.breach_date,
                "description": r.description,
            }
            for r in rows
        ]
    finally:
        db.close()

    if fmt == "table":
        render_table(results)
    elif fmt == "json":
        output_str = to_json(results, output)
        if not output:
            console.print(output_str)
    elif fmt == "csv":
        output_str = to_csv(results, output)
        if not output:
            console.print(output_str)


@cli.command()
@click.option("--limit", default=50, help="Number of alerts to show")
@click.pass_context
def alerts(ctx: click.Context, limit: int) -> None:
    """Display recent alerts."""
    config = ctx.obj["config"]
    init_db(config)

    db = get_db()
    try:
        rows = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
    finally:
        db.close()

    if not rows:
        console.print("[dim]No alerts.[/dim]")
        return

    from rich.table import Table
    from rich import box

    table = Table(title="WRAITH Alerts", box=box.ROUNDED)
    table.add_column("Time", style="dim")
    table.add_column("Target", style="cyan")
    table.add_column("Feed", style="blue")
    table.add_column("Severity", justify="center")
    table.add_column("Message")

    for a in rows:
        sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(a.severity, "white")
        table.add_row(
            str(a.created_at)[:19],
            a.target,
            a.source_feed,
            f"[{sev_color}]{a.severity}[/{sev_color}]",
            a.message[:80],
        )

    console.print(table)


@cli.command()
@click.option("--port", default=5050, help="Port to run the dashboard on")
@click.pass_context
def dashboard(ctx: click.Context, port: int) -> None:
    """Launch the WRAITH web dashboard."""
    config = ctx.obj["config"]
    init_db(config)

    console.print(f"[cyan]Starting WRAITH dashboard on http://localhost:{port}[/cyan]")

    dashboard_app = Path(__file__).resolve().parents[2] / "dashboard" / "backend" / "app.py"
    import subprocess
    subprocess.run([sys.executable, str(dashboard_app), "--port", str(port)])
