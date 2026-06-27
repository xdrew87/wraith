import asyncio
import logging
import sys
import time
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.aggregator import aggregate, detect_target_type
from core.config import load_config, setup_logging
from core.database import Alert, ExposedCredential, WatchTarget, get_db, init_db
from core.reporter import render_table, to_csv, to_json

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

# Feed display names and whether they need a paid key (for the status table label)
FEED_LABELS = {
    "hibp": ("HIBP", True),
    "dehashed": ("DeHashed", True),
    "intelx": ("IntelX", True),
    "pastebin": ("Pastebin", False),
    "github": ("GitHub", False),
    "hudsonrock": ("HudsonRock", False),
    "crtsh": ("crt.sh", False),
}

SEV_COLORS = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}


def _build_scan_table(target: str, feed_states: dict, scan_start: float) -> Panel:
    elapsed = time.monotonic() - scan_start
    mins, secs = divmod(int(elapsed), 60)

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim", padding=(0, 1))
    table.add_column("Feed", style="bold", width=14)
    table.add_column("Status", width=30)
    table.add_column("Results", justify="right", width=10)
    table.add_column("Time", justify="right", width=7)

    spinner_frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    spin_char = spinner_frames[int(elapsed * 8) % len(spinner_frames)]

    for feed_name, (label, paid) in FEED_LABELS.items():
        state = feed_states.get(feed_name)
        if state is None:
            continue

        status_str = state["status"]
        count = state["count"]
        msg = state["msg"]
        feed_elapsed = state["elapsed"]

        if status_str == "pending":
            status_cell = Text("◌  Queued", style="dim")
            result_cell = Text("—", style="dim")
        elif status_str == "running":
            status_cell = Text(f"{spin_char}  Scanning...", style="yellow")
            result_cell = Text("—", style="dim")
        elif status_str == "skipped":
            status_cell = Text(f"⚠  {msg}", style="yellow")
            if paid:
                status_cell.append("  (paid)", style="dim")
            result_cell = Text("—", style="dim")
        elif status_str == "done":
            if count > 0:
                status_cell = Text("✓  Complete", style="bold green")
                result_cell = Text(str(count), style="bold green")
            else:
                status_cell = Text("✓  No results", style="dim green")
                result_cell = Text("0", style="dim")
        elif status_str == "error":
            status_cell = Text(f"✗  {msg[:28]}", style="red")
            result_cell = Text("—", style="red")
        else:
            status_cell = Text(status_str, style="dim")
            result_cell = Text("—", style="dim")

        time_cell = Text(f"{feed_elapsed:.1f}s", style="dim") if feed_elapsed > 0 else Text("—", style="dim")
        table.add_row(label, status_cell, result_cell, time_cell)

    title = Text.assemble(
        ("🔍 WRAITH", "bold cyan"),
        ("  —  ", "dim"),
        ("Scanning: ", "dim"),
        (target, "bold white"),
        ("   ", ""),
        (f"⏱  {mins:02d}:{secs:02d}", "dim"),
    )
    return Panel(table, title=title, border_style="cyan", padding=(0, 1))


async def _scan_with_display(
    target: str,
    config: dict,
    feed_list: list[str] | None,
) -> list[dict]:
    feed_states: dict[str, dict] = {}
    scan_start = time.monotonic()

    def progress_cb(name: str, status: str, count: int, msg: str, elapsed: float) -> None:
        feed_states[name] = {"status": status, "count": count, "msg": msg, "elapsed": elapsed}

    # Suppress INFO/WARNING console log output while Live display is active
    root_logger = logging.getLogger()
    original_levels = {h: h.level for h in root_logger.handlers}
    for h in root_logger.handlers:
        if h.level < logging.ERROR:
            h.setLevel(logging.ERROR)

    try:
        with Live(
            _build_scan_table(target, feed_states, scan_start),
            console=console,
            refresh_per_second=8,
            transient=False,
        ) as live:

            async def _tick() -> None:
                while True:
                    live.update(_build_scan_table(target, feed_states, scan_start))
                    await asyncio.sleep(0.125)

            ticker = asyncio.create_task(_tick())
            try:
                results = await aggregate(target, config, feed_list, progress_cb=progress_cb)
            finally:
                ticker.cancel()
                live.update(_build_scan_table(target, feed_states, scan_start))
    finally:
        for h, lvl in original_levels.items():
            h.setLevel(lvl)

    return results


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None) -> None:
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
def scan(ctx: click.Context, target: str, feeds: str | None, fmt: str, output: str | None) -> None:
    """Scan a domain or email for credential exposures."""
    console.print(BANNER)
    config = ctx.obj["config"]
    init_db(config)

    feed_list = [f.strip() for f in feeds.split(",")] if feeds else None

    results = asyncio.run(_scan_with_display(target, config, feed_list))

    if not results:
        console.print("\n[yellow]No findings.[/yellow]")
        return

    console.print()
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
def report(
    ctx: click.Context, target: str | None, severity: str | None, fmt: str, output: str | None, limit: int
) -> None:
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
@click.pass_context
def monitor(ctx: click.Context) -> None:
    """Run the continuous monitoring daemon — scans all active watch targets on interval."""
    from core.monitor import monitor_loop

    config = ctx.obj["config"]
    init_db(config)

    interval = config.get("monitor", {}).get("interval_seconds", 3600)
    console.print(f"[cyan]Starting WRAITH monitor daemon (interval: {interval}s)[/cyan]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    try:
        asyncio.run(monitor_loop(config))
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor daemon stopped.[/yellow]")


@cli.command()
@click.option("--port", default=5050, help="Port to run the dashboard on")
@click.option("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
@click.pass_context
def dashboard(ctx: click.Context, port: int, host: str) -> None:
    """Launch the WRAITH web dashboard."""
    config = ctx.obj["config"]
    init_db(config)

    console.print(f"[cyan]Starting WRAITH dashboard on http://{host}:{port}[/cyan]")

    dashboard_app_path = Path(__file__).resolve().parents[2] / "dashboard" / "backend" / "app.py"
    import subprocess

    subprocess.run([sys.executable, str(dashboard_app_path), "--port", str(port), "--host", host])
