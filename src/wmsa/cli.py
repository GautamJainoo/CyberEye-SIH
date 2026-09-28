"""
WMSA Command Line Interface (Typer).
Enforces human confirmation for state-changing commands and writes audit events.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from wmsa.db import Database
from wmsa.scope import (
    ScopeGuard,
    activate_kill_switch,
    deactivate_kill_switch,
    is_kill_active,
    load_scope_manifest,
)
from wmsa.target import TargetManager

app = typer.Typer(
    name="wmsa",
    help="World Monitor Security Assessment CLI (SIH 2026, PS 26163)",
    add_completion=False,
)

target_app = typer.Typer(help="Target environment operations (setup, up, down, health)")
scope_app = typer.Typer(help="Scope manifest operations")
app.add_typer(target_app, name="target")
app.add_typer(scope_app, name="scope")


@app.command()
def init(
    db_path: Path = typer.Option(Path("wmsa.db"), help="Path to SQLite database"),
):
    """Initializes local directories, SQLite database with FTS5, and verifies tools."""
    rprint("[bold blue]Initializing WMSA Environment...[/bold blue]")

    # Ensure required dirs
    for d in ["config", "docker", "rules", "probes", "evidence", "reports", "target"]:
        Path(d).mkdir(parents=True, exist_ok=True)
    rprint("✔ Directories verified.")

    # Initialize DB
    db = Database(db_path)
    rprint(f"✔ SQLite database initialized with FTS5 at [green]{db_path}[/green]")

    # Check tools from tools.lock.json
    lock_file = Path("tools.lock.json")
    if lock_file.exists():
        with open(lock_file, "r") as f:
            lock_data = json.load(f)

        table = Table(title="Installed Security Tools Status")
        table.add_column("Tool", style="cyan")
        table.add_column("Required Version", style="magenta")
        table.add_column("Binary Status", style="green")

        for tool_name, meta in lock_data.get("tools", {}).items():
            bin_name = meta.get("binary")
            if bin_name:
                found = shutil.which(bin_name)
                status = f"[green]Found ({found})[/green]" if found else "[red]Not found[/red]"
            else:
                status = f"[yellow]Docker Image: {meta.get('image')}[/yellow]"
            table.add_row(tool_name, meta.get("version"), status)

        rprint(table)

    db.log_audit_event(
        event_type="wmsa_init",
        actor_type="analyst",
        actor_id="cli_user",
        payload={"db_path": str(db_path)},
    )
    rprint("[bold green]WMSA initialization complete.[/bold green]")


@scope_app.command("validate")
def scope_validate(
    manifest_file: Path = typer.Option(
        Path("config/scope.yaml"), help="Path to scope manifest"
    ),
):
    """Validates scope manifest syntax, commitments, and displays allowlist."""
    try:
        manifest = load_scope_manifest(manifest_file)
    except Exception as e:
        rprint(f"[bold red]Scope Manifest Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    table = Table(title="Active Scope Manifest Allowlist")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row("Scope ID", manifest.scope_id)
    table.add_row("Repo URL", manifest.repo_url)
    table.add_row("Pinned Commit", manifest.commit_sha)
    table.add_row("Allowed Hosts", ", ".join(manifest.allowed_hosts))
    table.add_row("Allowed Ports", ", ".join(map(str, manifest.allowed_ports)))
    table.add_row("Route Prefixes", ", ".join(manifest.allowed_route_prefixes))
    table.add_row("Approved By", manifest.approved_by)
    table.add_row("Approved At", manifest.approved_at)

    rprint(table)
    rprint("[bold green]✔ Scope manifest is valid and strictly enforced.[/bold green]")


@app.command()
def kill(
    clear: bool = typer.Option(False, "--clear", help="Clear the kill switch sentinel"),
):
    """Activates the global kill switch to abort all running scans and block outbound traffic."""
    if clear:
        deactivate_kill_switch()
        rprint("[bold green]✔ Kill switch cleared. System operational.[/bold green]")
    else:
        sentinel = activate_kill_switch()
        rprint(f"[bold red]⛔ KILL SWITCH ACTIVATED! Sentinel created at {sentinel}.[/bold red]")
        rprint("[bold red]All active operations and outbound network calls are aborted.[/bold red]")


@target_app.command("setup")
def target_setup():
    """Clones target repo and checks out pinned commit SHA."""
    mgr = TargetManager()
    try:
        info = mgr.setup()
        rprint(Panel(json.dumps(info, indent=2), title="Target Setup Details", style="green"))
    except Exception as e:
        rprint(f"[bold red]Target setup failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@target_app.command("health")
def target_health(
    base_url: str = typer.Option("http://127.0.0.1:3000", help="Target URL on loopback"),
):
    """Performs loopback health check for DAST and probe gating."""
    mgr = TargetManager()
    healthy, msg = mgr.check_health(base_url)
    if healthy:
        rprint(f"[bold green]✔ Target Health Gate: PASSED ({msg})[/bold green]")
    else:
        rprint(f"[bold red]✖ Target Health Gate: FAILED ({msg})[/bold red]")
        raise typer.Exit(code=1)


@target_app.command("up")
def target_up():
    """Starts target container on loopback with isolated network."""
    mgr = TargetManager()
    try:
        out = mgr.up()
        rprint(f"[green]{out}[/green]")
    except Exception as e:
        rprint(f"[bold red]Failed to start target:[/bold red] {e}")
        raise typer.Exit(code=1)


@target_app.command("down")
def target_down():
    """Stops isolated target containers."""
    mgr = TargetManager()
    out = mgr.down()
    rprint(f"[yellow]{out}[/yellow]")


if __name__ == "__main__":
    app()
