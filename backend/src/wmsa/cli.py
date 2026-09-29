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
from typing import List, Optional

import typer
import uvicorn
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from wmsa.adapters.probes import ProbesAdapter
from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.lifecycle import LifecycleManager, LifecycleViolation
from wmsa.orchestrator import Orchestrator
from wmsa.patching import PatchManager
from wmsa.report import ReportExporter
from wmsa.retest import RetestEngine
from wmsa.scope import (
    ScopeGuard,
    activate_kill_switch,
    deactivate_kill_switch,
    is_kill_active,
    load_scope_manifest,
)
from wmsa.intel import ThreatIntelManager
from wmsa.target import TargetManager

app = typer.Typer(
    name="wmsa",
    help="World Monitor Security Assessment CLI (SIH 2026, PS 26163)",
    add_completion=False,
)

target_app = typer.Typer(help="Target environment operations")
scope_app = typer.Typer(help="Scope manifest operations")
probes_app = typer.Typer(help="World Monitor specific safe probe operations")
findings_app = typer.Typer(help="Findings management and detail inspection")
patch_app = typer.Typer(help="Patch proposal and isolated git branching")
report_app = typer.Typer(help="Report export operations")
intel_app = typer.Typer(help="Threat intelligence and CISA KEV synchronization")

app.add_typer(target_app, name="target")
app.add_typer(scope_app, name="scope")
app.add_typer(probes_app, name="probes")
app.add_typer(findings_app, name="findings")
app.add_typer(patch_app, name="patch")
app.add_typer(report_app, name="report")
app.add_typer(intel_app, name="intel")


@app.command()
def init(
    db_path: Path = typer.Option(Path("wmsa.db"), help="Path to SQLite database"),
):
    """Initializes local directories, SQLite database with FTS5, and verifies tools."""
    rprint("[bold blue]Initializing WMSA Environment...[/bold blue]")

    for d in ["config", "docker", "rules", "probes", "evidence", "reports", "target"]:
        Path(d).mkdir(parents=True, exist_ok=True)
    rprint("✔ Directories verified.")

    db = Database(db_path)
    rprint(f"✔ SQLite database initialized with FTS5 at [green]{db_path}[/green]")

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


@app.command()
def scan(
    profile: str = typer.Option("lite", help="Scan profile: 'lite' or 'standard'"),
    tools: Optional[str] = typer.Option(None, help="Comma-separated tools to run"),
):
    """Executes multi-scanner assessment run against pinned local target."""
    rprint(f"[bold blue]Initiating WMSA scan with profile: {profile}...[/bold blue]")
    orch = Orchestrator()
    tool_list = [t.strip() for t in tools.split(",")] if tools else None
    res = orch.run_scan(profile_name=profile, selected_tools=tool_list)

    table = Table(title="Scan Execution Results")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Profile", style="yellow")
    table.add_column("Duration (s)", style="magenta")
    table.add_column("Findings Ingested", style="green")

    table.add_row(res["scan_id"], res["profile"], f"{res['duration_seconds']:.1f}", str(res["findings_count"]))
    rprint(table)


@probes_app.command("list")
def probes_list():
    """Lists all code-derived safe probe recipes."""
    adapter = ProbesAdapter()
    recipes = adapter.list_recipes()

    table = Table(title="World Monitor Specific Probes")
    table.add_column("ID", style="cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Title", style="green")
    table.add_column("Max Reqs", style="magenta")

    for r in recipes:
        table.add_row(r.get("id"), r.get("category"), r.get("title"), str(r.get("max_requests")))
    rprint(table)


@probes_app.command("run")
def probes_run(recipe_id: str):
    """Executes a specific safe probe recipe against the target."""
    adapter = ProbesAdapter()
    recipes = adapter.list_recipes()
    target_recipe = next((r for r in recipes if r.get("id") == recipe_id), None)
    if not target_recipe:
        rprint(f"[bold red]Recipe '{recipe_id}' not found.[/bold red]")
        raise typer.Exit(code=1)

    rprint(f"Executing recipe [cyan]{recipe_id}[/cyan]...")
    res = adapter.execute_recipe(
        recipe=target_recipe,
        target_base_url="http://127.0.0.1:3000",
        output_dir=Path("evidence") / "cli_probes",
        commit_sha="manual",
        build_id="b-manual",
    )
    rprint(f"Verdict: [bold]{res.verdict}[/bold]")
    rprint(f"Evidence artifact: {res.evidence_artifact_path}")


@findings_app.command("list")
def findings_list(
    status: Optional[str] = typer.Option(None, help="Filter by status"),
    category: Optional[str] = typer.Option(None, help="Filter by category"),
):
    """Lists normalized findings from SQLite database."""
    db = Database()
    query = "SELECT finding_id, title, category, status, severity, commit_sha FROM findings WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status.upper())
    if category:
        query += " AND category = ?"
        params.append(category.lower())

    with db.get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    table = Table(title="Normalized Security Findings")
    table.add_column("Finding ID", style="cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Status", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="white")

    for r in rows:
        table.add_row(r["finding_id"][:8], r["category"], r["status"], r["severity"], r["title"])
    rprint(table)


@findings_app.command("show")
def findings_show(finding_id: str):
    """Displays complete finding details and evidence."""
    db = Database()
    ev_mgr = EvidenceManager(db)
    lc_mgr = LifecycleManager(db, ev_mgr)

    # Allow prefix match on finding_id
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT finding_id FROM findings WHERE finding_id LIKE ?",
            (f"{finding_id}%",),
        ).fetchone()
        if not row:
            rprint(f"[bold red]Finding '{finding_id}' not found.[/bold red]")
            raise typer.Exit(code=1)
        full_id = row["finding_id"]

    f = lc_mgr.get_finding(full_id)
    ev_list = ev_mgr.list_evidence(full_id)

    rprint(Panel(json.dumps(f.model_dump(), indent=2), title=f"Finding Details: {full_id}"))
    rprint(f"Evidence artifacts ({len(ev_list)}):")
    for ev in ev_list:
        rprint(f"  - [{ev['artifact_type']}] SHA-256: {ev['sha256_hash']} ({ev['file_path']})")


@app.command()
def triage(
    finding_id: str,
    reason: str = typer.Option(..., "--reason", help="Analyst triage reason"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Triages a candidate finding (Analyst action)."""
    if not yes:
        confirm = typer.confirm(f"Triage finding {finding_id} with reason: '{reason}'?")
        if not confirm:
            raise typer.Abort()

    db = Database()
    lc_mgr = LifecycleManager(db)
    with db.get_connection() as conn:
        row = conn.execute("SELECT finding_id FROM findings WHERE finding_id LIKE ?", (f"{finding_id}%",)).fetchone()
        if not row:
            rprint(f"[red]Finding not found[/red]")
            raise typer.Exit(1)
        full_id = row["finding_id"]

    try:
        updated = lc_mgr.transition(full_id, "TRIAGED", "analyst", "cli_analyst", reason)
        rprint(f"[bold green]✔ Finding {full_id[:8]} transitioned to TRIAGED.[/bold green]")
    except LifecycleViolation as e:
        rprint(f"[bold red]Transition failed:[/bold red] {e}")


@app.command()
def verify(
    finding_id: str,
    reason: str = typer.Option(..., "--reason", help="Analyst verification decision reason"),
    impact: str = typer.Option(..., "--impact", help="Documented security/business impact"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Verifies a triaged finding via the Evidence Gate (Analyst action)."""
    if not yes:
        confirm = typer.confirm(f"Promote finding {finding_id} to VERIFIED?")
        if not confirm:
            raise typer.Abort()

    db = Database()
    lc_mgr = LifecycleManager(db)
    with db.get_connection() as conn:
        row = conn.execute("SELECT finding_id FROM findings WHERE finding_id LIKE ?", (f"{finding_id}%",)).fetchone()
        if not row:
            rprint(f"[red]Finding not found[/red]")
            raise typer.Exit(1)
        full_id = row["finding_id"]

    try:
        updated = lc_mgr.transition(full_id, "VERIFIED", "analyst", "cli_analyst", reason, impact=impact)
        rprint(f"[bold green]✔ Evidence Gate PASSED. Finding {full_id[:8]} is now VERIFIED.[/bold green]")
    except LifecycleViolation as e:
        rprint(f"[bold red]Evidence gate rejected transition:[/bold red] {e}")


@app.command()
def reject(
    finding_id: str,
    reason: str = typer.Option(..., "--reason", help="Rejection rationale"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Rejects a candidate or triaged finding (Analyst action)."""
    if not yes:
        confirm = typer.confirm(f"Reject finding {finding_id}?")
        if not confirm:
            raise typer.Abort()

    db = Database()
    lc_mgr = LifecycleManager(db)
    with db.get_connection() as conn:
        row = conn.execute("SELECT finding_id FROM findings WHERE finding_id LIKE ?", (f"{finding_id}%",)).fetchone()
        if not row:
            rprint(f"[red]Finding not found[/red]")
            raise typer.Exit(1)
        full_id = row["finding_id"]

    try:
        updated = lc_mgr.transition(full_id, "REJECTED", "analyst", "cli_analyst", reason)
        rprint(f"[yellow]✔ Finding {full_id[:8]} marked REJECTED.[/yellow]")
    except LifecycleViolation as e:
        rprint(f"[bold red]Rejection failed:[/bold red] {e}")


@patch_app.command("propose")
def patch_propose(
    finding_id: str,
    diff_file: Path = typer.Option(..., "--diff-file", help="Path to unified diff file"),
):
    """Proposes a patch diff for an isolated branch."""
    if not diff_file.exists():
        rprint(f"[red]Diff file {diff_file} not found.[/red]")
        raise typer.Exit(1)

    diff_text = diff_file.read_text(encoding="utf-8")
    db = Database()
    with db.get_connection() as conn:
        row = conn.execute("SELECT finding_id FROM findings WHERE finding_id LIKE ?", (f"{finding_id}%",)).fetchone()
        if not row:
            rprint(f"[red]Finding not found[/red]")
            raise typer.Exit(1)
        full_id = row["finding_id"]

    pm = PatchManager(db=db)
    res = pm.propose_patch(full_id, diff_text, created_by="cli_analyst")
    rprint(f"[bold green]✔ Patch proposed: {res['patch_id']} for branch {res['branch_name']}[/bold green]")


@patch_app.command("apply")
def patch_apply(
    finding_id: str,
    patch_id: str,
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm patch application"),
):
    """Applies patch to isolated Git branch assess/<finding-id>."""
    if not yes:
        confirm = typer.confirm(f"Apply patch {patch_id} to isolated branch?")
        if not confirm:
            raise typer.Abort()

    db = Database()
    with db.get_connection() as conn:
        row = conn.execute("SELECT finding_id FROM findings WHERE finding_id LIKE ?", (f"{finding_id}%",)).fetchone()
        if not row:
            rprint(f"[red]Finding not found[/red]")
            raise typer.Exit(1)
        full_id = row["finding_id"]

    pm = PatchManager(db=db)
    try:
        res = pm.apply_patch(full_id, patch_id)
        rprint(f"[bold green]✔ Patch applied to branch {res['branch_name']}. Commit SHA: {res['patch_commit_sha']}[/bold green]")
    except Exception as e:
        rprint(f"[bold red]Patch application failed:[/bold red] {e}")


@app.command()
def retest(
    finding_id: str,
    recipe_id: str,
):
    """Replays exact recipe against patched target and establishes before/after proof."""
    db = Database()
    with db.get_connection() as conn:
        row = conn.execute("SELECT finding_id FROM findings WHERE finding_id LIKE ?", (f"{finding_id}%",)).fetchone()
        if not row:
            rprint(f"[red]Finding not found[/red]")
            raise typer.Exit(1)
        full_id = row["finding_id"]

    engine = RetestEngine(db=db)
    try:
        res = engine.retest_finding(full_id, recipe_id, analyst_id="cli_analyst")
        rprint(Panel(json.dumps(res, indent=2), title=f"Retest Result: {res['outcome']}"))
    except Exception as e:
        rprint(f"[bold red]Retest failed:[/bold red] {e}")


@report_app.command("export")
def report_export(
    format: str = typer.Option("json", "--format", help="Export format: 'json' or 'html'"),
    out: Optional[Path] = typer.Option(None, "--out", help="Output file destination"),
):
    """Exports assessment report in JSON or HTML format."""
    exporter = ReportExporter()
    default_out = Path("reports") / f"worldmonitor_security_report.{format}"
    destination = out or default_out

    if format.lower() == "html":
        exporter.export_html(destination)
        rprint(f"[bold green]✔ HTML report exported to: {destination}[/bold green]")
    else:
        exporter.export_json(destination)
        rprint(f"[bold green]✔ Canonical JSON report exported to: {destination}[/bold green]")


@intel_app.command("sync")
def intel_sync(
    force: bool = typer.Option(False, "--force", "-f", help="Force refresh from feeds, ignoring TTL"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Synchronizes threat intelligence feeds (CISA KEV, GHSA) into local SQLite FTS5 database."""
    if not yes:
        confirm = typer.confirm("Synchronize external threat feeds into local database?", default=True)
        if not confirm:
            raise typer.Abort()

    mgr = ThreatIntelManager()
    rprint("[cyan]Fetching threat intelligence feeds...[/cyan]")
    res = mgr.sync_all(force=force)
    rprint(Panel(json.dumps(res, indent=2), title="Threat Intel Sync Results"))


@intel_app.command("search")
def intel_search(
    query: str = typer.Argument(..., help="Search query or CVE identifier (e.g. 'CVE-2021-23337')"),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum results to return"),
):
    """Searches local threat intelligence index using SQLite FTS5."""
    mgr = ThreatIntelManager()
    results = mgr.search_advisories(query, limit=limit)
    if not results:
        rprint(f"[yellow]No threat advisories matching '{query}'[/yellow]")
        return

    table = Table(title=f"Threat Advisories matching '{query}' ({len(results)} found)")
    table.add_column("Advisory ID", style="cyan")
    table.add_column("Source", style="blue")
    table.add_column("CVE / GHSA", style="magenta")
    table.add_column("KEV Match", style="bold red")
    table.add_column("Title", style="white")

    for a in results:
        ref = a.get("cve_id") or a.get("ghsa_id") or "—"
        kev = "✔ YES" if a.get("kev_match") else "NO"
        table.add_row(
            a.get("advisory_id", ""),
            a.get("source", ""),
            ref,
            kev,
            (a.get("title") or "")[:60],
        )

    rprint(table)


@intel_app.command("status")
def intel_status():
    """Displays local threat intelligence feed freshness and sync status."""
    mgr = ThreatIntelManager()
    statuses = mgr.get_feed_statuses()
    if not statuses:
        rprint("[yellow]No feeds synchronized yet. Run 'wmsa intel sync'.[/yellow]")
        return

    table = Table(title="Threat Intelligence Feed Status")
    table.add_column("Feed Name", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Records", style="magenta")
    table.add_column("Last Synced (UTC)", style="white")
    table.add_column("Freshness", style="bold yellow")

    for s in statuses:
        freshness = "[bold red]STALE (>24h)[/bold red]" if s.get("is_stale") else "[green]FRESH[/green]"
        table.add_row(
            s.get("feed_name", ""),
            s.get("status", ""),
            str(s.get("record_count", 0)),
            s.get("last_sync_time", "Never"),
            freshness,
        )

    rprint(table)


@app.command()
def server(
    host: str = typer.Option("127.0.0.1", help="Host interface to bind dashboard API"),
    port: int = typer.Option(8000, help="Port to bind dashboard API"),
):
    """Launches local WMSA API server."""
    rprint(f"[bold green]Starting WMSA Local Assessment API on http://{host}:{port}...[/bold green]")
    uvicorn.run("wmsa.api:api_app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
