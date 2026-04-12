"""
IamWatching CLI
================
Entry point: `iamwatching audit`

Orchestrates the full scan pipeline:
  1. Scanner  -> pull IAM + compute metadata from AWS/Azure/GCP
  2. Verifier -> non-destructive credential handshake (WhoAmI calls)
  3. Importer -> load everything into Neo4j graph
  4. Matcher  -> run Cypher pattern detection
  5. Report   -> print findings to console / write JSON report
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from iamwatching.scanners import AWSScanner, AzureScanner, GCPScanner
from iamwatching.handshake import CredentialVerifier
from iamwatching.graph import GraphImporter
from iamwatching.patterns import PatternMatcher, Severity
from iamwatching.logging_module import configure_logging, get_logger, new_correlation_id

console = Console()
# Module-level logger (reconfigured after CLI args parsed)
log = get_logger("cli")

BANNER = r"""
[bold cyan]
 ___            __        __    _       _     _
|_ _|__ _ _ __ \ \      / /_ _| |_ ___| |__ (_)_ __   __ _
 | |/ _` | '_ \ \ \ /\ / / _` | __/ __| '_ \| | '_ \ / _` |
 | | (_| | | | | \ V  V / (_| | || (__| | | | | | | | (_| |
|___\__,_|_| |_|  \_/\_/ \__,_|\__\___|_| |_|_|_| |_|\__, |
                                                        |___/
[/bold cyan][dim]Multi-Cloud IAM Security Auditor — Aniza Corp[/dim]
"""

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


def setup_logging(verbose: bool, log_dir=None):
    level = "DEBUG" if verbose else "INFO"
    run_id = configure_logging(
        level=level,
        log_dir=__import__("pathlib").Path(log_dir) if log_dir else __import__("pathlib").Path.cwd() / "logs",
        json_file=True,
        audit_file=True,
        console_json=False,
    )
    return run_id


def get_neo4j_config():
    return {
        "uri": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        "username": os.environ.get("NEO4J_USERNAME", "neo4j"),
        "password": os.environ.get("NEO4J_PASSWORD", "iamwatching"),
        "database": os.environ.get("NEO4J_DATABASE", "neo4j"),
    }


@click.group()
@click.version_option(version="1.0.0", prog_name="iamwatching")
def cli():
    """IamWatching — Multi-Cloud IAM Security Auditor"""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# audit command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--aws/--no-aws", default=False, help="Scan AWS IAM")
@click.option("--azure/--no-azure", default=False, help="Scan Azure IAM")
@click.option("--gcp/--no-gcp", default=False, help="Scan GCP IAM")
@click.option("--aws-profile", default=None, envvar="AWS_PROFILE",
              help="AWS CLI profile name")
@click.option("--aws-regions", default="us-east-1",
              help="Comma-separated AWS regions to scan")
@click.option("--azure-subscription", default=None, envvar="AZURE_SUBSCRIPTION_ID",
              help="Azure subscription ID")
@click.option("--azure-tenant", default=None, envvar="AZURE_TENANT_ID",
              help="Azure tenant ID")
@click.option("--gcp-project", default=None, envvar="GCP_PROJECT_ID",
              help="GCP project ID")
@click.option("--gcp-locations", default="us-central1",
              help="Comma-separated GCP locations to scan")
@click.option("--verify/--no-verify", default=True,
              help="Run credential verification handshake")
@click.option("--import-graph/--no-import-graph", default=True,
              help="Import results into Neo4j")
@click.option("--detect/--no-detect", default=True,
              help="Run Cypher pattern detection")
@click.option("--severity", default=None,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
              help="Filter findings by minimum severity")
@click.option("--output", default=None, help="Write JSON report to file")
@click.option("--pdf", "pdf_report", default=None,
              help="Write a PDF report to file (e.g. --pdf report.pdf)")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.option("--log-dir", default=None, help="Directory for log files (default: ./logs)")
@click.option("--json-logs/--no-json-logs", default=False, help="Emit JSON logs to stderr")
@click.option("--list-checks", is_flag=True, default=False,
              help="List all available checks and exit (no scan performed)")
@click.option("--family", default=None, multiple=True,
              help="Filter checks by framework family (e.g. --family owasp --family cis). "
                   "Families: cis, owasp, nist, custom. Can be specified multiple times.")
def audit(
    aws, azure, gcp,
    aws_profile, aws_regions, azure_subscription, azure_tenant,
    gcp_project, gcp_locations,
    verify, import_graph, detect,
    severity, output, pdf_report, verbose, log_dir, json_logs,
    list_checks, family,
):
    """
    Run a full multi-cloud IAM security audit.

    \b
    Examples:
      iamwatching audit --aws --aws-regions us-east-1,eu-west-1
      iamwatching audit --gcp --gcp-project my-project-123
      iamwatching audit --aws --azure --gcp --output report.json
    """
    # ── --list-checks: show all checks and exit without scanning ─────────────
    if list_checks:
        from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
        registry = get_registry()
        registry.load()

        # Resolve --family aliases to framework names
        framework_filter = _resolve_family_filter(family) if family else None

        all_checks = registry.all_checks(enabled_only=False)
        if framework_filter:
            all_checks = [c for c in all_checks if
                          any(f.lower() in c.framework.lower() for f in framework_filter)]
        if severity:
            all_checks = [c for c in all_checks if str(c.severity) == severity]

        _print_checks_table(all_checks, framework_filter)
        return

    # If the user didn't specify any cloud, default to AWS (backward compatible)
    if not aws and not azure and not gcp:
        aws = True

    run_id = setup_logging(verbose, log_dir)
    global log
    log = get_logger("cli", correlation_id=run_id)

    # Suppress neo4j driver's GQL notification spam at the Python logging level.
    # This covers any notification path not already handled by consume() calls.
    import logging as _logging
    for _neo4j_logger in ("neo4j", "neo4j.notifications", "neo4j.io",
                           "neo4j.pool", "neo4j.work"):
        _logging.getLogger(_neo4j_logger).setLevel(_logging.CRITICAL)

    console.print(BANNER)
    asyncio.run(_run_audit(
        do_aws=aws, do_azure=azure, do_gcp=gcp,
        aws_profile=aws_profile,
        aws_regions=[r.strip() for r in aws_regions.split(",")],
        azure_subscription=azure_subscription,
        azure_tenant=azure_tenant,
        gcp_project=gcp_project,
        gcp_locations=[l.strip() for l in gcp_locations.split(",")],
        do_verify=verify,
        do_import=import_graph,
        do_detect=detect,
        severity_filter=severity,
        output_file=output,
        pdf_report_file=pdf_report,
        family_filter=_build_cloud_framework_filter(
            do_aws=aws,
            do_azure=azure,
            do_gcp=gcp,
            explicit_family=_resolve_family_filter(family) if family else None,
        ),
    ))


# Framework prefixes that are cloud-specific vs always applicable.
#
# IMPORTANT: NIST, OWASP, PCI, ISO checks all query AWSPrincipal/AWSResource
# nodes. They are NOT cloud-agnostic despite being "framework" checks.
# They must only run when AWS is being scanned, otherwise they return
# findings from stale AWS data left in the graph by a previous --aws run.
#
# CROSS-CLOUD and CUSTOM are the only truly cloud-agnostic frameworks.
# Their queries use generic Resource/Principal labels AND filter by
# updated_at >= scan_start so they only surface nodes from the current scan.
# AWS-specific frameworks — only run when --aws is active
_AWS_FRAMEWORK_PREFIXES   = ["CIS-AWS", "AWS-COMPUTE", "AWS-DATA"]
_AZURE_FRAMEWORK_PREFIXES = ["AZURE"]
_GCP_FRAMEWORK_PREFIXES   = ["GCP"]
# These compliance frameworks run on EVERY cloud scan.
# Their Cypher queries use generic Principal/Resource labels (not AWSPrincipal)
# so they surface findings from whichever cloud was just scanned.
# scan_start_ms scoping ensures only current-scan nodes appear.
_ALWAYS_RUN_PREFIXES      = ["CROSS-CLOUD", "CUSTOM", "NIST", "OWASP", "PCI", "ISO"]


def _resolve_family_filter(family_args: tuple) -> list[str]:
    """
    Map short family aliases to framework name substrings.
    e.g. "owasp" -> "OWASP", "cis" -> "CIS", "nist" -> "NIST", "custom" -> "CUSTOM"
    """
    aliases = {
        "owasp":   "OWASP",
        "cis":     "CIS",
        "nist":    "NIST",
        "custom":  "CUSTOM",
        "mitre":   "MITRE",
        "aws":     "AWS",
        "azure":   "AZURE",
        "gcp":     "GCP",
    }
    resolved = []
    for f in family_args:
        resolved.append(aliases.get(f.lower(), f.upper()))
    return resolved


def _build_cloud_framework_filter(
    do_aws: bool,
    do_azure: bool,
    do_gcp: bool,
    explicit_family: list | None,
) -> list[str] | None:
    """
    Build a framework filter from active cloud flags so that:
      --azure  → only Azure + always-run frameworks (not CIS-AWS, not AWS-*)
      --gcp    → only GCP + always-run frameworks
      --aws    → only AWS + always-run frameworks
      --aws --azure → AWS + Azure + always-run
      (no flag) → all frameworks (None = no filter)

    If the user also passed --family flags, those take priority and we return
    them as-is (they've already been explicit about what they want).
    """
    if explicit_family:
        # User specified exact families — respect that, don't auto-filter
        return explicit_family

    # Build from cloud flags
    selected: list[str] = list(_ALWAYS_RUN_PREFIXES)   # always include
    if do_aws:
        selected.extend(_AWS_FRAMEWORK_PREFIXES)
    if do_azure:
        selected.extend(_AZURE_FRAMEWORK_PREFIXES)
    if do_gcp:
        selected.extend(_GCP_FRAMEWORK_PREFIXES)

    # If all three are on, no point filtering — return None (run everything)
    if do_aws and do_azure and do_gcp:
        return None

    return selected


def _print_checks_table(checks: list, family_filter=None) -> None:
    """Print a formatted table of checks to the console."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
    registry = get_registry()
    registry.load()
    summary = registry.summary()

    title_parts = ["[bold]IamWatching — Available Security Checks[/bold]"]
    if family_filter:
        title_parts.append(f"  [dim](filtered by family: {', '.join(family_filter)})[/dim]")
    console.print("\n" + "".join(title_parts))
    console.print(f"[dim]Checks directory: {summary['checks_dir']}[/dim]\n")

    # Group by framework
    by_framework: dict = {}
    for c in checks:
        by_framework.setdefault(c.framework, []).append(c)

    for framework, fw_checks in sorted(by_framework.items()):
        console.print(f"[bold cyan]{framework}[/bold cyan]  ({len(fw_checks)} checks)")
        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("ID",           style="dim",        width=18)
        table.add_column("Severity",     width=10)
        table.add_column("Title",        width=52)
        table.add_column("Enabled",      width=7,  justify="center")

        for c in sorted(fw_checks, key=lambda x: (
            ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(c.severity.value), x.id
        )):
            sev_style = SEVERITY_COLORS.get(c.severity.value, "white")
            table.add_row(
                c.id,
                Text(c.severity.value, style=sev_style),
                c.title,
                "[green]✓[/green]" if c.enabled else "[red]✗[/red]",
            )
        console.print(table)

    total_enabled  = sum(1 for c in checks if c.enabled)
    total_disabled = len(checks) - total_enabled
    console.print(f"[dim]Total: {len(checks)} checks  "
                  f"({total_enabled} enabled, {total_disabled} disabled)[/dim]")
    console.print()
    console.print("[bold]Usage examples:[/bold]")
    console.print("  [cyan]iamwatching audit --aws --list-checks[/cyan]               "
                  "List all checks")
    console.print("  [cyan]iamwatching audit --aws --list-checks --family owasp[/cyan] "
                  "List OWASP checks only")
    console.print("  [cyan]iamwatching audit --aws --list-checks --family cis --family nist[/cyan]")
    console.print("  [cyan]iamwatching checks add --id CUSTOM-001 --title '...' --cypher '...'[/cyan]")
    console.print("  [cyan]iamwatching checks show CIS-AWS-1.4[/cyan]")
    console.print("  [cyan]iamwatching checks disable CIS-AWS-1.17[/cyan]")
    console.print()


async def _run_audit(
    do_aws, do_azure, do_gcp,
    aws_profile, aws_regions,
    azure_subscription, azure_tenant,
    gcp_project, gcp_locations,
    do_verify, do_import, do_detect,
    severity_filter, output_file,
    pdf_report_file=None,
    family_filter=None,
):
    report = {
        "scan_results": {},
        "verification_results": [],
        "graph_stats": {},
        "findings": [],
    }

    aws_result = azure_result = gcp_result = None
    all_creds = []

    # ── Show clearly which clouds are being scanned ───────────────────────
    active = []
    if do_aws:   active.append("[bold cyan]AWS[/bold cyan]")
    if do_azure: active.append("[bold blue]Azure[/bold blue]")
    if do_gcp:   active.append("[bold green]GCP[/bold green]")
    console.print(
        Panel(
            f"Scanning: {' + '.join(active) or '[red]none[/red]'}\n"
            f"[dim]To scan a specific cloud: iamwatching audit --aws | --azure | --gcp[/dim]",
            title="[bold]IamWatching v2.0.0 — Cloud Scope[/bold]",
            border_style="cyan",
        )
    )

    # Record scan start time (milliseconds, same epoch as Neo4j timestamp())
    # This is passed to the graph importer and pattern matcher so every node
    # written in this scan gets a scan_start_ms property, and pattern detection
    # only surfaces nodes updated >= this timestamp.
    import time as _time
    scan_start_ms = int(_time.time() * 1000)
    report["scan_start_ms"] = scan_start_ms

    # ── Preflight checks ───────────────────────────────────────────────────
    _preflight_ok = True

    if do_aws:
        try:
            import aioboto3  # noqa: F401
        except ImportError:
            console.print(Panel(
                "[bold red]AWS SDK not installed.[/bold red]\n\n"
                "Fix: [cyan]pip install 'iamwatching[dev]'[/cyan]\n"
                "  or: [cyan]pip install aioboto3 aiobotocore botocore[/cyan]",
                title="Missing Dependency", border_style="red",
            ))
            _preflight_ok = False

    if do_azure:
        try:
            import azure.identity  # noqa: F401
        except ImportError:
            console.print(Panel(
                "[bold red]Azure SDK not installed.[/bold red]\n\n"
                "Fix: [cyan]pip install 'iamwatching[dev]'[/cyan]\n"
                "  or: [cyan]pip install azure-identity azure-mgmt-authorization azure-mgmt-resource[/cyan]",
                title="Missing Dependency", border_style="red",
            ))
            _preflight_ok = False

    if do_gcp:
        try:
            import google.auth  # noqa: F401
        except ImportError:
            console.print(Panel(
                "[bold red]GCP SDK not installed.[/bold red]\n\n"
                "Fix: [cyan]pip install 'iamwatching[dev]'[/cyan]\n"
                "  or: [cyan]pip install google-auth google-cloud-functions google-api-python-client[/cyan]",
                title="Missing Dependency", border_style="red",
            ))
            _preflight_ok = False

    if do_import or do_detect:
        import socket as _socket
        neo4j_cfg = get_neo4j_config()
        _neo4j_host = neo4j_cfg["uri"].replace("bolt://", "").replace("neo4j://", "").split(":")[0]
        _neo4j_port = 7687
        try:
            _s = _socket.create_connection((_neo4j_host, _neo4j_port), timeout=3)
            _s.close()
        except (OSError, ConnectionRefusedError):
            console.print(Panel(
                f"[bold red]Neo4j is not reachable at {neo4j_cfg['uri']}[/bold red]\n\n"
                "Start Neo4j first:\n"
                "  [cyan]./start.sh[/cyan]\n"
                "  or: [cyan]docker compose -f docker/docker-compose.yml up -d neo4j[/cyan]\n\n"
                "Then re-run the audit. Or skip graph steps:\n"
                "  [cyan]iamwatching audit --aws --no-import-graph --no-detect[/cyan]",
                title="Neo4j Not Running", border_style="red",
            ))
            if do_import:
                do_import = False
            if do_detect:
                do_detect = False

    if not _preflight_ok:
        console.print("[red]Fix the missing dependencies above and re-run.[/red]")
        return

    # ── Phase 1: Scan ──────────────────────────────────────────────────────
    with console.status("[bold green]Phase 1: Scanning IAM data...[/bold green]"):
        if do_aws:
            try:
                scanner = AWSScanner(profile=aws_profile, regions=aws_regions)
                aws_result = await scanner.scan()
                report["scan_results"]["aws"] = {
                    "account_id": aws_result.account_id,
                    "principals": len(aws_result.principals),
                    "resources": len(aws_result.resources),
                    "discovered_credentials": len(aws_result.discovered_credentials),
                }
                all_creds.extend(aws_result.discovered_credentials)
                _print_scan_summary("AWS", aws_result.account_id,
                                    len(aws_result.principals), len(aws_result.resources),
                                    len(aws_result.discovered_credentials))
            except Exception as e:
                console.print(f"[red]AWS scan failed: {e}[/red]")

        if do_azure:
            if not azure_subscription or not azure_tenant:
                console.print("[yellow]Azure scan skipped: --azure-subscription and --azure-tenant required[/yellow]")
            else:
                try:
                    scanner = AzureScanner(azure_subscription, azure_tenant)
                    azure_result = await scanner.scan()
                    report["scan_results"]["azure"] = {
                        "subscription_id": azure_result.subscription_id,
                        "principals": len(azure_result.principals),
                        "resources": len(azure_result.resources),
                        "discovered_credentials": len(azure_result.discovered_credentials),
                    }
                    all_creds.extend(azure_result.discovered_credentials)
                    _print_scan_summary("Azure", azure_result.subscription_id,
                                        len(azure_result.principals), len(azure_result.resources),
                                        len(azure_result.discovered_credentials))
                except Exception as e:
                    console.print(f"[red]Azure scan failed: {e}[/red]")

        if do_gcp:
            if not gcp_project:
                console.print("[yellow]GCP scan skipped: --gcp-project required[/yellow]")
            else:
                try:
                    scanner = GCPScanner(gcp_project, gcp_locations)
                    gcp_result = await scanner.scan()
                    report["scan_results"]["gcp"] = {
                        "project_id": gcp_result.project_id,
                        "principals": len(gcp_result.principals),
                        "resources": len(gcp_result.resources),
                        "discovered_credentials": len(gcp_result.discovered_credentials),
                    }
                    all_creds.extend(gcp_result.discovered_credentials)
                    _print_scan_summary("GCP", gcp_result.project_id,
                                        len(gcp_result.principals), len(gcp_result.resources),
                                        len(gcp_result.discovered_credentials))
                except Exception as e:
                    console.print(f"[red]GCP scan failed: {e}[/red]")

    # ── Phase 2: Verify Credentials ───────────────────────────────────────
    verification_results = []
    if do_verify and all_creds:
        with console.status(f"[bold green]Phase 2: Verifying {len(all_creds)} discovered credentials...[/bold green]"):
            verifier = CredentialVerifier(concurrency=5)
            verification_results = await verifier.verify_all(all_creds)
            verified = [v for v in verification_results if v.verified_link]
            console.print(
                Panel(
                    f"[bold]Credential Verification:[/bold]\n"
                    f"  Tested:   {len(verification_results)}\n"
                    f"  [red bold]LIVE:     {len(verified)}[/red bold]\n"
                    f"  Invalid:  {sum(1 for v in verification_results if str(v.status) == 'INVALID')}",
                    title="Phase 2: Handshake",
                    border_style="yellow",
                )
            )
            report["verification_results"] = [
                {
                    "source_cloud": v.credential_source_cloud,
                    "source_resource": v.credential_source_resource,
                    "cred_type": v.credential_type,
                    "target_cloud": v.target_cloud,
                    "status": str(v.status),
                    "identity": v.identity,
                    "account": v.account,
                    "verified": v.verified_link,
                }
                for v in verification_results
            ]

    # ── Phase 3: Graph Import ─────────────────────────────────────────────
    if do_import:
        neo4j_cfg = get_neo4j_config()
        with console.status("[bold green]Phase 3: Importing into Neo4j graph...[/bold green]"):
            try:
                importer = GraphImporter(**neo4j_cfg, scan_start_ms=scan_start_ms)
                await importer.connect()
                stats = await importer.import_all(
                    aws_result=aws_result,
                    azure_result=azure_result,
                    gcp_result=gcp_result,
                    verification_results=verification_results,
                )
                await importer.close()
                report["graph_stats"] = stats
                console.print(
                    Panel(
                        _format_graph_stats(stats),
                        title="Phase 3: Neo4j Graph",
                        border_style="blue",
                    )
                )
            except Exception as e:
                err_str = str(e)
                if "7687" in err_str or "Connect" in err_str or "refused" in err_str.lower():
                    console.print("[red]Neo4j not reachable. Start it with: ./start.sh[/red]")
                else:
                    console.print(f"[red]Graph import failed: {err_str[:120]}[/red]")

    # ── Phase 4: Pattern Detection ────────────────────────────────────────
    if do_detect:
        neo4j_cfg = get_neo4j_config()
        with console.status("[bold green]Phase 4: Running pattern detection...[/bold green]"):
            try:
                matcher = PatternMatcher(**neo4j_cfg)
                await matcher.connect()
                sev_enum = Severity(severity_filter) if severity_filter else None
                # active_clouds passed explicitly — never derived from framework names
                # so NIST/OWASP/PCI/ISO in the always-run list don't incorrectly
                # activate AWS hardcoded rules during Azure or GCP scans.
                _clouds: set[str] = set()
                if do_aws:   _clouds.add("aws")
                if do_azure: _clouds.add("azure")
                if do_gcp:   _clouds.add("gcp")
                if not _clouds: _clouds = {"aws"}  # fallback matches audit default

                findings = await matcher.run_all(
                    severity_filter=sev_enum,
                    frameworks=family_filter,
                    scan_start_ms=scan_start_ms,
                    active_clouds=_clouds,
                )
                await matcher.close()
                report["findings"] = [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": str(f.severity),
                        "description": f.description,
                        "affected_count": len(f.affected_nodes),
                        "recommendation": f.recommendation,
                        "mitre_attack": f.mitre_attack,
                        "records": f.raw_records[:50],   # up to 50 affected resources in PDF
                    }
                    for f in findings
                ]
                _print_findings(findings)
            except Exception as e:
                err_str = str(e)
                if "7687" in err_str or "Connect" in err_str or "refused" in err_str.lower():
                    console.print("[red]Neo4j not reachable. Start it with: ./start.sh[/red]")
                else:
                    console.print(f"[red]Pattern detection failed: {err_str[:120]}[/red]")

    # ── Output ────────────────────────────────────────────────────────────
    if output_file:
        Path(output_file).write_text(json.dumps(report, indent=2, default=str))
        console.print(f"\n[green]JSON report written to {output_file}[/green]")

    if pdf_report_file:
        try:
            from iamwatching.report.pdf_report import generate_pdf_report  # noqa: PLC0415
            with console.status("[bold green]Generating PDF report...[/bold green]"):
                pdf_path = generate_pdf_report(report, pdf_report_file)
            console.print(f"\n[green]PDF report written to {pdf_path}[/green]")
        except ImportError:
            console.print("[red]PDF generation requires reportlab: pip install reportlab[/red]")
        except Exception as _pdf_err:
            console.print(f"[red]PDF generation failed: {_pdf_err}[/red]")

    _print_summary(report)


def _print_scan_summary(cloud, account, principals, resources, creds):
    console.print(
        Panel(
            f"Account/Project: [bold]{account}[/bold]\n"
            f"Principals:      {principals}\n"
            f"Resources:       {resources}\n"
            f"[yellow]Potential Creds: {creds}[/yellow]",
            title=f"[cyan]{cloud} Scan[/cyan]",
            border_style="cyan",
        )
    )


def _format_graph_stats(stats):
    lines = []
    for cloud, s in stats.items():
        lines.append(f"[bold]{cloud.upper()}[/bold]")
        for k, v in s.items():
            lines.append(f"  {k}: {v}")
    return "\n".join(lines) if lines else "No stats"


def _print_findings(findings):
    # Separate evaluated findings from checks that could not be evaluated
    evaluated     = [f for f in findings if not getattr(f, "not_evaluated", False)]
    not_evaluated = [f for f in findings if getattr(f, "not_evaluated", False)]

    if not evaluated and not not_evaluated:
        console.print("[green]No findings matched. Graph may be empty or environment is clean.[/green]")
        return

    if evaluated:
        table = Table(
            title="Security Findings",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("ID",       style="dim",   width=18)
        table.add_column("Severity",                width=10)
        table.add_column("Title",                   width=50)
        table.add_column("Affected", justify="right", width=8)
        table.add_column("MITRE",                   width=24)

        for f in evaluated:
            sev_val   = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_style = SEVERITY_COLORS.get(sev_val, "white")
            table.add_row(
                f.rule_id,
                Text(sev_val, style=sev_style),
                f.title,
                str(len(f.affected_nodes)),
                "\n".join(f.mitre_attack[:2]),
            )
        console.print(table)

        # Detailed output for CRITICAL findings
        for f in evaluated:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_val == "CRITICAL":
                console.print(
                    Panel(
                        f"[bold red]{f.title}[/bold red]\n\n"
                        f"{f.description}\n\n"
                        f"[bold yellow]Recommendation:[/bold yellow]\n{f.recommendation}\n\n"
                        f"[bold]MITRE ATT&CK:[/bold] {', '.join(f.mitre_attack)}\n\n"
                        f"[bold]Sample affected (first 3):[/bold]\n"
                        + json.dumps(f.raw_records[:3], indent=2, default=str),
                        title=f"[red]CRITICAL: {f.rule_id}[/red]",
                        border_style="red",
                    )
                )

    if not_evaluated:
        ne_table = Table(
            title="[yellow]Checks Not Yet Evaluated — Requires Additional Graph Data[/yellow]",
            box=box.SIMPLE,
            show_lines=False,
        )
        ne_table.add_column("ID",      style="dim",    width=20)
        ne_table.add_column("Severity",                width=10)
        ne_table.add_column("Check Title",             width=46)
        ne_table.add_column("Reason Not Evaluated",    width=38)

        for f in not_evaluated:
            sev_val   = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_style = SEVERITY_COLORS.get(sev_val, "white")
            reason    = getattr(f, "not_evaluated_reason", "Missing graph data")
            # Truncate long reasons for table display
            short_reason = reason[:80] + "..." if len(reason) > 80 else reason
            ne_table.add_row(
                f.rule_id,
                Text(sev_val, style=sev_style),
                f.title,
                f"[dim]{short_reason}[/dim]",
            )
        console.print(ne_table)
        console.print(
            "[dim]These checks require relationships (e.g. resource policies, "
            "cross-account trusts) that are not yet in the graph.\n"
            "They were NOT skipped — they ran and returned no data because the "
            "required graph edges do not exist yet.\n"
            "To populate them: ensure S3/Lambda resource policies exist and "
            "re-run with --import-graph, or run a cross-cloud scan.[/dim]\n"
        )


def _print_summary(report):
    finding_counts = {}
    for f in report.get("findings", []):
        sev = f["severity"]
        finding_counts[sev] = finding_counts.get(sev, 0) + 1

    verified_creds = sum(1 for v in report.get("verification_results", []) if v.get("verified"))

    lines = [
        f"[bold]Clouds scanned:[/bold] {', '.join(report['scan_results'].keys()) or 'none'}",
        f"[bold red]Verified cross-cloud credentials:[/bold red] {verified_creds}",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = finding_counts.get(sev, 0)
        color = SEVERITY_COLORS.get(sev, "white")
        if count:
            lines.append(f"[{color}]{sev}: {count}[/{color}]")

    console.print(Panel("\n".join(lines), title="[bold]Audit Complete[/bold]", border_style="green"))


# ─────────────────────────────────────────────────────────────────────────────
# graph command: run custom Cypher
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("cypher")
@click.option("--title", default="Custom Query", help="Label for the query")
def query(cypher, title):
    """Run a custom Cypher query against the IAM graph."""
    async def _run():
        neo4j_cfg = get_neo4j_config()
        matcher = PatternMatcher(**neo4j_cfg)
        await matcher.connect()
        finding = await matcher.run_custom(cypher, title)
        await matcher.close()
        console.print_json(json.dumps(finding.raw_records, default=str))
    asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# detect command: run only pattern matching
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--severity", default=None,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
@click.option("--output", default=None)
def detect(severity, output):
    """Run pattern detection against an existing Neo4j graph (no scanning)."""
    async def _run():
        neo4j_cfg = get_neo4j_config()
        matcher = PatternMatcher(**neo4j_cfg)
        await matcher.connect()
        sev_enum = Severity(severity) if severity else None
        findings = await matcher.run_all(severity_filter=sev_enum)
        await matcher.close()
        _print_findings(findings)
        if output:
            data = [
                {"rule_id": f.rule_id, "title": f.title, "severity": str(f.severity),
                 "affected": f.raw_records}
                for f in findings
            ]
            Path(output).write_text(json.dumps(data, indent=2, default=str))
            console.print(f"[green]Report written to {output}[/green]")
    asyncio.run(_run())



# ─────────────────────────────────────────────────────────────────────────────
# checks command group — manage detection checks
# ─────────────────────────────────────────────────────────────────────────────

@cli.group()
def checks():
    """Manage detection checks (list, add, enable, disable, reload)."""
    pass


@checks.command("list")
@click.option("--framework", default=None, help="Filter by framework (CIS-AWS-3.0, OWASP-CLOUD-NATIVE-2024, NIST-CSF-2.0, CUSTOM)")
@click.option("--severity", default=None,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
@click.option("--all", "show_all", is_flag=True, help="Include disabled checks")
def checks_list(framework, severity, show_all):
    """List all available detection checks."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
    registry = get_registry()
    registry.load()

    all_checks = registry.all_checks(enabled_only=not show_all)
    if framework:
        all_checks = [c for c in all_checks if c.framework == framework]
    if severity:
        all_checks = [c for c in all_checks if str(c.severity) == severity]

    summary = registry.summary()
    console.print(f"\n[bold]IamWatching Check Library[/bold]  ({summary['total']} enabled checks)\n")

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("ID", style="dim", width=18)
    table.add_column("Framework", width=22)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=50)
    table.add_column("On", width=4)

    for c in all_checks:
        sev_style = SEVERITY_COLORS.get(str(c.severity), "white")
        table.add_row(
            c.id,
            c.framework,
            Text(str(c.severity), style=sev_style),
            c.title,
            "✓" if c.enabled else "✗",
        )
    console.print(table)

    console.print(f"\n[bold]Frameworks:[/bold]")
    for fw, cnt in summary["by_framework"].items():
        console.print(f"  {fw}: {cnt} checks")
    console.print(f"\n[dim]Checks directory: {summary['checks_dir']}[/dim]\n")


@checks.command("show")
@click.argument("check_id")
def checks_show(check_id):
    """Show full details of a specific check."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
    registry = get_registry()
    registry.load()
    c = registry.get(check_id)
    if not c:
        console.print(f"[red]Check not found: {check_id}[/red]")
        return
    sev_style = SEVERITY_COLORS.get(str(c.severity), "white")
    console.print(Panel(
        f"[bold]{c.title}[/bold]\n\n"
        f"[bold]Framework:[/bold] {c.framework}\n"
        f"[bold]Severity:[/bold]  [{sev_style}]{c.severity}[/{sev_style}]\n"
        f"[bold]Enabled:[/bold]   {'Yes' if c.enabled else 'No'}\n\n"
        f"[bold]Description:[/bold]\n{c.description}\n\n"
        f"[bold]Cypher Query:[/bold]\n[dim]{c.cypher}[/dim]\n\n"
        f"[bold]Recommendation:[/bold]\n{c.recommendation}\n\n"
        f"[bold]MITRE ATT&CK:[/bold] {', '.join(c.mitre) or 'N/A'}\n"
        f"[bold]References:[/bold]\n" + "\n".join(f"  {r}" for r in c.references),
        title=f"[bold]{c.id}[/bold]",
        border_style=sev_style,
    ))


@checks.command("disable")
@click.argument("check_id")
def checks_disable(check_id):
    """Disable a check by ID (skipped during detection runs)."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
    registry = get_registry()
    registry.load()
    if registry.disable(check_id):
        console.print(f"[yellow]Disabled: {check_id}[/yellow]")
    else:
        console.print(f"[red]Check not found: {check_id}[/red]")


@checks.command("enable")
@click.argument("check_id")
def checks_enable(check_id):
    """Re-enable a previously disabled check."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
    registry = get_registry()
    registry.load()
    if registry.enable(check_id):
        console.print(f"[green]Enabled: {check_id}[/green]")
    else:
        console.print(f"[red]Check not found: {check_id}[/red]")


@checks.command("reload")
def checks_reload():
    """Reload all check YAML files from disk (picks up new custom checks)."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
    registry = get_registry()
    n = registry.load(force=True)
    console.print(f"[green]Reloaded {n} checks.[/green]")
    summary = registry.summary()
    for fw, cnt in summary["by_framework"].items():
        console.print(f"  {fw}: {cnt}")


@checks.command("add")
@click.option("--id", "check_id", required=True, help="Unique check ID (e.g. CUSTOM-003)")
@click.option("--title", required=True, help="Short descriptive title")
@click.option("--severity", default="MEDIUM",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
@click.option("--cypher", required=True, help="Neo4j Cypher query that returns affected resources")
@click.option("--description", default="", help="What this check detects")
@click.option("--recommendation", default="", help="How to fix findings")
@click.option("--framework", default="CUSTOM", help="Framework name (default: CUSTOM)")
@click.option("--mitre", default="", help="Comma-separated MITRE ATT&CK technique IDs")
@click.option("--reference", default="", multiple=True, help="Reference URL (repeatable)")
def checks_add(check_id, title, severity, cypher, description, recommendation, framework, mitre, reference):
    """
    Write a new custom check and save it to checks/custom/.

    \b
    Example:
      iamwatching checks add \\
        --id CUSTOM-010 \\
        --title "Roles without description" \\
        --severity LOW \\
        --cypher "MATCH (p:Principal {principal_type:\'Role\'}) WHERE p.scan_start_ms >= $scan_start AND NOT p.metadata CONTAINS \'description\' RETURN labels(p) AS cloud, p.name AS name" \\
        --recommendation "Add descriptions to all roles for auditability"
    """
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415

    registry = get_registry()
    registry.load()

    mitre_list = [m.strip() for m in mitre.split(",") if m.strip()] if mitre else []
    check_def = {
        "id": check_id,
        "title": title,
        "severity": severity,
        "description": description,
        "cypher": cypher,
        "recommendation": recommendation,
        "framework": framework,
        "mitre": mitre_list,
        "references": list(reference),
    }
    check = registry.add_custom(check_def, persist=True)
    console.print(Panel(
        f"[green]Check {check.id} saved[/green]\n\n"
        f"Title:     {check.title}\n"
        f"Severity:  {check.severity.value if hasattr(check.severity,'value') else check.severity}\n"
        f"Framework: {check.framework}\n"
        f"File:      checks/custom/{check_id.lower().replace('-','_')}.yaml\n\n"
        "[dim]Run: iamwatching checks reload  to pick it up immediately.[/dim]",
        title="[bold green]Custom Check Created[/bold green]",
        border_style="green",
    ))


@checks.command("edit")
@click.argument("check_id")
@click.option("--title", default=None, help="New title")
@click.option("--severity", default=None,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
@click.option("--cypher", default=None, help="New Cypher query")
@click.option("--description", default=None, help="New description")
@click.option("--recommendation", default=None, help="New recommendation")
def checks_edit(check_id, title, severity, cypher, description, recommendation):
    """Edit a custom check. Built-in checks cannot be edited (use disable instead)."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415

    registry = get_registry()
    registry.load()
    check = registry.get(check_id)
    if not check:
        console.print(f"[red]Check {check_id} not found.[/red]")
        return
    if "custom" not in check.source_file and check.source_file != "runtime":
        console.print(
            Panel(
                f"[yellow]{check_id} is a built-in check and cannot be edited.[/yellow]\n\n"
                "To customise a built-in check:\n"
                "  1. Export it:  [cyan]iamwatching checks export --id {check_id} --output my_check.yaml[/cyan]\n"
                "  2. Edit the YAML file\n"
                "  3. Import it:  [cyan]iamwatching checks import my_check.yaml[/cyan]\n"
                "     (custom version overrides the built-in with the same ID)",
                title="Built-in Check",
                border_style="yellow",
            )
        )
        return

    if title:         check.title = title
    if severity:      check.severity = check.severity.__class__(severity)
    if cypher:        check.cypher = cypher
    if description:   check.description = description
    if recommendation: check.recommendation = recommendation

    # Re-save to disk
    import yaml as _yaml  # noqa: PLC0415
    from pathlib import Path as _Path  # noqa: PLC0415
    src = _Path(check.source_file)
    if src.exists():
        data = _yaml.safe_load(src.read_text())
        for i, c in enumerate(data.get("checks", [])):
            if c["id"] == check_id:
                data["checks"][i] = check.to_dict()
                break
        src.write_text(_yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False))
        console.print(f"[green]Check {check_id} updated in {src}[/green]")
    else:
        console.print(f"[yellow]Check updated in memory only (source file not found: {check.source_file})[/yellow]")


@checks.command("delete")
@click.argument("check_id")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
def checks_delete(check_id, yes):
    """Permanently delete a custom check. Built-in checks cannot be deleted."""
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415

    registry = get_registry()
    registry.load()
    check = registry.get(check_id)
    if not check:
        console.print(f"[red]Check {check_id} not found.[/red]")
        return
    if not yes:
        click.confirm(f"Permanently delete {check_id} ({check.title})?", abort=True)
    try:
        registry.delete_custom(check_id)
        console.print(f"[green]Deleted: {check_id}[/green]")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        console.print("[dim]Tip: to suppress a built-in check, use: iamwatching checks disable {check_id}[/dim]")


@checks.command("export")
@click.option("--output", "-o", required=True, help="Output file path (.yaml or .json)")
@click.option("--framework", default=None, help="Filter by framework (e.g. NIST, CIS, CUSTOM)")
@click.option("--custom-only", is_flag=True, help="Export only custom checks")
@click.option("--enabled-only", is_flag=True, help="Export only enabled checks")
@click.option("--id", "check_id", default=None, help="Export a single check by ID")
def checks_export(output, framework, custom_only, enabled_only, check_id):
    """
    Export checks to a YAML or JSON file.

    \b
    Examples:
      iamwatching checks export --output all_checks.yaml
      iamwatching checks export --output custom.yaml --custom-only
      iamwatching checks export --output nist.json --framework NIST
      iamwatching checks export --output single.yaml --id CIS-AWS-1.4
    """
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
    from pathlib import Path as _Path  # noqa: PLC0415

    registry = get_registry()
    registry.load()

    # Single-check export
    if check_id:
        check = registry.get(check_id)
        if not check:
            console.print(f"[red]Check {check_id} not found.[/red]")
            return
        registry._checks = {check_id: check}

    out = _Path(output)
    try:
        if out.suffix.lower() == ".json":
            n = registry.export_json(out, framework=framework,
                                     custom_only=custom_only, enabled_only=enabled_only)
        else:
            n = registry.export_yaml(out, framework=framework,
                                     custom_only=custom_only, enabled_only=enabled_only)
        console.print(f"[green]Exported {n} check(s) to {out}[/green]")
    except Exception as e:
        console.print(f"[red]Export failed: {e}[/red]")


@checks.command("import")
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--target", default="custom",
              type=click.Choice(["custom", "builtin"]),
              help="Where to save imported checks (default: custom)")
@click.option("--overwrite", is_flag=True, help="Overwrite existing checks with the same ID")
def checks_import(input_file, target, overwrite):
    """
    Import checks from a YAML or JSON file.

    Accepts any file exported by 'iamwatching checks export', or any YAML
    file following the standard check format (framework + checks list).

    \b
    Examples:
      iamwatching checks import my_checks.yaml
      iamwatching checks import team_checks.json --target custom
      iamwatching checks import updated_cis.yaml --target builtin --overwrite
    """
    from iamwatching.patterns.registry import get_registry  # noqa: PLC0415

    registry = get_registry()
    registry.load()
    try:
        n, skipped = registry.import_file(input_file, target=target, overwrite=overwrite)
        msg = f"[green]Imported {n} check(s) into checks/{target}/[/green]"
        if skipped:
            msg += f"\n[yellow]Skipped {len(skipped)} existing check(s): {', '.join(skipped[:5])}{'...' if len(skipped) > 5 else ''}[/yellow]"
            msg += "\n[dim]Use --overwrite to replace existing checks.[/dim]"
        console.print(Panel(msg, title="Import Complete", border_style="green"))
        console.print("[dim]Run: iamwatching checks reload[/dim]")
    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")


@checks.command("write")
@click.option("--id",             "check_id",      prompt="Check ID (e.g. CUSTOM-001)", help="Unique check identifier")
@click.option("--title",                           prompt="Title (plain English)",       help="Short check title")
@click.option("--severity",                        prompt="Severity",
              type=click.Choice(["CRITICAL","HIGH","MEDIUM","LOW","INFO"]),              help="Severity level")
@click.option("--framework",  default="CUSTOM",   prompt="Framework name",              help="Framework name (default: CUSTOM)")
@click.option("--description", default="",        prompt="Description (Enter to skip)", help="What this check looks for")
@click.option("--recommendation", default="",     prompt="Recommendation (Enter to skip)", help="How to fix findings")
@click.option("--cypher",                          prompt="Cypher query",                help="Neo4j Cypher query")
@click.option("--output", "-o", default=None,                                           help="Write to specific file instead of checks/custom/")
def checks_write(check_id, title, severity, framework, description, recommendation, cypher, output):
    """
    Interactively write a new custom check and save it.

    Prompts for all required fields and saves to checks/custom/ as YAML.
    The check is immediately available after: iamwatching checks reload

    \b
    Examples:
      iamwatching checks write
      iamwatching checks write --id CUSTOM-010 --title "All roles must have description" --severity LOW --cypher "MATCH (r:Principal {principal_type:\'Role\'}) WHERE r.name IS NOT NULL RETURN r.arn AS principal_id, r.name AS name"
      iamwatching checks write --output my_checks.yaml

    \b
    Cypher tips:
      Always include: WHERE p.scan_start_ms >= $scan_start  (scopes to current scan)
      Return columns: principal_id, resource_id, name, region, issue
    """
    import yaml as _yaml  # noqa: PLC0415
    from pathlib import Path as _Path  # noqa: PLC0415
    from iamwatching.patterns.registry import get_registry, _find_checks_dir  # noqa: PLC0415

    # Validate Cypher has basic structure
    cypher_stripped = cypher.strip()
    if not cypher_stripped.upper().startswith("MATCH") and not cypher_stripped.upper().startswith("OPTIONAL"):
        console.print("[yellow]Warning: Cypher query does not start with MATCH. Saving anyway.[/yellow]")

    # Build the check dict
    check_def = {
        "id":             check_id,
        "title":          title,
        "severity":       severity,
        "description":    description or f"{title}",
        "cypher":         cypher_stripped,
        "recommendation": recommendation or "Review and remediate the affected resources.",
        "mitre":          [],
        "references":     [],
    }

    # Preview
    console.print()
    console.print(Panel(
        f"[bold]ID:[/bold]             {check_id}\n"
        f"[bold]Title:[/bold]          {title}\n"
        f"[bold]Severity:[/bold]       [{SEVERITY_COLORS.get(severity,'white')}]{severity}[/{SEVERITY_COLORS.get(severity,'white')}]\n"
        f"[bold]Framework:[/bold]      {framework}\n"
        f"[bold]Description:[/bold]    {(description or '—')[:80]}\n"
        f"[bold]Recommendation:[/bold] {(recommendation or '—')[:80]}\n"
        f"[bold]Cypher:[/bold]\n[dim]{cypher_stripped[:200]}{'...' if len(cypher_stripped)>200 else ''}[/dim]",
        title="[bold]New Check Preview[/bold]",
        border_style="cyan",
    ))

    if not click.confirm("Save this check?", default=True):
        console.print("[dim]Cancelled.[/dim]")
        return

    # Determine output path
    if output:
        out_path = _Path(output)
    else:
        checks_dir = _find_checks_dir()
        custom_dir = checks_dir / "custom"
        custom_dir.mkdir(parents=True, exist_ok=True)
        safe_fw = re.sub(r"[^a-z0-9_]", "_", framework.lower())
        out_path = custom_dir / f"{safe_fw}_checks.yaml"

    # Merge into existing file or create new
    if out_path.exists():
        try:
            existing = _yaml.safe_load(out_path.read_text())
            if isinstance(existing, dict) and "checks" in existing:
                # Check for duplicate ID
                existing_ids = {c.get("id") for c in existing.get("checks",[])}
                if check_id in existing_ids:
                    if not click.confirm(f"[yellow]Check {check_id} already exists in {out_path.name}. Overwrite?[/yellow]", default=False):
                        console.print("[dim]Cancelled.[/dim]")
                        return
                    existing["checks"] = [c for c in existing["checks"] if c.get("id") != check_id]
                existing["checks"].append(check_def)
                out_path.write_text(
                    _yaml.dump(existing, default_flow_style=False, allow_unicode=True, sort_keys=False),
                    encoding="utf-8",
                )
                n = len(existing["checks"])
                console.print(f"[green]Check {check_id} added to {out_path} ({n} checks total)[/green]")
            else:
                raise ValueError("Unexpected file structure")
        except Exception:
            # File exists but malformed — append as new
            _write_new_file(out_path, framework, check_def)
    else:
        _write_new_file(out_path, framework, check_def)

    console.print(f"[dim]Run: iamwatching checks reload[/dim]")
    console.print(f"[dim]Run: iamwatching checks show {check_id}   to verify[/dim]")


def _write_new_file(path, framework: str, check_def: dict):
    """Write a new YAML checks file with a single check."""
    import yaml as _yaml  # noqa: PLC0415
    data = {
        "framework":   framework,
        "description": f"Custom checks — {framework}",
        "checks":      [check_def],
    }
    path.write_text(
        _yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    console.print(f"[green]Check saved to {path}[/green]")


@checks.command("update")
@click.option("--family", default=None, multiple=True,
              help="Specific check family file to update (e.g. --family cis_aws.yaml). "
                   "Can be specified multiple times. Default: all families.")
@click.option("--dry-run", is_flag=True,
              help="Show what would be updated without downloading anything.")
def checks_update(family, dry_run):
    """
    Download the latest checks from official internet sources.

    Sources include IamWatching curated releases (CIS, OWASP, NIST, PCI, ISO,
    AWS, Azure, GCP), Prowler, and CloudSploit. Each framework family is stored
    in its own file so families can be updated independently.

    \b
    Examples:
      iamwatching checks update                     # Update all sources
      iamwatching checks update --dry-run           # Preview without downloading
      iamwatching checks update --family cis_aws.yaml --family nist_csf.yaml

    \b
    Run 'iamwatching checks sources' to see all available sources.
    """
    from iamwatching.patterns.registry import get_registry, _find_checks_dir  # noqa: PLC0415
    from iamwatching.patterns.updater import (                                 # noqa: PLC0415
        SOURCES, update_from_sources, get_manifest
    )

    checks_dir = _find_checks_dir()
    manifest   = get_manifest(checks_dir)

    # Map --family file names to source IDs
    if family:
        source_ids = [s.id for s in SOURCES if s.target_file in family]
        if not source_ids:
            console.print(f"[red]Unknown family file(s): {list(family)}[/red]")
            console.print(f"[dim]Available: {', '.join(s.target_file for s in SOURCES)}[/dim]")
            return
    else:
        source_ids = None  # all sources

    n_sources = len(source_ids) if source_ids else len(SOURCES)
    console.print(
        Panel(
            f"[bold]{'[DRY RUN] ' if dry_run else ''}Fetching from {n_sources} source(s)[/bold]\n"
            f"Checks directory: [cyan]{checks_dir / 'builtin'}[/cyan]\n"
            + ("[yellow]DRY RUN — no files will be written[/yellow]" if dry_run else
               "[dim]Existing files will be backed up to checks/.backups/ before overwriting[/dim]"),
            title="[bold cyan]IamWatching — Check Update[/bold cyan]",
            border_style="cyan",
        )
    )

    with console.status("[bold green]Fetching check definitions from internet sources...[/bold green]"):
        results = update_from_sources(
            checks_dir  = checks_dir,
            source_ids  = source_ids,
            dry_run     = dry_run,
            backup      = True,
        )

    table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    table.add_column("File",     style="dim",   width=35)
    table.add_column("Status",                  width=55)

    updated = unchanged = failed = 0
    for r in results:
        if r.status in ("updated", "dry_run"):
            icon, style = "[green]✓[/green]", "green"
            updated += 1
        elif r.status == "unchanged":
            icon, style = "[dim]=[/dim]", "dim"
            unchanged += 1
        else:
            icon, style = "[red]✗[/red]", "red"
            failed += 1

        status_text = (
            f"updated ({r.checks_count} checks)" if r.status == "updated" else
            f"dry_run ({r.checks_count} checks)" if r.status == "dry_run" else
            f"unchanged ({r.checks_count} checks)" if r.status == "unchanged" else
            f"FAILED: {r.error[:50]}"
        )
        table.add_row(f"{icon}  {r.source_name[:34]}", Text(status_text, style=style))

    console.print(table)

    if dry_run:
        console.print(f"\n[cyan]{updated} source(s) have updates available. Run without --dry-run to apply.[/cyan]")
    elif updated:
        console.print(f"\n[green]{updated} source(s) updated. Reloading registry...[/green]")
        registry = get_registry()
        n = registry.load(force=True)
        console.print(f"[green]{n} checks available.[/green]")
    else:
        console.print("\n[dim]All check files are already up to date.[/dim]")

    if failed:
        console.print(
            f"[red]{failed} source(s) failed.[/red]\n"
            "[dim]Check your internet connection or try again. "
            "Your existing check files were not modified.[/dim]"
        )

    console.print(
        f"\n[dim]Run 'iamwatching checks sources' to see all available sources.[/dim]\n"
        "[dim]Your custom checks in checks/custom/ are never touched by updates.[/dim]"
    )


def main():
    cli()


@checks.command("sources")
def checks_sources():
    """List all registered internet sources for check updates."""
    from iamwatching.patterns.updater import SOURCES, get_manifest  # noqa: PLC0415
    from iamwatching.patterns.registry import _find_checks_dir      # noqa: PLC0415

    manifest = get_manifest(_find_checks_dir())
    console.print(f"\n[bold]IamWatching Check Sources[/bold]  ({len(SOURCES)} registered)\n")

    table = Table(box=box.ROUNDED, show_lines=True,
                  title="[bold]Available Check Sources[/bold]")
    table.add_column("Source ID",   style="cyan",       width=22)
    table.add_column("Name",                            width=36)
    table.add_column("Publisher",                       width=20)
    table.add_column("Checks",      justify="right",    width=7)
    table.add_column("Last Updated",                    width=12)
    table.add_column("Target File", style="dim",        width=28)

    for s in SOURCES:
        last = manifest.get(s.id, {})
        last_date  = last.get("updated_at", "never")[:10] if last else "never"
        last_count = str(last.get("checks_count", "?")) if last else "?"
        table.add_row(
            s.id, s.name[:36], s.publisher[:20],
            last_count, last_date,
            s.target_file,
        )

    console.print(table)
    console.print(
        "\n[dim]Run: iamwatching checks update --source SOURCE_ID   to update a specific source[/dim]\n"
        "[dim]Run: iamwatching checks update                       to update all sources[/dim]\n"
    )


if __name__ == "__main__":
    main()
