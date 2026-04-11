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
_AWS_FRAMEWORK_PREFIXES   = [
    "CIS-AWS", "AWS-COMPUTE", "AWS-DATA",
    # Compliance frameworks: all current checks query AWSPrincipal/AWSResource
    "NIST", "OWASP", "PCI", "ISO",
]
_AZURE_FRAMEWORK_PREFIXES = ["AZURE"]
_GCP_FRAMEWORK_PREFIXES   = ["GCP"]
_ALWAYS_RUN_PREFIXES      = ["CROSS-CLOUD", "CUSTOM"]


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
                findings = await matcher.run_all(
                    severity_filter=sev_enum,
                    frameworks=family_filter,
                    scan_start_ms=scan_start_ms,
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
@click.option("--cypher", required=True, help="Cypher query string")
@click.option("--description", default="", help="What this check detects")
@click.option("--recommendation", default="", help="How to fix findings")
@click.option("--framework", default="CUSTOM", help="Framework name")
def checks_add(check_id, title, severity, cypher, description, recommendation, framework):
    """
    Add a custom check and save it to checks/custom/.

    \b
    Example:
      iamwatching checks add \\
        --id CUSTOM-010 \\
        --title "Roles without description" \\
        --severity LOW \\
        --cypher "MATCH (r:AWSPrincipal {principal_type:\'Role\'}) WHERE NOT r.metadata CONTAINS \'description\' RETURN r.arn" \\
        --recommendation "Add descriptions to all IAM roles for auditability"
    """
    import yaml as _yaml  # noqa: PLC0415
    from iamwatching.patterns.registry import get_registry, _find_checks_dir  # noqa: PLC0415

    checks_dir = _find_checks_dir()
    custom_dir = checks_dir / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)

    out_file = custom_dir / f"{check_id.lower().replace('-', '_')}.yaml"
    check_data = {
        "framework": framework,
        "description": f"Custom check: {title}",
        "checks": [{
            "id": check_id,
            "title": title,
            "severity": severity,
            "description": description,
            "cypher": cypher,
            "recommendation": recommendation,
            "mitre": [],
            "references": [],
        }]
    }
    with open(out_file, "w") as f:
        _yaml.dump(check_data, f, default_flow_style=False, allow_unicode=True)

    console.print(f"[green]Check {check_id} saved to {out_file}[/green]")
    console.print("[dim]Run 'iamwatching checks reload' or restart to pick it up.[/dim]")


@checks.command("update")
@click.option("--builtin", is_flag=True, help="Update built-in checks from latest release")
def checks_update(builtin):
    """
    Update checks from upstream sources.

    \b
    Without --builtin: shows instructions for manual update.
    With --builtin: displays update command for built-in check files.
    """
    from iamwatching.patterns.registry import _find_checks_dir  # noqa: PLC0415
    checks_dir = _find_checks_dir()

    if not builtin:
        console.print(Panel(
            "[bold]To update built-in checks:[/bold]\n\n"
            "  Option 1 — Download latest release:\n"
            "  [cyan]curl -sL https://github.com/anizacorp/iamwatching/releases/latest/download/checks.tar.gz | tar xz -C checks/[/cyan]\n\n"
            "  Option 2 — Copy updated YAML files into:[/cyan]\n"
            f"  [dim]{checks_dir / 'builtin'}[/dim]\n\n"
            "  Option 3 — Add custom checks in:\n"
            f"  [dim]{checks_dir / 'custom'}[/dim]\n\n"
            "  Then run: [cyan]iamwatching checks reload[/cyan]",
            title="Updating Checks",
            border_style="blue",
        ))
    else:
        console.print("[yellow]Built-in update via network not yet implemented.[/yellow]")
        console.print(f"Manually place YAML files in: [cyan]{checks_dir / 'builtin'}[/cyan]")

def main():
    cli()


if __name__ == "__main__":
    main()
