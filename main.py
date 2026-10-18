#!/usr/bin/env python3
"""CIS Palo Alto Auditor - audit first, explicitly opted-in remediation second."""
import argparse
import getpass
import re
import sys
from pathlib import Path

from lxml import etree
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cis_scanner import CISScanner
from src.panos_client import PanOSClient
from src.remediation import ALLOWED, prepare_change, guard_candidate_clean, apply_remediation
from src.reporting import make_report, save

console = Console()


def cli_args():
    p = argparse.ArgumentParser(
        description="CIS Palo Alto Auditor - 14 selected controls, HTML/JSON, safe remediation"
    )
    p.add_argument("--host", default="10.0.10.11", help="Single firewall (backward compatible)")
    p.add_argument("--hosts", nargs="+", help="Several firewall addresses")
    p.add_argument("--username", default="cis-auditor", help="Read-only audit user by default")
    tls = p.add_mutually_exclusive_group()
    tls.add_argument("--lab-insecure", action="store_true", help="Self-signed certificate: LAB ONLY")
    tls.add_argument("--ca-bundle", help="CA bundle for verified TLS")
    p.add_argument("--out-dir", default="reports")
    p.add_argument("--rules", default=None, help="Rule definitions YAML path")
    p.add_argument("--site-policy", default=None, help="Approved NTP servers YAML path")
    p.add_argument("--offline-fixture", default=None, help="Run without network on synthetic XML sample")
    p.add_argument("--remediate", choices=list(ALLOWED), help="Whitelisted CIS id; preview by default")
    p.add_argument("--apply", action="store_true", help="Actually stage and commit remediation")
    p.add_argument("--confirm-host", help="Must exactly match --host for writes")
    p.add_argument("--ack-ha", action="store_true",
                   help="Acknowledge change impact on HA pair and need to validate BOTH peers")
    return p.parse_args()


def status(st):
    colors = {"PASS": "green", "FAIL": "red", "REVIEW": "yellow",
              "ERROR": "bright_red", "N/A": "dim"}
    return Text(f"● {st}", style=f"bold {colors.get(st, 'white')}")


def fmt(value):
    if value is None:
        return "Not found"
    if isinstance(value, dict):
        return "; ".join(f"{k}: {v if v is not None else '-'}" for k, v in value.items())
    return str(value)


def header(host, args, mode):
    console.print(Panel.fit(
        "[bold bright_cyan]CIS PALO ALTO SECURITY AUDITOR[/bold bright_cyan]\n"
        "[dim]PAN-OS Configuration Compliance Assessment[/dim]",
        border_style="cyan", box=box.ROUNDED, padding=(1, 3)))
    console.print(f" [cyan]Target[/cyan]    {host}    "
                  f"[cyan]User[/cyan]    {args.username}    "
                  f"[cyan]Mode[/cyan]    {mode}\n")
    if args.lab_insecure:
        console.print(" [yellow]⚠ TLS verification disabled: isolated lab only[/yellow]\n")


def show_results(results, report):
    # Compact table remains readable in 80-column VS Code terminals.
    table = Table(title="CIS COMPLIANCE RESULTS", title_style="bold cyan",
                  box=box.ROUNDED, border_style="bright_black", show_lines=False,
                  header_style="bold cyan", expand=True)
    table.add_column("CIS", width=7, no_wrap=True, style="cyan")
    table.add_column("Security control", ratio=4)
    table.add_column("Result", width=10, justify="center", no_wrap=True)
    for r in results:
        table.add_row(r["id"], r["name"], status(r["status"]))
    console.print(table)

    s = report["summary"]
    metrics = Table.grid(padding=(0, 3))
    for _ in range(5):
        metrics.add_column(justify="center")
    metrics.add_row("[green]PASS[/green]", "[red]FAIL[/red]",
                    "[yellow]REVIEW[/yellow]", "[bright_red]ERROR[/bright_red]", "EVALUATED")
    metrics.add_row(str(s["pass"]), str(s["fail"]), str(s["review"]),
                    str(s["error"]), f"{s['evaluated']}/{s['total']}")
    score = (f"{s['compliance_percent']:.2f}%" if s["compliance_percent"] is not None else "N/A")
    console.print(Panel(metrics, title="ASSESSMENT SUMMARY", border_style="cyan", box=box.ROUNDED))
    console.print(f"  Compliance of evaluated controls: [bold cyan]{score}[/bold cyan]"
                  f"   |   Coverage: [bold]{s['coverage_percent']:.2f}%[/bold]")
    console.print("  [dim]REVIEW/ERROR not counted as PASS. NOT full Benchmark compliance.[/dim]\n")
    for r in results:
        if r["status"] in ("FAIL", "REVIEW", "ERROR"):
            console.print(f" [yellow]• CIS {r['id']} ({r['status']}):[/yellow]"
                          f" Expected: {r['expected']} | Actual: {fmt(r['actual'])}")
            if r.get("reason"):
                console.print(f"   [dim]{r['reason']}[/dim]")


def parse_xml(path):
    return etree.parse(str(path), parser=etree.XMLParser(
        resolve_entities=False, no_network=True, huge_tree=False
    )).getroot()


def evaluate(config, args, ha_state=None):
    scanner = CISScanner(config, rules_path=args.rules, site_policy=args.site_policy,
                         ha_state=ha_state)
    return scanner.scan()


def report_for(host, args, results, mode="READ_ONLY_AUDIT", metadata=None):
    report = make_report(host, args.username, results, mode=mode, metadata=metadata)
    show_results(results, report)
    json_path, html_path = save(report, args.out_dir)
    console.print(f" [green]✔[/green] JSON: [cyan]{json_path}[/cyan]")
    console.print(f" [green]✔[/green] HTML: [cyan]{html_path}[/cyan]\n")
    return report


def main():
    args = cli_args()
    hosts = args.hosts or [args.host]
    if args.apply and not args.remediate:
        raise SystemExit("--apply requires --remediate ID")
    if args.remediate and len(hosts) != 1:
        raise SystemExit("Remediate exactly ONE firewall at a time (--host)")
    if args.offline_fixture and args.apply:
        raise SystemExit("Offline fixture cannot be modified")
    if args.apply:
        if args.confirm_host != hosts[0] or not args.ack_ha:
            raise SystemExit("Write blocked: require --confirm-host <same IP> and --ack-ha")
        if not sys.stdin.isatty():
            raise SystemExit("Write blocked: interactive terminal required")
    if args.lab_insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for host in hosts:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host):
            raise SystemExit(f"Invalid host: {host}")
        mode = "REMEDIATION PREVIEW" if args.remediate else "READ_ONLY AUDIT"
        header(host, args, mode)
        client = None
        try:
            if args.offline_fixture:
                config = parse_xml(Path(args.offline_fixture))
                ha_state = None
                console.print(" [cyan]◆[/cyan] Synthetic offline fixture loaded; no firewall contacted")
            else:
                verify_tls = False if args.lab_insecure else args.ca_bundle or True
                password = getpass.getpass(f"Password for {args.username}@{host}: ")
                client = PanOSClient(host, verify_tls=verify_tls)
                client.authenticate(args.username, password)
                console.print(" [green]✔[/green] Authenticated via PAN-OS XML API")
                config = client.get_config("show")
                console.print(" [green]✔[/green] Running Configuration retrieved")
                try:
                    ha_state = client.get_ha_state()
                    console.print(" [green]✔[/green] HA operational state retrieved")
                except Exception as exc:
                    ha_state = None
                    console.print(f" [yellow]◆[/yellow] HA op unavailable: {type(exc).__name__} (CIS 3.1 -> REVIEW)")
            results = evaluate(config, args, ha_state)
            report_for(host, args, results, mode=mode)

            if not args.remediate:
                continue

            item = next(r for r in results if r["id"] == args.remediate)
            changes = prepare_change(args.remediate, config, item["status"])
            preview = Table(title="REMEDIATION PLAN - WHITELIST ONLY", box=box.ROUNDED,
                            border_style="yellow", expand=True)
            preview.add_column("XPath", ratio=2)
            preview.add_column("Element", ratio=1)
            for change in changes:
                preview.add_row(change["xpath"], change["element"])
            console.print(preview)
            if not args.apply:
                console.print(" [yellow]DRY RUN ONLY: no API write, no commit.[/yellow]\n"
                              " To execute, use --apply --confirm-host HOST --ack-ha\n"
                              " with a SEPARATE write-authorized PAN-OS account.\n")
                continue
            if client is None:
                raise RuntimeError("Live authenticated client required")
            console.print(" [yellow]⚠ Verify HA synchronization, backup and maintenance window.[/yellow]")
            confirm = input(f"Type 'APPLY {host} {args.remediate}' to modify firewall: ").strip()
            if confirm != f"APPLY {host} {args.remediate}":
                console.print(" [yellow]Cancelled - no changes made.[/yellow]")
                continue
            guard_candidate_clean(client, config)
            console.print(" [yellow]◆[/yellow] Candidate clean; staging allowlisted XML only...")
            job = apply_remediation(client, changes, args.username)
            console.print(f" [green]✔[/green] Commit job {job} finished OK")
            after_config = client.get_config("show")
            try:
                after_ha = client.get_ha_state()
            except Exception:
                after_ha = None
            after_results = evaluate(after_config, args, after_ha)
            newitem = next(r for r in after_results if r["id"] == args.remediate)
            report_for(host, args, after_results, mode="POST_REMEDIATION_AUDIT",
                       metadata={"control": args.remediate, "commit_job": job,
                                 "before": item["status"], "after": newitem["status"]})
            if newitem["status"] != "PASS":
                console.print(" [red]✖ Post-check not PASS. Inspect candidate, job and HA peer manually.[/red]")
                raise SystemExit(2)
            console.print(" [green]✔[/green] Remediation verified PASS on target; inspect second HA peer separately")
        except (KeyboardInterrupt, EOFError):
            console.print("\n [yellow]Interrupted. If a write started, inspect candidate/commit jobs.[/yellow]")
            raise SystemExit(130)
        except Exception as exc:
            console.print(Panel(f"{type(exc).__name__}: {exc}", title="OPERATION FAILED",
                                border_style="red", box=box.ROUNDED))
            raise SystemExit(1)
        finally:
            if client:
                client.close()


if __name__ == "__main__":
    main()
