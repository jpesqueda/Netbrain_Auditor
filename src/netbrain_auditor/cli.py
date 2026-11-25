"""Command-line interface and report generation."""
import argparse
import csv
import getpass
import json
import logging
import os
import platform
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import yaml
from . import __version__
from .client import NetBrain, AuditError, APIError, AuthenticationError, ConnectivityError, ci_get
from .audit import audit, collect, FIELDS, FINDING_FIELDS, DUP_FIELDS, version_summary

LOG = logging.getLogger("netbrain_auditor")
CONSOLE = Console(markup=False)
SOFTWARE_FIELDS = ["Device_ID", "Hostname", "Management_IP", "Vendor", "Model",
                   "Software_Version", "Approved_Versions", "Status"]


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Read-only NetBrain inventory and data quality audit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  netbrain-auditor --url https://netbrain.example.local -u USERNAME -o Network_Audit
  netbrain-auditor --url https://netbrain.example.local -u USERNAME --tenant LAB-TENANT --domain LAB-DOMAIN -o Reports
  netbrain-auditor --from-json examples/devices.json -o Demo
  netbrain-auditor --from-json examples/devices.json --software-policy examples/approved_versions.yaml -o Demo
  netbrain-auditor --stale-days 60 -o Reports --overwrite
  netbrain-auditor --help
""")
    p.add_argument("--version", action="version", version=f"Netbrain_Auditor {__version__}")
    p.add_argument("--url", help="HTTPS NetBrain base URL; prompted if omitted")
    p.add_argument("-u", "--user", "--username", help="Username; prompted if omitted")
    p.add_argument("-p", "--password", "--pasword", help="Password (prefer secure prompt; CLI arguments may be exposed)")
    p.add_argument("--auth-id")
    p.add_argument("--tenant", help="Tenant name or ID")
    p.add_argument("--domain", help="Domain name or ID")
    tls = p.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true", help="Disable TLS verification; unsafe outside trusted labs")
    tls.add_argument("--ca-file", help="Trusted CA certificate bundle")
    p.add_argument("-o", "--output", help="Report directory; prompted if omitted")
    p.add_argument("--overwrite", action="store_true", help="Replace generated reports in an existing directory")
    p.add_argument("--from-json", help="Audit a local device list or API response without connecting")
    p.add_argument("--raw-json", action="store_true", help="Save collected inventory as Raw_Inventory.json (sensitive)")
    p.add_argument("--stale-days", type=int, default=30, help="Discovery age threshold in days (default: 30)")
    p.add_argument("--software-policy", help="YAML file with approved_versions mapping")
    p.add_argument("--page-size", type=int, choices=range(10, 101), metavar="10-100", default=100)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--retry-backoff", type=float, default=1.0)
    p.add_argument("-v", "--verbose", action="store_true", help="Additional diagnostics in log")
    a = p.parse_args(argv)
    if a.stale_days < 1 or a.timeout < 1 or not 0 <= a.retries <= 10 or not 0 <= a.retry_backoff <= 60:
        p.error("Invalid stale-days, timeout, retries (0-10), or backoff (0-60)")
    if a.from_json and any([a.url, a.user, a.password, a.tenant, a.domain, a.auth_id, a.insecure, a.ca_file]):
        p.error("--from-json cannot be combined with live connection options")
    return a


def choose(items, wanted, name, ident, label):
    if not items:
        raise APIError(f"No accessible {label}s")
    if wanted:
        matches = [x for x in items if str(wanted).casefold() in
                   {str(ci_get(x, name)).casefold(), str(ci_get(x, ident)).casefold()}]
        if len(matches) != 1:
            raise AuditError(f"Requested {label} not found or ambiguous")
        return matches[0]
    if len(items) == 1:
        return items[0]
    if not sys.stdin.isatty():
        raise AuditError(f"Specify --{label} for non-interactive operation")
    for i, item in enumerate(items, 1):
        CONSOLE.print(f"  {i}. {ci_get(item, name)}")
    try:
        index = int(input(f"Select {label}: "))
    except ValueError:
        raise AuditError(f"Invalid {label} selection") from None
    if not 1 <= index <= len(items):
        raise AuditError(f"Invalid {label} selection")
    return items[index - 1]


def load_policy(path):
    if not path:
        return None
    obj = yaml.safe_load(Path(path).read_text(encoding="utf-8-sig"))
    rules = obj.get("approved_versions") if isinstance(obj, dict) else None
    if not isinstance(rules, dict) or not rules:
        raise AuditError("Policy must contain a nonempty approved_versions mapping")
    seen = set()
    for k, v in rules.items():
        if (not isinstance(k, str) or not k.strip() or k.casefold() in seen or
                not isinstance(v, list) or not v or any(not isinstance(x, str) or not x.strip() for x in v)):
            raise AuditError("Policy requires unique model prefixes and nonempty lists of quoted version strings")
        seen.add(k.casefold())
    return rules


def load_snapshot(path):
    obj = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(obj, dict):
        code = ci_get(obj, "statusCode")
        if code is not None and str(code) not in ("790200", "200", "0"):
            raise APIError("Snapshot contains an API error")
        obj = ci_get(obj, "devices")
    if not isinstance(obj, list) or any(not isinstance(x, dict) for x in obj):
        raise AuditError("Snapshot must contain a device list")
    return obj


def safe_cell(v):
    # Prevent spreadsheet formula injection from untrusted device attributes.
    if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + v
    return v


def atomic_write(path, write):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".audit-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as f:
            write(f)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_csv(path, fields, rows):
    def write(f):
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: safe_cell(row.get(k, "")) for k in fields})
    atomic_write(path, write)


def report(out, records, coverage, scope, policy, stale_days, raw):
    inventory, findings, duplicates, software = audit(records, stale_days, policy)
    summary = {
        "Scope": scope, "Coverage": coverage, "Total devices": len(inventory),
        "Devices with findings": sum(d["Audit_Status"] == "REVIEW" for d in inventory),
        "Devices without findings": sum(d["Audit_Status"] == "PASS" for d in inventory),
        "Findings": len(findings),
        "Stale devices": sum(d["Discovery_Status"] == "STALE" for d in inventory),
        "Unknown discovery age": sum(d["Discovery_Status"] == "UNKNOWN" for d in inventory),
        "Software exceptions": sum(d["Status"] == "FAIL" for d in software),
        "Software policy": "ENABLED" if policy is not None else "NOT_EVALUATED",
        "Duplicate groups": len({(d["Type"], str(d["Value"]).casefold()) for d in duplicates}),
        "Stale threshold days": stale_days,
    }
    for key, count in sorted(Counter(d["Device_Type"] or "UNKNOWN" for d in inventory).items()):
        summary["Device type: " + key] = count
    for key, count in sorted(Counter(d["Severity"] for d in findings).items()):
        summary["Severity: " + key] = count
    for key, count in sorted(Counter(d["Status"] for d in software).items()):
        summary["Software status: " + key] = count
    outputs = [
        ("Network_Inventory.csv", FIELDS, inventory),
        ("Audit_Findings.csv", FINDING_FIELDS, findings),
        ("Software_Versions.csv", SOFTWARE_FIELDS, software),
        ("Software_Summary.csv", ["Vendor", "Model", "Software_Version", "Devices"], version_summary(inventory)),
        ("Stale_Devices.csv", FIELDS, [d for d in inventory if d["Discovery_Status"] == "STALE"]),
        ("Missing_Information.csv", FINDING_FIELDS, [d for d in findings if d["Category"] == "DATA_QUALITY" or d["Finding"] == "Unknown discovery age"]),
        ("Duplicate_Devices.csv", DUP_FIELDS, duplicates),
        ("Audit_Summary.csv", ["Metric", "Value"], [{"Metric": k, "Value": v} for k, v in summary.items()]),
    ]
    for name, fields, rows in outputs:
        write_csv(out / name, fields, rows)
        LOG.info("Report %s: %s rows", name, len(rows))
    if raw:
        atomic_write(out / "Raw_Inventory.json", lambda f: json.dump(records, f, indent=2, ensure_ascii=False))
        LOG.warning("Raw inventory contains network data")
    return summary


def main(argv=None):
    a = parse_args(argv)
    start = time.monotonic()
    client = None
    handler = None
    log_path = None
    try:
        out = Path(a.output or input("Output directory [Network_Audit]: ").strip() or "Network_Audit").expanduser()
        out.mkdir(parents=True, exist_ok=True)
        if not a.overwrite and any(out.iterdir()):
            raise AuditError("Output directory is not empty. Choose another -o or use --overwrite.")
        names = ["Network_Inventory.csv", "Audit_Findings.csv", "Software_Versions.csv",
                 "Software_Summary.csv", "Stale_Devices.csv", "Missing_Information.csv",
                 "Duplicate_Devices.csv", "Audit_Summary.csv", "Network_Audit.log", "Raw_Inventory.json"]
        # Never overwrite source or policy, even when --overwrite is requested.
        for source in (a.from_json, a.software_policy, a.ca_file):
            if source and any(Path(source).resolve() == (out / n).resolve() for n in names):
                raise AuditError("Input file conflicts with a generated output")
        log_path = out / "Network_Audit.log"
        handler = logging.FileHandler(log_path, mode="w" if a.overwrite else "x", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        LOG.addHandler(handler)
        LOG.setLevel(logging.DEBUG if a.verbose else logging.INFO)
        LOG.info("Version=%s Python=%s Platform=%s mode=%s", __version__, platform.python_version(),
                 platform.system(), "OFFLINE" if a.from_json else "LIVE")
        LOG.info("Timeout=%s retries=%s backoff=%s stale_days=%s page_size=%s TLS verify=%s",
                 a.timeout, a.retries, a.retry_backoff, a.stale_days, a.page_size, not a.insecure)
        policy = load_policy(a.software_policy)
        CONSOLE.print("=" * 68, style="green")
        CONSOLE.print("NETBRAIN NETWORK AUDITOR".center(68), style="green")
        CONSOLE.print("=" * 68, style="green")
        if a.from_json:
            CONSOLE.print("[+] Loading offline inventory...", style="green")
            records = load_snapshot(a.from_json)
            coverage, scope = "OFFLINE_UNVERIFIED", "OFFLINE_SNAPSHOT"
        else:
            url = (a.url or input("NetBrain URL: ")).strip()
            user = a.user or input("NetBrain Username: ").strip()
            password = a.password if a.password is not None else getpass.getpass("NetBrain Password: ")
            a.password = None
            if not user or not password:
                raise AuthenticationError("Username and password are required")
            client = NetBrain(url, user, password, auth_id=a.auth_id, insecure=a.insecure,
                              ca_file=a.ca_file, timeout=a.timeout, retries=a.retries, backoff=a.retry_backoff)
            del password
            CONSOLE.print("[+] Validating NetBrain connectivity...", style="green")
            CONSOLE.print(f"    URL    : {url}")
            client.validate_connection()
            CONSOLE.print("    Status : Reachable", style="green")
            CONSOLE.print("[+] Connecting to NetBrain API...", style="green")
            client.login()
            CONSOLE.print("    Login  : Successful", style="green")
            CONSOLE.print("    Token  : Received", style="green")
            scope = client.select_domain(a.tenant, a.domain, choose)
            CONSOLE.print(f"    Domain : {scope}", style="green")
            LOG.info("Selected domain: %s", scope)
            CONSOLE.print("[+] Collecting network inventory...", style="green")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                          TaskProgressColumn(), console=CONSOLE) as progress:
                task = progress.add_task("Devices: 0", total=None)
                def update(count, total):
                    progress.update(task, description=f"Devices: {count}", completed=count, total=total)
                records, coverage = collect(client, a.page_size, update)
                progress.update(task, total=max(1, len(records)), completed=max(1, len(records)))
        CONSOLE.print("[+] Running inventory audit...", style="green")
        summary = report(out, records, coverage, scope, policy, a.stale_days, a.raw_json)
        CONSOLE.print("=" * 68, style="green")
        CONSOLE.print("SUMMARY".center(68), style="green")
        CONSOLE.print("=" * 68, style="green")
        for k in ["Total devices", "Devices without findings", "Devices with findings", "Findings",
                  "Stale devices", "Unknown discovery age", "Duplicate groups", "Software exceptions",
                  "Software policy", "Coverage"]:
            CONSOLE.print(f"    {k:25}: {summary[k]}")
        CONSOLE.print(f"    {'Report directory':25}: {out}")
        CONSOLE.print(f"    {'Diagnostic log':25}: {log_path}")
        CONSOLE.print(f"    {'Execution time':25}: {time.monotonic()-start:.2f}s")
        CONSOLE.print("[+] Audit completed successfully.", style="green")
        return 0
    except KeyboardInterrupt:
        LOG.warning("Cancelled")
        CONSOLE.print("[-] Cancelled by user.", style="yellow")
        return 130
    except (AuthenticationError, ConnectivityError, AuditError, OSError, ValueError, yaml.YAMLError, EOFError) as exc:
        LOG.error("%s: %s", type(exc).__name__, exc)
        message = ("NetBrain authentication failed." if isinstance(exc, AuthenticationError) else
                   "Unable to reach NetBrain server." if isinstance(exc, ConnectivityError) else
                   "NetBrain API or inventory validation failed." if isinstance(exc, APIError) else
                   str(exc) if isinstance(exc, AuditError) else "Input or file operation failed.")
        CONSOLE.print(f"[-] ERROR: {message}", style="red")
        if log_path and handler:
            CONSOLE.print(f"    Diagnostic log: {log_path}")
        return 3 if isinstance(exc, AuthenticationError) else 4 if isinstance(exc, ConnectivityError) else 5 if isinstance(exc, APIError) else 2
    except Exception as exc:
        LOG.error("Unexpected error type: %s", type(exc).__name__)
        CONSOLE.print(f"[-] ERROR: Unexpected {type(exc).__name__}.", style="red")
        if log_path and handler:
            CONSOLE.print(f"    Diagnostic log: {log_path}")
        return 1
    finally:
        if client:
            client.close()
        if handler:
            LOG.info("Execution time: %.2fs", time.monotonic()-start)
            LOG.removeHandler(handler)
            handler.close()
