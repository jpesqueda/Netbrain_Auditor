"""Inventory normalization, pagination and deterministic audit rules."""
import ipaddress
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from .client import APIError, ci_get, require_list

LOG = logging.getLogger("netbrain_auditor")
EMPTY = {"", "n/a", "na", "none", "null", "unknown", "not available", "-", "not applicable"}
FIELDS = ["Device_ID", "Hostname", "Management_IP", "Device_Type", "Vendor", "Model",
          "Serial", "Software_Version", "Site", "Location", "First_Discovery", "Last_Discovery",
          "Age_Days", "Discovery_Status", "Audit_Status"]
FINDING_FIELDS = ["Device_ID", "Hostname", "Management_IP", "Category", "Finding",
                  "Severity", "Current_Value", "Recommended_Action"]
DUP_FIELDS = ["Type", "Value", "Device_Count", "Device_ID", "Hostname", "Management_IP"]


def value(record, *keys):
    for key in keys:
        v = ci_get(record, key)
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            s = str(v).strip()
            if s.casefold() not in EMPTY:
                return s
    return ""


def parse_date(raw):
    try:
        if isinstance(raw, dict):
            raw = raw.get("$date")
        if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.isdigit()):
            n = float(raw)
            return datetime.fromtimestamp(n / 1000 if abs(n) > 100_000_000_000 else n, timezone.utc)
        if isinstance(raw, str):
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt.replace(tzinfo=dt.tzinfo or timezone.utc).astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def get_date(record, *keys):
    for key in keys:
        parsed = parse_date(ci_get(record, key))
        if parsed is not None:
            return parsed
    return None


def collect(client, page_size, progress):
    rows = []
    ids = set()
    fingerprints = set()
    total = None
    while True:
        payload = client.device_page(len(rows), page_size)
        page = require_list(payload, "devices")
        expected = ci_get(payload, "totalResultCount")
        if expected is not None:
            try:
                if isinstance(expected, bool) or not str(expected).isdigit():
                    raise ValueError
                expected = int(expected)
            except (ValueError, TypeError):
                raise APIError("Invalid totalResultCount") from None
            if total is not None and expected != total:
                raise APIError("Inventory count changed during pagination; rerun")
            total = expected
        if len(page) > page_size:
            raise APIError("API returned more devices than requested")
        if not page:
            if total is not None and len(rows) != total:
                raise APIError("Inventory ended before reported total")
            break
        fingerprint = json.dumps(page, sort_keys=True, ensure_ascii=False)
        if fingerprint in fingerprints:
            raise APIError("Repeated inventory page; pagination may be ignored")
        fingerprints.add(fingerprint)
        for rec in page:
            ident = value(rec, "id", "deviceId", "devicesID")
            if ident:
                if ident in ids:
                    raise APIError("Repeated device ID during pagination; coverage uncertain")
                ids.add(ident)
        rows.extend(page)
        progress(len(rows), total)
        LOG.info("Inventory page: collected=%s reported_total=%s", len(rows), total)
        if total is not None and len(rows) > total:
            raise APIError("Collected count exceeds reported total")
        if len(rows) > 1_000_000:
            raise APIError("Inventory safety limit reached")
    return rows, "COUNT_MATCHED" if total is not None else "PAGINATION_EXHAUSTED"


def normalize(rec, now, stale_days):
    first = get_date(rec, "fDiscoveryTime", "firstDiscoveryTime", "firstDiscoverTime")
    last = get_date(rec, "lDiscoveryTime", "lastDiscoveryTime", "lastDiscoverTime")
    age = (now - last).days if last and last <= now else None
    ip = value(rec, "mgmtIP", "managementIP", "ip")
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        pass
    return dict(zip(FIELDS, [
        value(rec, "id", "deviceId", "devicesID"), value(rec, "name", "hostname"),
        ip, value(rec, "subTypeName", "deviceTypeName", "deviceType"),
        value(rec, "vendor"), value(rec, "model"), value(rec, "sn", "serial", "serialNumber"),
        value(rec, "ver", "softwareVersion", "osVersion"), value(rec, "site", "siteName"),
        value(rec, "loc", "location"), first.isoformat() if first else "",
        last.isoformat() if last else "", age if age is not None else "",
        "UNKNOWN" if age is None else ("STALE" if age >= stale_days else "CURRENT"), "PASS"
    ]))


def audit(records, stale_days, policy=None, now=None):
    now = now or datetime.now(timezone.utc)
    inventory = [normalize(x, now, stale_days) for x in records]
    findings, duplicates, software = [], [], []
    flagged = set()

    def add(i, category, finding, severity, current, action):
        d = inventory[i]
        findings.append(dict(zip(FINDING_FIELDS, [d["Device_ID"], d["Hostname"],
            d["Management_IP"], category, finding, severity, current, action])))
        flagged.add(i)

    for i, d in enumerate(inventory):
        for field in ("Device_ID", "Hostname", "Management_IP", "Device_Type", "Vendor",
                      "Model", "Serial", "Software_Version", "Site"):
            if not d[field]:
                add(i, "DATA_QUALITY", f"Missing {field}", "MEDIUM", "", "Verify NetBrain device attributes")
        if d["Management_IP"]:
            try:
                ipaddress.ip_address(d["Management_IP"])
            except ValueError:
                add(i, "DATA_QUALITY", "Invalid management IP", "HIGH", d["Management_IP"], "Review management address")
        if d["Site"] and d["Site"].replace("/", chr(92)).split(chr(92))[-1].strip().casefold() == "unassigned":
            add(i, "DATA_QUALITY", "Unassigned site", "MEDIUM", d["Site"], "Review site assignment")
        if d["Discovery_Status"] == "STALE":
            add(i, "DISCOVERY", "Stale discovery", "HIGH", d["Age_Days"], "Review discovery and reachability")
        elif d["Discovery_Status"] == "UNKNOWN":
            add(i, "DISCOVERY", "Unknown discovery age", "MEDIUM", d["Last_Discovery"], "Verify discovery timestamp")
        allowed = None
        for prefix in sorted(policy or {}, key=len, reverse=True):
            if d["Model"].casefold().startswith(prefix.casefold()):
                allowed = policy[prefix]
                break
        status = "NOT_EVALUATED" if policy is None else ("UNKNOWN_MODEL" if allowed is None else
                 ("UNKNOWN_VERSION" if not d["Software_Version"] else
                  ("PASS" if d["Software_Version"] in allowed else "FAIL")))
        if status == "FAIL":
            add(i, "SOFTWARE", "Unapproved version", "HIGH", d["Software_Version"], "Review approved software policy")
        software.append({k: d[k] for k in ["Device_ID", "Hostname", "Management_IP", "Vendor", "Model", "Software_Version"]} |
                        {"Approved_Versions": "; ".join(allowed or []), "Status": status})

    for field in ("Management_IP", "Hostname", "Serial"):
        groups = defaultdict(list)
        for i, d in enumerate(inventory):
            if d[field]:
                groups[str(d[field]).casefold()].append(i)
        for group in groups.values():
            if len(group) < 2:
                continue
            for i in group:
                d = inventory[i]
                duplicates.append(dict(zip(DUP_FIELDS, [field, d[field], len(group), d["Device_ID"],
                                                          d["Hostname"], d["Management_IP"]])))
                add(i, "DUPLICATE", f"Possible duplicate {field}", "HIGH", d[field], "Validate unique device identity")
    for i in flagged:
        inventory[i]["Audit_Status"] = "REVIEW"
    return inventory, findings, duplicates, software


def version_summary(inventory):
    counts = Counter((d["Vendor"], d["Model"], d["Software_Version"]) for d in inventory)
    return [dict(zip(["Vendor", "Model", "Software_Version", "Devices"], (*key, count)))
            for key, count in sorted(counts.items())]
