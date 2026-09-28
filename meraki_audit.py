#!/usr/bin/env python3
"""
Meraki Network Audit Toolkit
============================
A read-only collection layer and check framework for Cisco Meraki
organizations, built on the Dashboard API.

What this does:
  - Collects inventory, networks, device status, admins, licensing,
    SSIDs, VLANs, syslog and alert configuration, and change history
  - Handles rate limiting, cursor pagination and transient failures
  - Runs a set of checks over the collected data and reports findings
  - Exports a CSV inventory and an HTML summary

The checks included here are a starter set. The framework is designed so
you can add your own: write a function that inspects the collected data
and returns finding() objects, and register it in CHECKS.

Every API call is a GET. There is no code path here that writes to the
Dashboard.

Usage:
    python3 meraki_audit.py --key <API_KEY> [--org <ORG_ID>]
    python3 meraki_audit.py --key <API_KEY> --list-orgs
    python3 meraki_audit.py --demo

Author: Wilson Ramirez
Licence: MIT
"""

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run:  pip install requests")

BASE_URL = "https://api.meraki.com/api/v1"
USER_AGENT = "NetworkAuditToolkit/1.0"
MAX_RETRIES = 5


# ---------------------------------------------------------------- API client

class MerakiClient:
    """Minimal read-only Dashboard API client with rate-limit handling."""

    def __init__(self, api_key, verbose=True):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "X-Cisco-Meraki-API-Key": api_key,
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        })
        self.call_count = 0

    def log(self, msg):
        if self.verbose:
            print(f"  {msg}", file=sys.stderr)

    def get(self, path, params=None, tolerate=(404, 400)):
        """GET with retry/backoff. Returns None on tolerated errors."""
        url = f"{BASE_URL}{path}"
        params = dict(params or {})
        results = []

        for attempt in range(MAX_RETRIES):
            try:
                resp = self.session.get(url, params=params, timeout=45)
            except requests.RequestException as exc:
                wait = 2 ** attempt
                self.log(f"network error on {path}: {exc} - retry in {wait}s")
                time.sleep(wait)
                continue

            self.call_count += 1

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 2))
                self.log(f"rate limited on {path} - waiting {wait}s")
                time.sleep(wait)
                continue

            if resp.status_code in tolerate:
                return None

            if resp.status_code >= 400:
                self.log(f"HTTP {resp.status_code} on {path}: {resp.text[:160]}")
                return None

            try:
                payload = resp.json()
            except ValueError:
                return None

            # Follow cursor pagination when present.
            if isinstance(payload, list):
                results.extend(payload)
                nxt = self._next_link(resp)
                if nxt:
                    url, params = nxt, None
                    time.sleep(0.2)
                    continue
                return results

            return payload

        self.log(f"giving up on {path} after {MAX_RETRIES} attempts")
        return None

    @staticmethod
    def _next_link(resp):
        link = resp.headers.get("Link", "")
        for part in link.split(","):
            if 'rel=next' in part:
                start = part.find("<")
                end = part.find(">")
                if start != -1 and end != -1:
                    return part[start + 1:end]
        return None


# ------------------------------------------------------------- data collection

def collect(client, org_id, org_name):
    """Gather everything the audit needs. All calls are read-only."""
    data = {
        "meta": {
            "org_id": org_id,
            "org_name": org_name,
            "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    }

    steps = [
        ("networks",         f"/organizations/{org_id}/networks", None),
        ("devices",          f"/organizations/{org_id}/devices", None),
        ("device_statuses",  f"/organizations/{org_id}/devices/statuses", None),
        ("admins",           f"/organizations/{org_id}/admins", None),
        ("licenses_overview",f"/organizations/{org_id}/licenses/overview", None),
        ("uplink_statuses",  f"/organizations/{org_id}/appliance/uplink/statuses", None),
        ("firmware",         f"/organizations/{org_id}/firmware/upgrades", {"perPage": 100}),
        ("config_changes",   f"/organizations/{org_id}/configurationChanges", {"timespan": 2592000}),
        ("api_requests",     f"/organizations/{org_id}/apiRequests/overview", {"timespan": 2592000}),
    ]

    for key, path, params in steps:
        print(f"[collect] {key} ...", file=sys.stderr)
        data[key] = client.get(path, params) or ([] if key != "licenses_overview" else {})

    # Per-network detail
    networks = data.get("networks") or []
    data["ssids"] = {}
    data["vlans"] = {}
    data["net_settings"] = {}
    data["syslog"] = {}
    data["alerts"] = {}

    for net in networks:
        nid = net.get("id")
        nname = net.get("name", nid)
        ptypes = net.get("productTypes", [])
        print(f"[collect] network detail: {nname}", file=sys.stderr)

        if "wireless" in ptypes:
            ssids = client.get(f"/networks/{nid}/wireless/ssids")
            if ssids:
                data["ssids"][nid] = ssids

        if "appliance" in ptypes:
            vlans = client.get(f"/networks/{nid}/appliance/vlans")
            if vlans:
                data["vlans"][nid] = vlans

        settings = client.get(f"/networks/{nid}/settings")
        if settings:
            data["net_settings"][nid] = settings

        syslog = client.get(f"/networks/{nid}/syslogServers")
        if syslog is not None:
            data["syslog"][nid] = syslog

        alerts = client.get(f"/networks/{nid}/alerts/settings")
        if alerts:
            data["alerts"][nid] = alerts

        time.sleep(0.15)

    data["meta"]["api_calls"] = client.call_count
    return data




# ------------------------------------------------------------ check framework

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def finding(fid, severity, title, detail, recommendation, affected=None):
    """Build a single finding. Severity is one of SEVERITY_ORDER's keys."""
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
        "affected": affected or [],
    }


# --- checks -----------------------------------------------------------------
#
# A check is a function that takes the collected data and returns a list of
# findings. Register it in CHECKS at the bottom of this section.
#
# The four below are a starter set covering the areas most estates fail on
# first. Extend with your own for licensing, logging coverage, naming
# conventions, change attribution, or whatever your standard requires.


def check_admin_2fa(data):
    """Administrators who can sign in with a password alone."""
    admins = data.get("admins") or []
    weak = [a.get("email") for a in admins if not a.get("twoFactorAuthEnabled")]
    if not weak:
        return []
    return [finding(
        "IAM-01", "High",
        "Dashboard administrators without two-factor authentication",
        f"{len(weak)} of {len(admins)} administrator accounts can sign in with a "
        "password alone. A single credential leak grants full access.",
        "Enforce two-factor authentication organization-wide under "
        "Organization > Settings.",
        weak)]


def check_open_ssids(data):
    """Enabled SSIDs broadcasting without encryption or a splash page."""
    networks = {n["id"]: n.get("name", n["id"]) for n in (data.get("networks") or [])}
    open_ssids = []
    for nid, ssids in (data.get("ssids") or {}).items():
        for s in ssids:
            if not s.get("enabled"):
                continue
            if (s.get("authMode") or "").lower() == "open" and not s.get("splashPage"):
                open_ssids.append(f"{networks.get(nid, nid)} / {s.get('name')}")
    if not open_ssids:
        return []
    return [finding(
        "WLAN-01", "Critical",
        "Wireless networks broadcasting without encryption",
        f"{len(open_ssids)} enabled SSID(s) accept clients with no encryption and "
        "no captive portal. Traffic is readable to anyone in range.",
        "Apply WPA2/WPA3, or isolate the SSID on a guest VLAN behind a splash "
        "page with client isolation enabled.",
        open_ssids)]


def check_device_status(data):
    """Devices the Dashboard cannot reach, or that are reporting a fault."""
    devices = data.get("devices") or []
    names = {d.get("serial"): (d.get("name") or d.get("model") or d.get("serial"))
             for d in devices}
    buckets = defaultdict(list)
    for st in data.get("device_statuses") or []:
        buckets[(st.get("status") or "unknown").lower()].append(
            names.get(st.get("serial"), st.get("serial")))

    out = []
    if buckets.get("offline"):
        out.append(finding(
            "OPS-01", "High", "Devices reporting offline",
            f"{len(buckets['offline'])} device(s) are not reachable. Each is either "
            "lost coverage, a failed unit, or stale inventory consuming a licence.",
            "Confirm whether each is decommissioned or genuinely down, and remove "
            "decommissioned units to reclaim licensing.",
            buckets["offline"]))
    if buckets.get("alerting"):
        out.append(finding(
            "OPS-02", "Medium", "Devices in an alerting state",
            f"{len(buckets['alerting'])} device(s) are online but reporting a fault.",
            "Review each alert in the Dashboard and resolve the condition.",
            buckets["alerting"]))
    return out


def check_device_naming(data):
    """Devices identified only by serial number."""
    devices = data.get("devices") or []
    unnamed = [d.get("serial") for d in devices if not (d.get("name") or "").strip()]
    if not unnamed:
        return []
    return [finding(
        "DOC-01", "Low",
        "Devices without an assigned name",
        f"{len(unnamed)} device(s) are identified only by serial number. During an "
        "incident this slows identification and raises the chance of changing the "
        "wrong device.",
        "Adopt a naming convention (site-role-number, e.g. SJO-SW-ACC-01) and apply "
        "it across the estate.",
        unnamed)]


CHECKS = [
    check_admin_2fa,
    check_open_ssids,
    check_device_status,
    check_device_naming,
]


def analyze(data):
    """Run every registered check and return findings sorted by severity."""
    out = []
    for check in CHECKS:
        try:
            out.extend(check(data) or [])
        except Exception as exc:                      # a broken check must not
            print(f"  check {check.__name__} failed: {exc}", file=sys.stderr)
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["id"]))
    return out


# ------------------------------------------------------------ output

SEV_COLOR = {
    "Critical": "#7f1d1d", "High": "#9a3412", "Medium": "#854d0e",
    "Low": "#1e40af", "Info": "#334155",
}


def esc(v):
    return (str(v).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def build_html(data, findings, title):
    """A plain HTML summary of the collected data and the findings."""
    meta = data["meta"]
    networks = data.get("networks") or []
    devices = data.get("devices") or []
    statuses = {s.get("serial"): s for s in (data.get("device_statuses") or [])}
    net_name = {n["id"]: n.get("name", n["id"]) for n in networks}
    counts = Counter(f["severity"] for f in findings)

    rows = ""
    for d in sorted(devices, key=lambda x: (x.get("networkId") or "", x.get("name") or "")):
        st = statuses.get(d.get("serial"), {})
        rows += (f"<tr><td>{esc(d.get('name') or '-')}</td>"
                 f"<td>{esc(d.get('model') or '-')}</td>"
                 f"<td>{esc(d.get('serial') or '-')}</td>"
                 f"<td>{esc(st.get('lanIp') or d.get('lanIp') or '-')}</td>"
                 f"<td>{esc(net_name.get(d.get('networkId'), '-'))}</td>"
                 f"<td>{esc(d.get('firmware') or '-')}</td>"
                 f"<td>{esc(st.get('status') or '-')}</td></tr>")

    items = ""
    for f in findings:
        aff = "".join(f"<li>{esc(a)}</li>" for a in f["affected"][:25])
        more = len(f["affected"]) - 25
        if more > 0:
            aff += f"<li>... and {more} more</li>"
        items += f"""
        <article>
          <h3><span style="color:{SEV_COLOR.get(f['severity'], '#334155')}">
            [{esc(f['severity'])}]</span> {esc(f['title'])}
            <small>{esc(f['id'])}</small></h3>
          <p>{esc(f['detail'])}</p>
          <p><strong>Recommendation:</strong> {esc(f['recommendation'])}</p>
          {f'<ul>{aff}</ul>' if aff else ''}
        </article>"""

    summary = " &middot; ".join(f"{counts[s]} {s.lower()}"
                               for s in ("Critical", "High", "Medium", "Low", "Info")
                               if counts[s])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Audit - {esc(title)}</title>
<style>
 body{{font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
   max-width:860px;margin:0 auto;padding:40px 24px;color:#1f2937}}
 h1{{font-size:26px;margin:0 0 4px}} h2{{font-size:18px;margin:36px 0 12px;
   border-bottom:2px solid #e5e7eb;padding-bottom:6px}}
 h3{{font-size:16px;margin:0 0 6px}} h3 small{{color:#9ca3af;font-weight:400}}
 article{{border:1px solid #e5e7eb;border-radius:6px;padding:16px;margin:12px 0}}
 article p{{margin:6px 0}} ul{{margin:6px 0;padding-left:22px;font-size:14px}}
 table{{width:100%;border-collapse:collapse;font-size:13.5px}}
 th{{text-align:left;background:#f9fafb;padding:8px;border-bottom:2px solid #e5e7eb}}
 td{{padding:7px 8px;border-bottom:1px solid #f3f4f6}}
 .meta{{color:#6b7280;font-size:14px}}
</style></head><body>
<h1>Network Audit</h1>
<p class="meta">{esc(title)} &middot; organization {esc(meta.get('org_name'))}<br>
Collected {esc(meta.get('collected_at'))} using {meta.get('api_calls', 0)} read-only API calls.</p>

<h2>Summary</h2>
<p>{len(networks)} network(s), {len(devices)} device(s),
<strong>{len(findings)} finding(s)</strong>{' &mdash; ' + summary if summary else ''}.</p>

<h2>Findings</h2>
{items or '<p>No findings were raised by the registered checks.</p>'}

<h2>Device inventory</h2>
<table><thead><tr><th>Name</th><th>Model</th><th>Serial</th><th>LAN IP</th>
<th>Network</th><th>Firmware</th><th>Status</th></tr></thead>
<tbody>{rows or '<tr><td colspan="7">No devices found</td></tr>'}</tbody></table>
</body></html>"""


def write_csv(data, path):
    statuses = {s.get("serial"): s for s in (data.get("device_statuses") or [])}
    net_name = {n["id"]: n.get("name", n["id"]) for n in (data.get("networks") or [])}
    cols = ["name", "model", "serial", "mac", "lanIp", "network",
            "firmware", "status", "address", "tags"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for d in data.get("devices") or []:
            st = statuses.get(d.get("serial"), {})
            w.writerow({
                "name": d.get("name") or "", "model": d.get("model") or "",
                "serial": d.get("serial") or "", "mac": d.get("mac") or "",
                "lanIp": st.get("lanIp") or d.get("lanIp") or "",
                "network": net_name.get(d.get("networkId"), ""),
                "firmware": d.get("firmware") or "",
                "status": st.get("status") or "",
                "address": d.get("address") or "",
                "tags": " ".join(d.get("tags") or []),
            })


# ----------------------------------------------------------------- demo data

def demo_data():
    """Sample dataset so the toolkit can be exercised without network access."""
    nets = [
        {"id": "N_1", "name": "HQ - San Jose", "productTypes": ["appliance", "switch", "wireless"]},
        {"id": "N_2", "name": "DC - Warehouse North", "productTypes": ["switch", "wireless"]},
        {"id": "N_3", "name": "Branch - Cartago", "productTypes": ["appliance", "wireless"]},
    ]
    devs, stats = [], []
    plan = [("N_1", "MS250-48", 4, "SJO-SW-ACC"), ("N_1", "MX84", 1, "SJO-FW"),
            ("N_1", "MR46", 8, "SJO-AP"), ("N_2", "MS425-16", 2, ""),
            ("N_2", "MR36", 12, "WHN-AP"), ("N_3", "MX67", 1, "CAR-FW"),
            ("N_3", "MR36", 4, "")]
    i = 0
    for nid, model, count, prefix in plan:
        for n in range(1, count + 1):
            i += 1
            serial = f"Q2XX-{1000+i}-ABCD"
            devs.append({
                "serial": serial, "model": model,
                "name": f"{prefix}-{n:02d}" if prefix else "",
                "networkId": nid, "firmware": "wireless-29-5-1",
                "mac": f"00:18:0a:{i:02x}:11:22",
                "address": "San Jose, CR" if nid == "N_1" else "",
                "tags": ["production"] if nid == "N_1" else [],
                "lanIp": f"10.{10 if nid=='N_1' else 20}.1.{i}",
            })
            status = "online"
            if i % 17 == 0:
                status = "offline"
            elif i % 23 == 0:
                status = "alerting"
            stats.append({"serial": serial, "status": status,
                          "lanIp": f"10.10.1.{i}"})

    return {
        "meta": {"org_id": "549236", "org_name": "DevNet Sandbox",
                 "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "api_calls": 0},
        "networks": nets, "devices": devs, "device_statuses": stats,
        "admins": [
            {"email": "ops@acme-msp.com", "orgAccess": "full", "twoFactorAuthEnabled": True},
            {"email": "jdoe@acme-msp.com", "orgAccess": "full", "twoFactorAuthEnabled": False},
            {"email": "contractor@gmail.com", "orgAccess": "full", "twoFactorAuthEnabled": False},
            {"email": "helpdesk@acme-msp.com", "orgAccess": "full", "twoFactorAuthEnabled": True},
            {"email": "audit@acme-msp.com", "orgAccess": "read-only", "twoFactorAuthEnabled": True},
        ],
        "licenses_overview": {"expirationDate": "2026-11-20T00:00:00Z", "status": "OK"},
        "ssids": {
            "N_1": [
                {"number": 0, "name": "ACME-Corp", "enabled": True,
                 "authMode": "8021x-radius", "encryptionMode": "wpa"},
                {"number": 1, "name": "ACME-Guest", "enabled": True,
                 "authMode": "open", "encryptionMode": "open", "splashPage": None},
            ],
            "N_2": [{"number": 0, "name": "WH-Scanners", "enabled": True,
                     "authMode": "psk", "encryptionMode": "wpa"}],
            "N_3": [{"number": 0, "name": "CAR-Staff", "enabled": True,
                     "authMode": "psk", "encryptionMode": "wpa2"}],
        },
        "syslog": {"N_1": [{"host": "10.10.5.20", "port": 514}], "N_2": [], "N_3": []},
        "alerts": {
            "N_1": {"defaultDestinations": {"emails": ["noc@acme-msp.com"]}},
            "N_2": {"defaultDestinations": {"emails": []}},
            "N_3": {"defaultDestinations": {"emails": []}},
        },
        "vlans": {}, "net_settings": {}, "uplink_statuses": [], "firmware": [],
        "config_changes": [
            {"adminName": "J. Doe", "ts": "2026-09-14"},
            {"adminName": "J. Doe", "ts": "2026-09-15"},
            {"adminName": "Helpdesk", "ts": "2026-09-19"},
        ],
        "api_requests": {},
    }


# ----------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Read-only Cisco Meraki network audit.")
    ap.add_argument("--key", help="Dashboard API key (read-only recommended)")
    ap.add_argument("--org", help="Organization ID")
    ap.add_argument("--out", default="./output", help="Output directory")
    ap.add_argument("--title", default="", help="Title shown on the report")
    ap.add_argument("--list-orgs", action="store_true",
                    help="List organizations the key can read, then exit")
    ap.add_argument("--demo", action="store_true",
                    help="Run offline against the bundled sample data")
    args = ap.parse_args()

    key = args.key or os.environ.get("MERAKI_API_KEY")

    if args.demo:
        data = demo_data()
        title = args.title or "Sample Organization"
    else:
        if not key:
            sys.exit("Provide --key or set MERAKI_API_KEY. Use --demo to try it offline.")
        client = MerakiClient(key)
        orgs = client.get("/organizations")
        if not orgs:
            sys.exit("Could not read organizations. Check the key and network access.")

        if args.list_orgs:
            print(f"{'ORG ID':<24} NAME")
            for o in orgs:
                print(f"{o.get('id',''):<24} {o.get('name','')}")
            return

        org_id = args.org
        if not org_id:
            if len(orgs) == 1:
                org_id = orgs[0]["id"]
            else:
                print("Select an organization:")
                for i, o in enumerate(orgs):
                    print(f"  [{i}] {o.get('name')}  ({o.get('id')})")
                org_id = orgs[int(input("Number: ").strip())]["id"]

        org_name = next((o.get("name") for o in orgs
                         if str(o.get("id")) == str(org_id)), org_id)
        print(f"[audit] organization: {org_name} ({org_id})", file=sys.stderr)
        data = collect(client, org_id, org_name)
        title = args.title or org_name

    findings = analyze(data)

    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d")
    slug = "".join(c if c.isalnum() else "_" for c in title)[:40]

    html_path = os.path.join(args.out, f"{slug}_audit_{stamp}.html")
    csv_path = os.path.join(args.out, f"{slug}_inventory_{stamp}.csv")
    json_path = os.path.join(args.out, f"{slug}_raw_{stamp}.json")

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(build_html(data, findings, title))
    write_csv(data, csv_path)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"data": data, "findings": findings}, fh, indent=2, default=str)

    sev = Counter(f["severity"] for f in findings)
    print("\n" + "=" * 58)
    print(f"  Audit complete - {title}")
    print("=" * 58)
    print(f"  Networks : {len(data.get('networks') or [])}")
    print(f"  Devices  : {len(data.get('devices') or [])}")
    print(f"  Findings : {len(findings)}  " +
          "  ".join(f"{k}:{sev[k]}" for k in
                    ("Critical", "High", "Medium", "Low", "Info") if sev[k]))
    print("-" * 58)
    print(f"  Report   : {html_path}")
    print(f"  Inventory: {csv_path}")
    print(f"  Raw data : {json_path}")
    print("=" * 58 + "\n")


if __name__ == "__main__":
    main()
