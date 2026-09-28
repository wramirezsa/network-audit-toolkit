# Meraki Network Audit Toolkit

A read-only collection layer and check framework for Cisco Meraki
organizations, built directly on the Dashboard API.

Point it at an organization with a read-only key and it will tell you what is
actually out there: every network, every device, what software they are running,
which ones are unreachable, how the wireless is configured, and who can log in
to change it.

**Every call is a `GET`. There is no code path in this repository that writes to
the Dashboard.**

---

## Why this exists

Inheriting a network nobody documented is a common problem and a slow one to
solve by hand. This is the part that should not be manual: the collection, the
pagination, the rate limiting, and a first pass of checks over the result.

What it produces is a starting point — an inventory you can hand to someone, and
a short list of things worth looking at.

---

## Install

```bash
git clone https://github.com/wramirezsa/network-audit-toolkit.git
cd network-audit-toolkit
pip install -r requirements.txt
```

Python 3.8+. One dependency: `requests`.

---

## Run it

**Offline, against the bundled sample data:**

```bash
python3 meraki_audit.py --demo
```

**Against Cisco's public sandbox** — they publish a read-only demo key:

```bash
python3 meraki_audit.py --list-orgs --key 6bec40cf957de430a6f1f2baa056b99a4fac9ea0
python3 meraki_audit.py --key 6bec40cf957de430a6f1f2baa056b99a4fac9ea0 --org <ORG_ID>
```

**Against a real organization:**

```bash
export MERAKI_API_KEY="your-read-only-key"
python3 meraki_audit.py --title "Client Name"
```

Generate the key under **Organization → Settings → Dashboard API access**, on an
account with **read-only** organization access.

---

## What it collects

Networks, devices and their live status, administrators, licensing, appliance
uplinks, firmware schedules, configuration change history, and per-network SSIDs,
VLANs, syslog servers and alert settings.

The client handles the parts that usually break a first attempt:

- **Rate limiting** — on HTTP 429 it waits the interval the API asks for and retries
- **Cursor pagination** — followed automatically wherever the API returns a `Link` header
- **Partial availability** — endpoints that do not apply to a network return `None` and are skipped rather than aborting the run
- **Transient failures** — five attempts with exponential backoff

---

## The checks

Four are included, covering what most estates fail on first:

| ID | Severity | Check |
|---|---|---|
| `IAM-01` | High | Administrators without two-factor authentication |
| `WLAN-01` | Critical | SSIDs broadcasting without encryption |
| `OPS-01/02` | High / Medium | Devices offline or in an alerting state |
| `DOC-01` | Low | Devices identified only by serial number |

### Adding your own

A check is a function that takes the collected data and returns findings:

```python
def check_firmware_drift(data):
    versions = {d.get("firmware") for d in data.get("devices") or []}
    if len(versions) <= 1:
        return []
    return [finding(
        "FW-01", "Medium",
        "Inconsistent firmware across the estate",
        f"{len(versions)} distinct firmware versions are in use.",
        "Align devices onto a common release before the next maintenance window.",
        sorted(v for v in versions if v))]

CHECKS.append(check_firmware_drift)
```

A check that raises is reported and skipped; one bad check will not take down
the run.

---

## Output

| File | Contents |
|---|---|
| `<title>_audit_<date>.html` | Summary, findings and full device inventory |
| `<title>_inventory_<date>.csv` | The inventory on its own, for spreadsheets |
| `<title>_raw_<date>.json` | Everything collected, plus the findings |

Examples of the first two are in [`examples/`](examples/).

---

## Options

```
--key KEY        Dashboard API key (or set MERAKI_API_KEY)
--org ID         Organization ID; prompts if omitted and several exist
--title NAME     Title printed on the report
--out DIR        Output directory (default ./output)
--list-orgs      List organizations the key can read, then exit
--demo           Run offline against the bundled sample data
```

---

## Licence

MIT. Use it, change it, ship it.

---

## Author

Wilson Ramírez — network engineer, Costa Rica.
CCNP Enterprise · ENCOR · Enterprise Wireless Implementation.
