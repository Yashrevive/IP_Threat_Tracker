# ip_threat_tracker

A command-line tool that checks IP addresses (or domains) against multiple threat intelligence sources and classifies them as **Safe**, **Suspicious**, or **Malicious** — with color-coded terminal output and bulk CSV scanning support.

```
 _____________          ___    __                              __    __                     __             
/_  __/  _/ _ \\        / _ \\  / /_  ____ ___  ____ ___/ /_  / /_______ _______/ /_____ ____
 / /  / // ___/       /_  __/ / __/ / __/  _ \\/ __// _  __/ / __/ __/ __/ __/  '_/ -_) __/
/_/  /___/_/            /_/   \\__/  \\___/  \\__/_/  \\__/_/\\__/  \\__/_/  \\__/\\__/_/\\_\\\\__/_/   
```

## Demo

**Single lookup**

![Single lookup demo](assets/demo_single_lookup.gif)

**Bulk scan**

![Bulk scan demo](assets/demo_bulk_scan.gif)

## What it does

Give it an IP address, a domain, or a CSV file of targets, and it will:

1. Classify the address (Loopback, Link-local, Multicast, Private, Reserved, or Public)
2. Pull geolocation and ISP/ASN info for public addresses
3. Check VirusTotal for malicious detection reports
4. Check AbuseIPDB for abuse confidence score, total reports, and last reported date
5. Render a final verdict — **Safe**, **Suspicious**, or **Malicious** — based on configurable thresholds

Single lookups print straight to the terminal in color. Bulk scans read a CSV of targets and write a structured CSV report, while still streaming color-coded progress to the terminal as each entry is processed.

## Example: single IP lookup

```
$ python ip_tracker.py -ip 185.220.101.1 -days 90

IP: 185.220.101.1
Location: Brandenburg an der Havel,Brandenburg,Germany,14621
Internet service Provider: Stiftung Erneuerbare Freiheit
Autonomous System: AS60729 Stiftung Erneuerbare Freiheit
Total malicious reports = 14
Abuse Score = 100/100
Total number of reports = 225
last reported date = 2026-08-15
Safety Status: Malicious
```

Output is printed in green for Safe, yellow for Suspicious, and bright red for Malicious.

## Example: domain lookup

```
$ python ip_tracker.py -domain bing.com -days 90

IP: 150.171.28.10
Location: Teterboro,New Jersey,United States,07608
Internet service Provider: Microsoft Corporation
Autonomous System: AS8075 Microsoft Corporation
Total malicious reports = 0
Abuse Score = 21/100
Total number of reports = 48
last reported date = 2026-08-14
Safety Status: Safe
```

Domains are resolved to an IP via DNS before being scanned, so all the same threat-intel checks apply.

## Example: bulk CSV scan

```
$ python ip_tracker.py -ifile sample.csv -ofile output.csv -days 90

Starting Bulk Scan
Retriving info about 127.0.0.1
127.0.0.1 is Loopback
...
Retriving info about 185.220.101.5
185.220.101.5 is Malicious
Retriving info about google.com
google.com is Safe
Retriving info about not_a_real_ip
not_a_real_ip is Invalid
Bulk Scan Completed
```

Every line is classified and color-coded live in the terminal (green/yellow/red), and the full structured record is written to the output CSV — including reserved/private/loopback ranges, resolved domains, and invalid entries — without needing a live API call for anything that isn't a public, routable address.

### Sample output.csv columns

| Column | Description |
|---|---|
| Serial No. | Row index |
| Input | Original IP or domain from the input file |
| Status | Loopback / Link-local / Multicast / Private / Reserved / Public / Invalid |
| city, region, country, zip | Geolocation (public IPs only) |
| Internet Service Provider | ISP name |
| Autonomous System | ASN + org name |
| Malicious Reports | VirusTotal detection count |
| Abuse Score | AbuseIPDB confidence score (0–100) |
| Safety Status | Safe / Suspicious / Malicious |
| Total Reports | Total AbuseIPDB reports in the lookback window |
| Last Reported | Date of most recent AbuseIPDB report |
| Error | Populated for unreachable APIs or invalid input |

## Usage

```
python ip_tracker.py -ip <ip_address> [-days N]
python ip_tracker.py -domain <domain_name> [-days N]
python ip_tracker.py -ifile <input.csv> -ofile <output.csv> [-days N]
```

| Flag | Description |
|---|---|
| `-ip` | Single IP address to check |
| `-domain` | Single domain to resolve and check |
| `-ifile` | Input CSV of targets for a bulk scan (expects an `Input` column) |
| `-ofile` | Output CSV path for bulk scan results |
| `-days` | Lookback window (in days) for AbuseIPDB report history — default 30 |

## How classification works

Non-public ranges (loopback, link-local, multicast, private, reserved/CGNAT) are detected locally via Python's `ipaddress` module — no API calls wasted on addresses that can't have a public reputation.

Public addresses are scored against two independent thresholds (`threshold.py`):

- **AbuseIPDB score:** ≤30 Safe · 31–69 Suspicious · ≥70 Malicious
- **VirusTotal malicious detections:** ≤3 Safe · 4–7 Suspicious · ≥7 Malicious

The stricter of the two verdicts wins — a high score on *either* source is enough to flag an address as Malicious.

## Architecture

```
ip_tracker.py      CLI entry point, argument parsing, single-scan and bulk-scan orchestration
validators.py       IP/domain validation, IP-range classification, verdict logic
api_clients.py      ip-api.com, AbuseIPDB, and VirusTotal integrations
threshold.py        Configurable safety thresholds for Abuse Score and VT detections
logger.py           Structured logging to log.txt (INFO for normal, WARNING for malicious)
```

## Data sources

- **[ip-api.com](https://ip-api.com)** — geolocation, ISP, ASN
- **[AbuseIPDB](https://www.abuseipdb.com)** — abuse confidence score, report history
- **[VirusTotal](https://www.virustotal.com)** — malicious detection count

## Setup

```
pip install -r requirements.txt
```

Create a `.env` file with your API keys:

```
my_abuseipdb_key=your_abuseipdb_key_here
vt_api_key=your_virustotal_key_here
```

## Roadmap (V4)

- Auto-alert/reporting based on scan results
- Live color-coded progress indicator during bulk scans, decoupled from CSV output (no ANSI codes leaking into CSV cells)
- Opt-in VirusTotal for bulk mode via a `--vt` flag, with client-side rate-limit throttling (free tier: 4 req/min, 500/day) and a caching layer built on a SQLite history store
- SQLite-backed scan history: if an IP was already checked recently, serve the cached result instead of re-hitting the APIs, saving quota on repeat lookups