# MSAT - Magento Security Assessment Tool

**v1.0** · by [@Jakka351](https://github.com/Jakka351) · [Tester Present](https://testerpresent.com.au)

---

A no-nonsense Tkinter GUI tool for poking at Magento Open Source (Community Edition) installs. Built for security researchers doing authorised pentesting and responsible disclosure work.

Not a point-and-click exploit framework. Not a skiddie tool. This is a recon and assessment utility that does the boring-but-necessary groundwork of figuring out what a Magento target is exposing before you even think about writing a PoC.

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

---

## What it actually does

10 scan phases, threaded where it makes sense, all results exportable:

1. **Version fingerprinting** — hits `/magento_version`, parses response headers, cookies, HTML indicators, `composer.json`, `deployed_version.txt`, REST store config. Tries to work out if you're looking at M1 or M2 and what version.

2. **Security header check** — looks for the usual suspects (HSTS, CSP, X-Frame-Options, etc). Flags anything missing or misconfigured.

3. **Path discovery** — multi-threaded scan of 50+ Magento-specific paths. Config files, log files, debug endpoints, API routes, setup wizards, the works. Flags high-severity stuff like exposed `env.php`, `.git/HEAD`, `local.xml`.

4. **Admin panel discovery** — brute-forces common admin paths (`/admin`, `/backend`, `/admin123`, etc). Checks for CAPTCHA on the login form. Cross-references `robots.txt` for admin path disclosure.

5. **API security** — tests 11 REST API endpoints for unauthenticated access. Products, customers, orders, modules list — the stuff that shouldn't be hanging out in the open. Also tests GraphQL: basic queries, introspection (if that's on in prod you've got problems), and sensitive type enumeration.

6. **SSL/TLS** — protocol version, cipher strength, cert validity. Flags deprecated TLS and weak ciphers.

7. **CVE assessment** — 11 curated Magento CVEs from 2019-2024 including CosmicSting (CVE-2024-34102), the checkout template injection RCEs, SQLi via Elasticsearch, Phar deserialization, etc. Version-based matching flags candidates for manual verification. Endpoint-based checks confirm where possible.

8. **Configuration audit** — directory listing, debug files (`phpinfo.php`, `adminer.php`), `.git` and `.env` exposure, setup/update wizard access, CORS misconfiguration.

9. **Recommendations** — auto-generated based on findings. Nothing groundbreaking, just the practical stuff that actually needs doing.

10. **Report generation** — structured text report across all findings with severity ratings.

## Requirements

Python 3.8+ and `requests`. That's it.

```bash
pip install requests
```

Tkinter ships with Python on most systems. If you're on a minimal Linux install and it's missing:

```bash
# Debian/Ubuntu
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter
```

## Usage

```bash
python3 magento_pentester.py
```

Or on Windows just double-click it, whatever works.

Enter the target URL, tick the modules you want to run, hit **Start Scan** (or F5). The console tab shows real-time output, findings tab gives you a sortable table, report tab has the full text report.

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `F5` | Start scan |
| `Esc` | Stop scan |
| `Ctrl+J` | Export JSON |
| `Ctrl+R` | Export report |

### Export formats

- **JSON** — full results object, good for piping into other tools or diffing between scans
- **CSV** — findings table, opens in Excel/Sheets if management needs a spreadsheet
- **Text** — the report tab content, ready to paste into a disclosure or attach to a ticket

## GUI layout

Left panel has your scan module toggles and a target info readout that populates as the scan runs. Right side is tabbed:

- **Console Output** — timestamped log with colour-coded severity (dark background, easy on the eyes during long scans)
- **Findings** — treeview table with severity counts along the top
- **CVE Reference** — the full CVE database with a detail pane, useful even without running a scan
- **Report** — formatted assessment report

Deliberately built with stock Tkinter widgets. Looks like engineering software because it is engineering software. No electron, no web UI, no npm install with 400 dependencies. Just runs.

## CVE database

Curated list, not exhaustive. These are the ones that matter:

| CVE | CVSS | What |
|-----|------|------|
| CVE-2024-34102 | 9.8 | CosmicSting — XXE to RCE, unauthenticated |
| CVE-2024-20720 | 9.1 | OS command injection via layout XML |
| CVE-2022-24086 | 9.8 | Template injection RCE at checkout |
| CVE-2022-24087 | 9.8 | Template injection RCE in email templates |
| CVE-2021-21024 | 9.1 | Blind SQLi in catalog |
| CVE-2019-7139 | 9.8 | SQLi via Elasticsearch |
| CVE-2019-7932 | 9.0 | Phar deserialization RCE |

Plus a few more HIGH-severity ones (IDOR account takeover, GraphQL rate limiting bypass, path traversal, info disclosure). See the CVE Reference tab in the app for the full list.

## Some things worth noting

- The tool does **not** attempt exploitation. It's passive recon and configuration checking. No payloads, no injection attempts, no brute-forcing credentials.

- Path scanning uses HEAD requests first and falls back to GET only when needed. Tries to be a polite scanner.

- SSL verification is disabled for the scanner session (otherwise you can't test targets with self-signed certs). This is intentional.

- CVE matching against detected versions flags candidates for **manual verification**. Version detection isn't always precise enough to confirm a specific patch level, so treat these as "worth investigating" not "confirmed vulnerable".

- The GraphQL introspection check is a good litmus test. If introspection is enabled in production, there's almost certainly other stuff misconfigured too.

## Legal

**Only use this against systems you own or have explicit written permission to test.**

The tool asks you to confirm authorisation before every scan. This isn't just a formality — if you're running this against someone else's infrastructure without permission, that's on you, not on us.

Built for legitimate security research, authorised penetration testing, and responsible vulnerability disclosure. If you find something, report it properly.

## About

Built by [@Jakka351](https://github.com/Jakka351) at [Tester Present — Specialist Automotive Solutions](https://testerpresent.com.au), Carnegie VIC.

Yeah, the name is an automotive diagnostics reference. `$3E` — Tester Present — the UDS keep-alive service. We do ECU diagnostics, J2534 PassThru, CAN bus, and reverse engineering. Sometimes that skillset crosses over into web application security work, and here we are.

If you've got questions, found a bug, or want to contribute — open an issue or PR.

---

*testerpresent.com.au*
