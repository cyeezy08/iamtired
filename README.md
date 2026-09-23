# CVE-2026-87899 — cPanel/WHM CalDAV & CardDAV Root RCE
### Externally-observable exposure report + detection

> **Credit:** CVE-2026-87899, CVE-2026-87900 and CVE-2026-68490 were found and responsibly
> disclosed by **Ali Mustafa (`rz1027`)** and published by **cPanel/WebPros** on **2026-09-22**.
> This document is an **independent exposure measurement** built from LEVIATHAN X scan data.
> It contains a **detection** method only — **no exploit code.**

---

## 1. The vulnerability (per cPanel's advisory)

| CVE | Component | Impact | Affected | Fixed in |
|---|---|---|---|---|
| **CVE-2026-87899** | CalDAV & CardDAV | A logged-in cPanel account holder can **execute code as root** → full server control | cPanel & WHM **v120+** | `11.134.0.57+`, `11.136.0.41+`, `11.138.0.8+`, WP Squared `11.138.1.11+` |
| **CVE-2026-87900** | WP Toolkit | A logged-in cPanel user can modify **databases in other accounts** | WP Toolkit ≤ `6.11.2-10794` | WP Toolkit `6.11.3+` |
| **CVE-2026-68490** | CalDAV & CardDAV | A local user can **read** other accounts' calendar events/contacts | cPanel & WHM **v120+** | same as 87899 |

- **Preconditions:** an account on the server (87899/87900). On shared hosting, that's any customer — or anyone who obtains a customer login.
- **KEV status:** not in CISA KEV (checked 2026-09-23), **no public exploitation reported at time of writing**.
- **Vendor workaround:** none offered; the only fix is upgrading.

**Update:**
```bash
/usr/local/cpanel/scripts/upcp --force             # cPanel & WHM (WHM → Home/cPanel/Upgrade to Latest Version)
bash <(curl https://wp-toolkit.plesk.com/cPanel/installer.sh) --version 6.11.3   # WP Toolkit
```

---

## 2. Externally-observable exposure (LEVIATHAN X fleet, 2026-09-24)

> Presence of a cPanel/WHM service is a **necessary** condition, not proof of a vulnerable
> version. Not every exposed control panel has an account attacker can reach, and most do not
> advertise a version. Treat this as **attack-surface size**, not a confirmed-vulnerable count.

| Query | Hosts |
|---|---|
| `app:cpanel` (fingerprinted cPanel/WHM) | **1,009** |
| `port:2087` (WHM) | **604** (391 non-decoy) |
| `port:2086` (WHM HTTP) | 181 |
| `port:2083` (cPanel SSL) | 1,089 |
| `port:2082` (cPanel HTTP) | 6,514 |

**Version-revealing hosts:** 20 hosts advertise a `Server: cpsrvd/X.Y.Z` banner. Of those, **6
advertise a version in the affected v120+ range and below the fix**:

| Version | Hosts | Status |
|---|---|---|
| `11.120.0.19` | 4 | **Affected** (< `11.134.0.57`) |
| `11.128.0.15` | 2 | **Affected** (< `11.134.0.57`) |
| `11.118.0.61`, `11.106.0.18`, `11.102.0.31`, `11.100.0.27`, `11.92.0.33`, `11.54.0.18`, `11.34.2.8`, `11.30.8.0` | 13 | Below v120 → not in scope for 87899 |

**Takeaway:** the *version-exposed* surface is small (most panels hide their build), but the
*reachable* cPanel/WHM surface is ~1,000–6,500 hosts depending on port. Patch status is largely
invisible from the outside — ownership-side action (run `upcp`) is the only reliable fix.

---

## 3. Detection (defensive)

Version-based, fingerprint only — reads the response header, sends no malicious request.

For Leviathan X 
```
app:cpanel port:2087
app:cpanel port:2083
```

Nuclei-style template: see `cpanel-cve-2026-87899-detect.yaml` in this directory.

Raw check:
```bash
curl -sI https://HOST:2087/ | grep -i '^server:'      # look for cpsrvd/X.Y.Z
# affected if version >= 11.120 and < the fix for its release line
```

---

## 5. Sources
- The Hacker News, 2026-09-23 — "New cPanel Flaw Lets a Hosting Account Run Code as Root"
- cPanel advisories (support.cpanel.net): CVE-2026-87899, CVE-2026-87900, CVE-2026-68490
- LEVIATHAN X fleet (`api.leviathan.ac`), measured 2026-09-24
