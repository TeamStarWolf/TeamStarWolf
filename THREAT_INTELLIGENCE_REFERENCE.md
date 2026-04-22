# Threat Intelligence Reference

> **TLP:CLEAR** — This reference document is intended for cybersecurity professionals. All content is educational and sourced from public domain research.

A comprehensive operational reference for threat intelligence analysts, SOC teams, and security researchers covering the full intelligence lifecycle, frameworks, actor taxonomy, IOC management, platforms, sources, enrichment workflows, and intelligence-driven detection.

---

## Table of Contents

1. [Intelligence Lifecycle](#intelligence-lifecycle)
2. [Intelligence Frameworks & Models](#intelligence-frameworks--models)
3. [Threat Actor Taxonomy](#threat-actor-taxonomy)
4. [IOC Types & Management](#ioc-types--management)
5. [Threat Intelligence Platforms (TIPs)](#threat-intelligence-platforms-tips)
6. [Intelligence Sources](#intelligence-sources)
7. [IOC Enrichment Workflows](#ioc-enrichment-workflows)
8. [Threat Intelligence Reporting](#threat-intelligence-reporting)
9. [Intelligence-Driven Detection](#intelligence-driven-detection)
10. [NIST & ATT&CK Mappings](#nist--attck-mappings)

---

## Intelligence Lifecycle

### Classic 6-Phase Intelligence Cycle

| Phase | Description | Key Activities |
|---|---|---|
| **Planning & Direction** | Define what intelligence is needed and why | Identify PIRs, assign collection tasks, set timelines |
| **Collection** | Gather raw data from all sources | OSINT, HUMINT, SIGINT, technical feeds, dark web monitoring |
| **Processing** | Convert raw data into usable format | Normalization, translation, decryption, deduplication |
| **Analysis** | Transform processed data into intelligence | Pattern recognition, TTP mapping, actor attribution, confidence scoring |
| **Dissemination** | Deliver finished intelligence to consumers | Reports, TIP updates, SIEM rule pushes, briefings |
| **Feedback** | Evaluate effectiveness and refine | Consumer feedback loop, gap analysis, PIR adjustment |

### F3EAD Cycle

Originally a military targeting methodology, F3EAD has been adopted by SOC teams for iterative threat tracking:

| Phase | Description | SOC Application |
|---|---|---|
| **Find** | Locate the threat | Hunt queries, IOC matching, anomaly detection |
| **Fix** | Confirm and characterize | Validate IOCs, map to actor/campaign |
| **Finish** | Neutralize the threat | Block IOCs, isolate hosts, remediate |
| **Exploit** | Extract intelligence | Collect artifacts, malware samples, C2 details |
| **Analyze** | Derive actionable intel | TTP mapping, attribution, campaign tracking |
| **Disseminate** | Share findings | Internal reports, ISAC sharing, TIP updates |

### Intelligence Requirements

- **Priority Intelligence Requirements (PIRs)**: The most critical questions leadership needs answered. Example: "Are our cloud tenants being targeted by financially motivated actors?"
- **Intelligence Requirements (IRs)**: Broader collection requirements supporting PIRs. Can be answered by multiple sources.
- **Standing Information Needs (SINs)**: Continuous monitoring requirements that do not expire. Example: "Monitor all mentions of company domain on paste sites."

### Intel Production Types

| Type | Audience | Time Horizon | Examples |
|---|---|---|---|
| **Strategic** | C-suite, Board, CISO | 6-18 months | Threat landscape reports, sector risk summaries |
| **Operational** | Security managers, IR leads | Weeks-months | Campaign tracking, actor activity reports |
| **Tactical** | SOC analysts, threat hunters | Real-time to days | IOC feeds, YARA/Sigma rules, flash alerts |

---

## Intelligence Frameworks & Models

### Diamond Model of Intrusion Analysis

Developed by Sergio Caltagirone, Andrew Pendergast, and Christopher Betz (2013). Every intrusion event has four core features connected in a diamond shape:

```
         Adversary
            /\
           /  \
          /    \
Infrastructure--Capability
          \    /
           \  /
            \/
          Victim
```

**Core Features:**
- **Adversary**: The threat actor or group conducting the intrusion
- **Capability**: Malware, exploits, tools used by the adversary
- **Infrastructure**: Domains, IPs, servers, bulletproof hosting used
- **Victim**: Target organization, person, asset, or data

**Meta-Features** (extend analytical power):
- **Timestamp**: When the event occurred
- **Phase**: Kill chain phase
- **Result**: Success/failure/unknown
- **Direction**: Adversary-to-victim or victim-to-adversary
- **Methodology**: Attack category (spearphishing, exploit, brute force)
- **Resources**: Software, knowledge, information, hardware, funds, facilities

**Activity Threads and Groups**: Multiple Diamond events can be linked into activity threads (single intrusion) and activity groups (multiple intrusions by same actor), enabling campaign attribution.

---

### Kill Chain (Lockheed Martin)

The Cyber Kill Chain identifies 7 phases of a targeted attack and maps defensive actions at each phase:

| Phase | Description | Detect | Deny | Disrupt | Degrade | Deceive | Destroy |
|---|---|---|---|---|---|---|---|
| **Reconnaissance** | Research targets (OSINT, scanning) | Web analytics, firewall logs | Firewall rules | — | — | DNS sinkholes | — |
| **Weaponization** | Create exploit + payload | Malware analysis | DMARC/SPF | — | — | — | — |
| **Delivery** | Transmit weapon to target | AV alerts, email gateway | Email filtering | — | — | Honeypot links | — |
| **Exploitation** | Trigger exploit on target system | HIDS/EDR alerts | Patch management | DEP/ASLR | — | — | — |
| **Installation** | Install persistent implant | EDR, file integrity | AppLocker | — | — | — | — |
| **C2** | Beacon to C2 channel | DNS monitoring, proxy logs | Firewall egress | IPS | Rate limit | DNS sinkholes | Takedown |
| **Actions on Objectives** | Achieve goal (exfil, ransomware) | DLP, SIEM correlation | Least privilege | — | — | Deception assets | — |

**Key insight**: The earlier in the kill chain you detect and deny, the lower the cost and impact.

---

### ATT&CK for CTI

MITRE ATT&CK is the de facto standard for describing adversary behavior in cyber threat intelligence.

**Mapping Actor TTPs to ATT&CK Navigator Layers:**

1. Identify actor from reliable source (Mandiant, CrowdStrike, MITRE ATT&CK Groups page)
2. Extract TTPs from reporting — map each behavior to ATT&CK technique/sub-technique
3. Export as Navigator layer JSON for visualization and detection gap analysis

**Key ATT&CK Group Pages:**
- **APT28 (G0007)**: `https://attack.mitre.org/groups/G0007/`
- **APT29 (G0016)**: `https://attack.mitre.org/groups/G0016/`
- **Lazarus Group (G0032)**: `https://attack.mitre.org/groups/G0032/`
- **Sandworm (G0034)**: `https://attack.mitre.org/groups/G0034/`
- **FIN7 (G0046)**: `https://attack.mitre.org/groups/G0046/`
- **Scattered Spider (G1015)**: `https://attack.mitre.org/groups/G1015/`

**ATT&CK Navigator Layer JSON Structure:**

```json
{
  "name": "APT28 TTPs",
  "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
  "domain": "enterprise-attack",
  "description": "ATT&CK techniques attributed to APT28",
  "techniques": [
    {
      "techniqueID": "T1566.001",
      "tactic": "initial-access",
      "color": "#ff6666",
      "comment": "Spearphishing with malicious attachment",
      "score": 1
    },
    {
      "techniqueID": "T1078",
      "tactic": "defense-evasion",
      "color": "#ff6666",
      "comment": "Valid accounts via credential theft"
    }
  ],
  "gradient": {"colors": ["#ff6666","#ffe766","#8ec843"], "minValue": 0, "maxValue": 100}
}
```

---

### STIX 2.1

Structured Threat Information eXpression (STIX) 2.1 is the standard JSON-based language for CTI sharing.

**STIX Domain Objects (SDOs):**

| SDO | Description |
|---|---|
| `threat-actor` | Individual, group, or organization conducting malicious activity |
| `intrusion-set` | Grouped adversary behaviors and resources with common properties |
| `campaign` | Grouping of adversary behaviors over a time period with shared intent |
| `malware` | Malicious code — RAT, ransomware, dropper, backdoor |
| `tool` | Legitimate software used for malicious purposes |
| `attack-pattern` | ATT&CK technique or other adversary TTP |
| `indicator` | Pattern that detects adversary activity (IOCs) |
| `observed-data` | Raw data observed on a system or network |
| `report` | Collection of CTI objects grouped as a finished intelligence product |
| `course-of-action` | Recommended mitigation or detection action |
| `identity` | Individual, organization, or system |
| `location` | Geographic location |
| `vulnerability` | CVE or other software vulnerability |
| `note` | Contextual commentary on other objects |
| `opinion` | Assessment of the correctness of information |

**STIX Relationship Objects (SROs):** `relationship`, `sighting`

**STIX Cyber Observable Objects (SCOs):** `ipv4-addr`, `domain-name`, `url`, `file`, `process`, `network-traffic`, `email-message`, `windows-registry-key`, `user-account`, `x509-certificate`

**Example STIX 2.1 Threat Actor:**

```json
{
  "type": "threat-actor",
  "spec_version": "2.1",
  "id": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
  "created": "2024-01-15T00:00:00.000Z",
  "modified": "2024-01-15T00:00:00.000Z",
  "name": "APT28",
  "description": "Russian GRU-affiliated threat actor targeting government, military, and political organizations.",
  "threat_actor_types": ["nation-state"],
  "aliases": ["Fancy Bear", "STRONTIUM", "Forest Blizzard", "Sofacy"],
  "first_seen": "2007-01-01T00:00:00.000Z",
  "goals": ["espionage", "credential-theft", "influence-operations"],
  "sophistication": "advanced",
  "resource_level": "government",
  "primary_motivation": "organizational-gain",
  "labels": ["apt"]
}
```

**Example STIX 2.1 Indicator:**

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98129fd0e28b",
  "created": "2024-04-01T12:00:00.000Z",
  "modified": "2024-04-01T12:00:00.000Z",
  "name": "APT28 C2 Domain",
  "description": "C2 domain associated with APT28 Zebrocy campaigns",
  "pattern": "[domain-name:value = 'update-microsoft-cdn.com']",
  "pattern_type": "stix",
  "valid_from": "2024-04-01T00:00:00.000Z",
  "indicator_types": ["malicious-activity"],
  "confidence": 85,
  "labels": ["apt28", "c2", "zebrocy"]
}
```

**Example STIX 2.1 Relationship:**

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--44298a74-ba52-4f0c-87d3-1f8a6de4b50f",
  "created": "2024-04-01T12:00:00.000Z",
  "modified": "2024-04-01T12:00:00.000Z",
  "relationship_type": "indicates",
  "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98129fd0e28b",
  "target_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500"
}
```

---

### TAXII 2.1

Trusted Automated eXchange of Intelligence Information (TAXII) 2.1 defines the API for transporting STIX objects.

**Key TAXII Concepts:**
- **Server**: Hosts one or more API roots
- **API Root**: A URL grouping related TAXII resources
- **Collection**: A named bucket of STIX objects
- **Channel**: Push mechanism (not widely implemented)

**TAXII 2.1 Endpoints:**

```bash
# Server discovery
curl -H "Accept: application/taxii+json;version=2.1" \
     -u user:password \
     https://taxii.example.com/taxii2/

# List API roots -> collections
curl -H "Accept: application/taxii+json;version=2.1" \
     -u user:password \
     https://taxii.example.com/api/v21/collections/

# Pull objects from a collection
curl -H "Accept: application/stix+json;version=2.1" \
     -u user:password \
     "https://taxii.example.com/api/v21/collections/COLLECTION_ID/objects/?added_after=2024-01-01T00:00:00Z"

# CISA AIS TAXII 2.1 (requires enrollment)
curl -H "Accept: application/stix+json;version=2.1" \
     --cert client.crt --key client.key \
     https://ais2.cisa.dhs.gov/taxii2/
```

---

## Threat Actor Taxonomy

### Naming Conventions by Vendor

| Vendor | Convention | Examples |
|---|---|---|
| **Mandiant** | APT## (nation-state) / FIN## (financial) / UNC#### (uncategorized) | APT28, FIN7, UNC2452 |
| **CrowdStrike** | [Animal] [Country-associated adjective] | Fancy Bear (Russia), Lazarus (DPRK) — Bear=Russia, Panda=China, Chollima=DPRK, Kitten=Iran, Spider=eCrime |
| **Microsoft** | [Country]-[Weather] (post-2023) | Forest Blizzard (APT28), Midnight Blizzard (APT29), Sapphire Sleet (Lazarus) |
| **Secureworks** | IRON/GOLD/BRONZE/NICKEL/COBALT [Name] | IRON TWILIGHT (APT28) |
| **MITRE ATT&CK** | G#### with common name | G0007 (APT28) |

### Motivation Categories

| Motivation | Description | Typical Actors |
|---|---|---|
| **Espionage** | Steal government, military, or corporate secrets | Nation-state APTs (China, Russia, DPRK, Iran) |
| **Financial** | Monetize access (ransomware, BEC, card theft) | FIN7, Lazarus, ransomware gangs |
| **Destructive/Sabotage** | Disrupt or destroy critical infrastructure | Sandworm, APT33 (SHAMOON) |
| **Hacktivism** | Political or ideological motivation | Anonymous, KillNet, IT Army of Ukraine |
| **Supply Chain** | Compromise software/hardware supply chains | APT41, UNC2452 (SolarWinds) |

### Actor Profiling Template

```
Actor Name: [Primary name]
Aliases: [Vendor-specific names]
Sponsor: [Attributed nation/criminal org]
Motivation: [espionage | financial | destructive | hacktivist]
First Observed: [YYYY]
Confidence Level: [High | Medium | Low]
Last Active: [YYYY-MM]
Targeted Sectors: [Government, Defense, Energy, Finance, Healthcare, etc.]
Targeted Geographies: [Regions/countries]
Observed TTPs (ATT&CK):
  - Initial Access: T1566.001 (Spearphishing Attachment), T1190 (Exploit Public-Facing Application)
  - Execution: T1059.001 (PowerShell), T1059.003 (Windows Command Shell)
  - Persistence: T1547.001 (Registry Run Keys)
  - Defense Evasion: T1036 (Masquerading), T1027 (Obfuscated Files)
  - Credential Access: T1003 (OS Credential Dumping)
  - Lateral Movement: T1021.001 (Remote Desktop Protocol)
  - Exfiltration: T1048 (Exfiltration Over Alternative Protocol)
Malware Families: [List with links to reports]
Infrastructure Patterns: [ASN preferences, hosting providers, TLD patterns]
Key Operations: [Named campaigns with dates]
Sources: [MITRE, vendor reports, government advisories]
```

### Key Actor Profiles

| Actor | Vendor Aliases | Sponsor | Motivation | Notable Operations | Key Malware |
|---|---|---|---|---|---|
| **APT28** | Fancy Bear, Forest Blizzard, STRONTIUM, Sofacy | Russia (GRU Unit 26165) | Espionage, Influence | Operation Pawn Storm, DNC hack (2016) | X-Agent, Zebrocy, CHOPSTICK, LOOBACK |
| **APT29** | Cozy Bear, Midnight Blizzard, NOBELIUM, The Dukes | Russia (SVR) | Espionage | SolarWinds (2020), MS Exchange OAuth (2023) | SUNBURST, MiniDuke, HAMMERTOSS, FOGGYWEB |
| **Lazarus Group** | HIDDEN COBRA, Sapphire Sleet, TEMP.Hermit | DPRK (RGB) | Financial, Espionage | WannaCry (2017), Bangladesh Bank Heist, Axie Infinity ($625M) | BLINDINGCAN, RATANKBA, AppleJeus, TraderTraitor |
| **FIN7** | Carbon Spider, Sangria Tempest | Criminal (Russia-linked) | Financial | Chipotle/Arby's breaches, Carbanak campaigns | CARBANAK, GRIFFON, TIRION, BIRDWATCH |
| **Sandworm** | Seashell Blizzard, VOODOO BEAR, TeleBots | Russia (GRU Unit 74455) | Destructive | BlackEnergy (2015 Ukraine grid), NotPetya (2017) | BlackEnergy, Industroyer, NotPetya, Cyclops Blink |
| **Scattered Spider** | Octo Tempest, UNC3944, Roasted 0ktapus | Criminal (English-speaking) | Financial, Ransomware | MGM Resorts ($100M+), Caesars Entertainment, Twilio | DragonForce/BlackCat ransomware (affiliate) |
| **LockBit** | LockBit 3.0/Black/Green | Criminal (Russia-linked) | Ransomware-as-a-Service | Boeing, Royal Mail, Accenture, ICBC | LockBit 3.0 (BlackMatter code), StealBit exfil tool |
| **ALPHV/BlackCat** | Noberus | Criminal (Russia-linked) | Ransomware-as-a-Service | Change Healthcare ($22M ransom), MGM, Reddit | BlackCat (Rust-based), SPHYNX, ExMatter |
| **Cl0p** | TA505, Graceful Spider | Criminal (Russia-linked) | Ransomware, Data extortion | MOVEit zero-day (2023, 2000+ orgs), GoAnywhere MFT | Cl0p ransomware, FlawedAmmyy, SDBot |
| **APT41** | Double Dragon, Winnti, Barium, Brass Typhoon | China (MSS) | Espionage + Financial | Supply chain attacks (CCleaner, ASUS), COVID research theft | HIGHNOON, POISONPLUG, MESSAGETAP |

---

## IOC Types & Management

### IOC Taxonomy

**Network IOCs:**
- IPv4/IPv6 addresses — C2 servers, scanners, exfiltration destinations
- Domains and FQDNs — malicious domains, DGA patterns, lookalike domains
- URLs — phishing pages, payload delivery URLs, webshell paths
- JA3/JA3S hashes — TLS client/server fingerprints for C2 identification
- SSL/TLS certificate hashes — SHA1 certificate fingerprints
- ASNs — bulletproof hosting ASNs associated with specific actors
- HTTP headers — User-Agent strings, custom headers, URI patterns

**Host-Based IOCs:**
- File hashes: MD5, SHA1, SHA256, SHA512, SSDEEP (fuzzy hash), TLSH, imphash
- File paths and names — common malware drop locations
- Registry keys and values — persistence mechanisms, configuration storage
- Mutex names — prevent multi-infection, uniquely identify malware families
- Named pipes — IPC communication artifacts from specific malware
- Service names — malicious services with distinctive naming patterns
- Scheduled task names — persistence via Windows Task Scheduler

**Behavioral IOCs:**
- Process parent-child relationships (e.g., Word spawning PowerShell)
- Command-line argument patterns (encoded commands, LOLBin abuse)
- Network connection patterns from unexpected processes
- Memory artifacts — strings, shellcode signatures, PE headers in memory
- Lateral movement patterns — unusual SMB, WMI, PsExec activity

### Pyramid of Pain (David Bianco)

```
        /\
       /  \   TTPs           <- Hardest to change (months-years)
      /----\
     / Tools \               <- Hard (weeks-months)
    /----------\
   / Host Artifacts \        <- Annoying (days-weeks)
  /-----------------\
 / Network Artifacts  \      <- Annoying (days-weeks)
/---------------------\
|      Domain Names    |     <- Simple (hours-days)
|-----------------------|
|      IP Addresses    |     <- Trivial (minutes)
|-----------------------|
|       Hash Values    |     <- Trivial (seconds)
 \_____________________/
```

**Defender value increases as you move up the pyramid.** Blocking a hash is trivial for the adversary to bypass; detecting specific TTPs requires fundamental re-tooling.

### IOC Lifecycle

```
Collection -> Validation -> Enrichment -> Scoring -> Active Monitoring -> Expiration/Review
```

1. **Collection**: Ingest from feeds, hunting, incident response, vendor sharing
2. **Validation**: Remove false positives, check against allowlists, verify source
3. **Enrichment**: Add context (geo, ASN, WHOIS, VirusTotal, Shodan, passive DNS)
4. **Scoring**: Assign confidence and severity based on scoring model
5. **Active Monitoring**: Push to SIEM, firewall, EDR for detection
6. **Expiration**: Retire stale IOCs on schedule

### IOC Scoring Factors

| Factor | Weight | Description |
|---|---|---|
| Source reliability | High | Tier 1 (ISAC, government) vs Tier 3 (unvetted open feeds) |
| Recency | High | Hours-old IOC vs months-old IOC |
| Specificity | Medium | Targeted malware vs broad scanner |
| Context confidence | Medium | Confirmed malicious vs suspicious |
| Volume/prevalence | Low | Unique IOC vs seen across 1000+ scans |

### IOC Expiration Guidelines

| IOC Type | Default TTL | Rationale |
|---|---|---|
| IP addresses | 30 days | IPs are frequently recycled, high false positive risk |
| Domains | 60 days | Domains persist longer; DGA domains may expire sooner |
| File hashes (MD5/SHA1) | 90 days | Malware variants still warrant long tracking |
| File hashes (SHA256) | 180 days | Cryptographically unique, reliable for extended use |
| SSL certificates | 90 days | Certs rotate but may persist |
| JA3 hashes | 180 days | TLS fingerprints change with tool updates |
| TTPs | Indefinite | Adversary behaviors persist across campaigns |

### Bulk IOC Operations — Python PyMISP Example

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP(url='https://misp.example.com', key='YOUR_API_KEY', ssl=True)

# Create a new event
event = MISPEvent()
event.info = 'APT28 Campaign IOCs - 2024-04'
event.add_tag('tlp:amber')
event.add_tag('PAP:AMBER')
event.threat_level_id = 1  # High
event.analysis = 2          # Completed
event.distribution = 1      # This community only

# Add IOCs
iocs = [
    ('ip-dst', '185.220.101.45'),
    ('domain', 'update-microsoft-cdn.com'),
    ('sha256', 'e3b0c44298fc1c149afb...'),
    ('url', 'https://phishing.example.com/login'),
]

for ioc_type, ioc_value in iocs:
    event.add_attribute(ioc_type, ioc_value, to_ids=True)

# Push event
result = misp.add_event(event)
print(f"Event created: {result['Event']['uuid']}")
```

---

## Threat Intelligence Platforms (TIPs)

### TIP Comparison Matrix

| Platform | Type | STIX/TAXII | REST API | ATT&CK Integration | Price Tier |
|---|---|---|---|---|---|
| **MISP** | OSS | Yes (2.0+2.1) | Yes | Module + Galaxy | Free |
| **OpenCTI** | OSS | Yes (2.1) | GraphQL + REST | Native | Free (self-hosted) |
| **ThreatConnect** | Commercial | Yes | Yes | Yes | $$$ |
| **Anomali ThreatStream** | Commercial | Yes | Yes | Yes | $$$ |
| **Recorded Future** | Commercial | STIX export | Yes | Structured | $$$$ |
| **Mandiant Threat Intelligence** | Commercial | Yes | Yes | Native actor pages | $$$$ |
| **CrowdStrike Falcon Intel** | Commercial | STIX export | Yes | Actor/Malware pages | $$$$ |
| **IBM X-Force Exchange** | Commercial (Free tier) | Yes | Yes | Limited | Free/$$$ |

### MISP

MISP (Malware Information Sharing Platform) is the most widely deployed open-source TIP.

**Event Structure:**
- **Event**: Top-level container with metadata (date, threat level, analysis status, distribution)
- **Attributes**: Individual IOCs with type, value, category, and IDS flag
- **Objects**: Structured groups of related attributes (file object, network-connection object)
- **Tags**: Taxonomy labels (TLP, PAP, MISP Galaxy, custom)
- **Galaxy**: Threat actor, malware family, ATT&CK technique clusters
- **Sharing Groups**: Granular trust-based sharing beyond distribution levels

**Tag Taxonomies:**
- **TLP**: `tlp:red`, `tlp:amber`, `tlp:amber+strict`, `tlp:green`, `tlp:clear`
- **PAP**: `PAP:RED`, `PAP:AMBER`, `PAP:GREEN`, `PAP:WHITE`
- **MISP Galaxy**: Links attributes to threat actors, campaigns, malware families
- **ATT&CK**: `misp-attack-pattern:enterprise-attack-T1566.001`

**MISP API Examples:**

```bash
# Get all events
curl -H 'Authorization: YOUR_API_KEY' \
     -H 'Accept: application/json' \
     https://misp.example.com/events/

# Search for IOC
curl -H 'Authorization: YOUR_API_KEY' \
     -H 'Accept: application/json' \
     -H 'Content-Type: application/json' \
     -d '{"returnFormat":"json","type":"ip-dst","value":"185.220.101.45"}' \
     https://misp.example.com/attributes/restSearch

# Feed configuration (fetch feed)
curl -H 'Authorization: YOUR_API_KEY' \
     -X POST \
     https://misp.example.com/feeds/fetchFromFeed/FEED_ID
```

**Popular MISP Feeds:**
- abuse.ch URLhaus, Feodo, MalwareBazaar
- CIRCL OSINT Feed
- Botvrij.eu
- DigitalSide OSINT Feed

### OpenCTI

OpenCTI is a modern OSS platform built natively on STIX 2.1 with a knowledge graph backend (ElasticSearch + Redis + RabbitMQ).

**Architecture:**
- **Platform Core**: GraphQL API, STIX 2.1 native storage
- **Connectors**: Import (ATT&CK, CVE, MISP, Mandiant, VT), Export (STIX, CSV, PDF), Enrichment (VT, Shodan, AbuseIPDB)
- **Streams**: Real-time STIX event streaming for SIEM integration

**OpenCTI GraphQL API Example:**

```graphql
query GetThreatActors {
  threatActors(first: 10) {
    edges {
      node {
        id
        name
        aliases
        first_seen
        sophistication
        confidence
      }
    }
  }
}
```

**ATT&CK Knowledge Base Import via connector-mitre:**

```yaml
connector-mitre:
  image: opencti/connector-mitre:6.0.0
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_TYPE=EXTERNAL_IMPORT
    - MITRE_ENTERPRISE_FILE_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    - MITRE_INTERVAL=7
```

### Feed Management Best Practices

| Tier | Characteristics | Examples | Action |
|---|---|---|---|
| **Tier 1** | High reliability, low volume, vetted | ISAC feeds, government TAXII, vendor intel | Ingest all, auto-push to SIEM |
| **Tier 2** | Medium reliability, medium volume | abuse.ch, AlienVault OTX, commercial | Ingest with scoring, selective push |
| **Tier 3** | Low reliability, high volume | Bulk open feeds, unvetted sources | Aggregate only, manual validation |

**Deduplication**: Always deduplicate on value+type before storage. Use normalized forms (lowercase domains, CIDR expansion for IPs).

**Allowlisting**: Maintain an allowlist of known-good infrastructure (CDNs, Google DNS, internal ranges) to suppress false positives before IOC matching.

---

## Intelligence Sources

### OSINT Feeds

| Source | What It Provides | URL / API |
|---|---|---|
| **abuse.ch MalwareBazaar** | Malware samples + hashes, YARA rules | `https://bazaar.abuse.ch/api/` |
| **abuse.ch URLhaus** | Malicious URLs, payloads, tags | `https://urlhaus-api.abuse.ch/v1/` |
| **abuse.ch Feodo Tracker** | Botnet C2 IPs (Emotet, QBot, Dridex) | `https://feodotracker.abuse.ch/downloads/ipblocklist.csv` |
| **abuse.ch ThreatFox** | IOCs from multiple malware families | `https://threatfox-api.abuse.ch/api/v1/` |
| **AlienVault OTX** | Pulse-based community threat sharing | `https://otx.alienvault.com/api/v1/` |
| **Shodan** | Internet-connected device scanning | `https://api.shodan.io/shodan/host/{ip}` |
| **Censys** | Certificate + protocol scanning | `https://search.censys.io/api/v2/` |
| **GreyNoise** | Mass internet scanner identification | `https://api.greynoise.io/v3/community/{ip}` |
| **URLScan.io** | Website scanning and screenshot | `https://urlscan.io/api/v1/scan/` |
| **VirusTotal** | Multi-AV + sandbox analysis | `https://www.virustotal.com/api/v3/` |

### Government & ISAC Feeds

| Source | Coverage | Access |
|---|---|---|
| **CISA AIS** | Automated Indicator Sharing — STIX/TAXII 2.1 | Enrollment at cisa.gov/ais |
| **CISA Known Exploited Vulnerabilities (KEV)** | Actively exploited CVEs | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| **FS-ISAC** | Financial sector threats | Member enrollment |
| **H-ISAC** | Healthcare sector threats | Member enrollment |
| **E-ISAC** | Electricity / energy sector | Member enrollment |
| **MS-ISAC** | State, local, tribal, territorial government | Free for SLTT, MS-ISAC.org |
| **NCSC (UK)** | UK government advisories | NCSC.gov.uk |
| **BSI (Germany)** | German federal cybersecurity | BSI.bund.de |

### Commercial Intelligence Sources

| Vendor | Strengths |
|---|---|
| **Mandiant / Google** | APT research, incident response intel, vulnerability data |
| **Recorded Future** | OSINT aggregation, dark web, predictive scoring |
| **CrowdStrike** | Adversary-centric, eCrime intelligence, HUMINT sources |
| **Intel 471** | Underground forum HUMINT, actor tracking |
| **KELA** | Dark web monitoring, ransomware tracking |
| **Flashpoint** | Dark web, illicit communities, fraud |

### Dark Web Monitoring

Dark web monitoring provides early warning of planned attacks, stolen credentials, and data leaks.

**Monitor Without Direct Access:**
- Commercial services (Recorded Future, Flashpoint, KELA) provide sanitized access
- Automated crawlers with HUMINT validation
- Keyword alerts for company names, domains, executive names, product names

**Key Sources to Monitor:**
- **Ransomware Leak Sites**: LockBit, ALPHV/BlackCat, Cl0p, Play, Akira — all have public-facing .onion sites listing victims
- **Credential Markets**: Genesis Market successors, Russian Market — stolen browser profiles
- **Forums**: BreachForums, XSS.is, Exploit.in — vulnerability sales, data dumps
- **Telegram Channels**: KillNet, NoName057(16), ransomware group channels — announcements and recruitment

**OPSEC Warning**: Direct access to dark web forums requires significant OPSEC and legal review. Use commercial services for organizational monitoring.

### Technical Collection Methods

**Passive DNS:**
- Provides historical domain-to-IP resolution data without active scanning
- Sources: Farsight DNSDB, PassiveTotal/RiskIQ, VirusTotal passive DNS
- Use cases: Track C2 infrastructure migration, identify actor-linked domains

**Certificate Transparency (CT) Logs:**
- All publicly trusted TLS certs are logged to CT logs
- `crt.sh` provides free search: `https://crt.sh/?q=%.targetdomain.com`
- Monitor for lookalike domains, phishing cert issuance

**BGP Monitoring:**
- Track autonomous system routing changes, detect BGP hijacking
- Sources: BGPStream (bgpstream.caida.org), RIPE NCC, Team Cymru

**Internet Scanning Historical Data:**
- Shodan/Censys historical: Reconstruct C2 infrastructure history for actor attribution

---

## IOC Enrichment Workflows

### API Examples

**VirusTotal — IP Lookup:**

```bash
curl --request GET \
  --url 'https://www.virustotal.com/api/v3/ip_addresses/185.220.101.45' \
  --header 'x-apikey: YOUR_VT_API_KEY'
```

**Shodan — Host Lookup:**

```bash
curl 'https://api.shodan.io/shodan/host/185.220.101.45?key=YOUR_SHODAN_KEY'
```

**GreyNoise — Community API:**

```bash
curl -H 'key: YOUR_GREYNOISE_KEY' \
     'https://api.greynoise.io/v3/community/185.220.101.45'
# Returns: noise (mass scanner), riot (benign service), unknown
```

**URLScan.io — Submit and Retrieve:**

```bash
# Submit scan
curl -X POST 'https://urlscan.io/api/v1/scan/' \
  -H 'API-Key: YOUR_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://suspicious.example.com", "visibility": "private"}'

# Retrieve result (after ~30 seconds)
curl 'https://urlscan.io/api/v1/result/SCAN_UUID/'
```

**AbuseIPDB — Check IP:**

```bash
curl -G 'https://api.abuseipdb.com/api/v2/check' \
  --data-urlencode 'ipAddress=185.220.101.45' \
  -d maxAgeInDays=90 \
  -H 'Key: YOUR_ABUSEIPDB_KEY' \
  -H 'Accept: application/json'
```

### Python Async Enrichment Script

```python
import asyncio
import aiohttp
from dataclasses import dataclass, field
from typing import Optional

VT_KEY = "YOUR_VT_KEY"
GN_KEY = "YOUR_GREYNOISE_KEY"

@dataclass
class EnrichedIOC:
    value: str
    ioc_type: str
    vt_detections: Optional[int] = None
    vt_total: Optional[int] = None
    greynoise_classification: Optional[str] = None
    confidence_score: int = 0
    tags: list = field(default_factory=list)

async def enrich_ip(session, ip):
    result = EnrichedIOC(value=ip, ioc_type="ip")
    # VirusTotal
    async with session.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT_KEY}
    ) as r:
        if r.status == 200:
            data = await r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result.vt_detections = stats.get("malicious", 0)
            result.vt_total = sum(stats.values())
    # GreyNoise
    async with session.get(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"key": GN_KEY}
    ) as r:
        if r.status == 200:
            data = await r.json()
            result.greynoise_classification = data.get("classification", "unknown")
            if data.get("riot"):
                result.tags.append("benign-service")
    # Scoring
    if result.vt_detections:
        if result.vt_detections >= 10:
            result.confidence_score += 50
        elif result.vt_detections >= 5:
            result.confidence_score += 30
    if result.greynoise_classification == "malicious":
        result.confidence_score += 30
    elif "benign-service" in result.tags:
        result.confidence_score = max(0, result.confidence_score - 40)
    return result

async def enrich_batch(iocs):
    async with aiohttp.ClientSession() as session:
        tasks = [enrich_ip(session, ip) for ip in iocs]
        return await asyncio.gather(*tasks, return_exceptions=True)
```

### Automated Enrichment Pipeline

```
SIEM Alert
    |
    v
Extract IOC (regex/grok for IP, domain, hash, URL)
    |
    v
Check allowlist (CDN ranges, internal subnets, known-good)
    |
    +-- ALLOWLISTED --> Suppress, log false positive candidate
    |
    v
Multi-source enrichment (async)
    +-- VirusTotal API
    +-- GreyNoise API
    +-- Shodan API
    +-- MISP/TIP local lookup
    |
    v
Confidence scoring (weighted per source)
    |
    +-- Score < 30  --> Log for analyst review
    +-- Score 30-70 --> Create alert ticket, enriched context
    +-- Score > 70  --> Auto-block (firewall/EDR), create P2 ticket
    |
    v
Update TIP + push detections to SIEM/EDR
```

---

## Threat Intelligence Reporting

### TLP (Traffic Light Protocol) 2.0

| Label | Sharing Scope | Description |
|---|---|---|
| **TLP:RED** | Named recipients only | Not for disclosure. Cannot be shared beyond direct recipients. |
| **TLP:AMBER** | Organization only | Limited disclosure to need-to-know within the recipient's organization. |
| **TLP:AMBER+STRICT** | Organization, no clients | Same as AMBER but explicitly excludes clients or customers. |
| **TLP:GREEN** | Community | Can be shared with peers and partner organizations but not published publicly. |
| **TLP:CLEAR** | Unlimited | No restrictions. Can be published publicly. |

### PAP (Permissible Actions Protocol)

| Label | Meaning |
|---|---|
| **PAP:RED** | Cannot be used for detection or hunting. For situational awareness only. |
| **PAP:AMBER** | Can be used for internal hunting and detection but not exposed in automated tools. |
| **PAP:GREEN** | Can be used in automated detection systems but not shared externally. |
| **PAP:WHITE** | Can be used for any purpose including public tools and external sharing. |

### Intel Report Types

**Strategic Report Template:**

```
CLASSIFICATION: TLP:AMBER
DATE: YYYY-MM-DD
TITLE: [Threat Actor/Campaign] Targeting [Sector]

EXECUTIVE SUMMARY
  [2-3 sentence high-level summary for non-technical leadership]

KEY JUDGMENTS
  - [High confidence] Finding 1
  - [Medium confidence] Finding 2
  - [Low confidence] Finding 3

THREAT LANDSCAPE
  [Current threat environment context for sector/region]

ADVERSARY TTPs
  [ATT&CK-mapped techniques with evidence]

INDICATORS OF COMPROMISE
  [High-confidence IOCs with expiration dates]

RECOMMENDATIONS
  Priority 1 (Immediate): [Action]
  Priority 2 (30 days): [Action]
  Priority 3 (90 days): [Action]

SOURCE ASSESSMENT
  [Source reliability and confidence methodology]
```

**Tactical IOC Report:**
- CSV format: `type,value,confidence,tlp,expiry,tags,source`
- STIX 2.1 bundle with Indicator + Report + Relationship objects
- Sigma rules for detection
- Include ATT&CK technique references

**Flash Report (Breaking Threat):**
- Maximum 1 page, BLUF (Bottom Line Up Front) lead
- Confirmed IOCs with immediate defensive actions
- Preliminary confidence — note it will be refined

### Confidence Levels

**Admiralty Code:**

| Source Reliability | | Information Reliability | |
|---|---|---|---|
| A — Completely reliable | | 1 — Confirmed | |
| B — Usually reliable | | 2 — Probably true | |
| C — Fairly reliable | | 3 — Possibly true | |
| D — Not usually reliable | | 4 — Doubtful | |
| E — Unreliable | | 5 — Improbable | |
| F — Cannot be judged | | 6 — Cannot be judged | |

Usage: Rate as `B2` (usually reliable source, probably true content).

**ACH (Analysis of Competing Hypotheses):**
1. List all plausible hypotheses
2. List evidence for/against each hypothesis
3. Score each piece of evidence against each hypothesis
4. Identify the hypothesis with the least evidence against it (most consistent)
5. Report confidence level based on evidence quality and quantity

**Structured Analytic Techniques:**
- **Key Assumptions Check**: Identify and challenge implicit assumptions
- **Red Team Analysis**: Steelman the adversary's perspective
- **Devil's Advocacy**: Argue the opposite of the consensus view
- **Pre-Mortem Analysis**: Assume the assessment is wrong, explain why

---

## Intelligence-Driven Detection

### Converting Intel to Detections

**IOC -> SIEM Detection Rule (Splunk):**

```splunk
index=network sourcetype=firewall
dest_ip IN ("185.220.101.45", "91.195.240.117", "194.165.16.78")
action=allowed
| stats count by src_ip, dest_ip, dest_port, _time
| eval severity="high", intel_source="APT28_campaign_2024-04"
| table _time, src_ip, dest_ip, dest_port, count, severity, intel_source
```

**TTP -> Behavioral Detection (Sigma):**

```yaml
title: PowerShell Download Cradle via WMIC
id: 1f21ec3f-810d-4b0e-8045-58c48a8e2eb4
status: stable
description: Detects PowerShell download cradle execution via WMIC
tags:
  - attack.execution
  - attack.t1047
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection
falsepositives:
  - Legitimate admin automation (validate with asset owner)
level: high
```

**Campaign -> Correlation Rule:**

```splunk
index=* earliest=-24h
(
  [| inputlookup apt28_iocs.csv | fields value | rename value as dest_ip]
  OR CommandLine="*Invoke-Expression*" ParentImage="*WmiPrvSE*"
  OR (dest_port=4444 src_ip=internal)
)
| stats dc(signature) as distinct_sigs, values(signature) as sigs by src_ip
| where distinct_sigs >= 2
| eval campaign="APT28-2024-Q1", confidence="medium"
```

### ATT&CK Navigator Layer from Actor Profile

1. Pull actor techniques from the MITRE ATT&CK STIX bundle
2. Filter relationships where `source_ref` is the group's STIX ID and `relationship_type` == "uses"
3. Build Navigator layer JSON with technique IDs and actor-specific color coding
4. Load in ATT&CK Navigator at `https://mitre-attack.github.io/attack-navigator/`
5. Compare against your detection coverage layer (covered vs gap)

### Intel-Driven Threat Hunting

**Hypothesis Formation:**

```
"Based on APT28 campaign reporting from 2024-Q1, the actor uses
WMI-based PowerShell execution (T1047 + T1059.001) to establish
persistence via scheduled tasks (T1053.005) in environments running
unpatched Exchange servers (T1190). Hypothesis: We have an undetected
APT28 intrusion in our Exchange environment."
```

**Hunt Query — Scheduled Task Creation via PowerShell (KQL):**

```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessCommandLine has_any ("schtasks", "New-ScheduledTask", "Register-ScheduledTask")
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessParentFileName in~ ("wmiprvse.exe", "mmc.exe", "outlook.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated desc
```

**Hunt -> Finding -> Report Cycle:**
1. Run hypothesis-driven hunt queries
2. Document findings (confirmed malicious / suspicious / false positive)
3. For confirmed/suspicious: create incident, collect forensic artifacts
4. Update TIP with new IOCs from hunt findings
5. Convert successful hunts into persistent SIEM detections
6. Produce hunt report: scope, methodology, findings, detections created, IOCs added

---

## NIST & ATT&CK Mappings

### NIST 800-53 Control Families

| Control Family | Relevance to Threat Intel |
|---|---|
| **PM-16 (Program Management)** | Threat Awareness Program — formal CTI program requirement |
| **RA-3 (Risk Assessment)** | Risk Assessment incorporating threat intelligence |
| **RA-10 (Threat Hunting)** | Intelligence-driven threat hunting mandate |
| **RA-5 (Vulnerability Monitoring)** | Vulnerability scanning informed by threat intel |
| **SI-5 (Security Alerts/Advisories)** | IOC dissemination and advisory consumption |
| **IR-4 (Incident Handling)** | Intel-enhanced incident response procedures |
| **CA-7 (Continuous Monitoring)** | Continuous monitoring using threat intel feeds |

### ATT&CK PRE-ATT&CK Techniques

Pre-ATT&CK (now merged into Enterprise ATT&CK) covers adversary activities before the main kill chain begins:

| Tactic | Key Techniques |
|---|---|
| **Reconnaissance (TA0043)** | T1595 Active Scanning, T1592 Gather Victim Host Info, T1589 Gather Victim Identity Info, T1590 Gather Victim Network Info, T1591 Gather Victim Org Info, T1598 Phishing for Information |
| **Resource Development (TA0042)** | T1583 Acquire Infrastructure, T1584 Compromise Infrastructure, T1585 Establish Accounts, T1586 Compromise Accounts, T1587 Develop Capabilities, T1588 Obtain Capabilities, T1608 Stage Capabilities |

**Intel value**: Monitoring for reconnaissance activity (Shodan scans against your org, registration of lookalike domains, GitHub code search for your org name) provides the earliest possible warning — before the kill chain even begins.

---

## Quick Reference

### Intelligence Rating Scale

| Confidence | Percentage | Usage |
|---|---|---|
| **Confirmed** | 95-100% | Multiple independent sources, technical validation |
| **High** | 80-94% | Strong evidence, single reliable source |
| **Medium** | 50-79% | Credible but limited/indirect evidence |
| **Low** | 20-49% | Unverified, single source, technical gaps |
| **Speculative** | <20% | Hypothesis only, minimal evidence |

### Key URLs

| Resource | URL |
|---|---|
| MITRE ATT&CK | `https://attack.mitre.org/` |
| ATT&CK Navigator | `https://mitre-attack.github.io/attack-navigator/` |
| MITRE CTI GitHub | `https://github.com/mitre/cti` |
| CISA KEV | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` |
| CISA AIS | `https://www.cisa.gov/resources-tools/programs/automated-indicator-sharing-ais` |
| FIRST TLP | `https://www.first.org/tlp/` |
| OASIS STIX/TAXII | `https://oasis-open.github.io/cti-documentation/` |
| abuse.ch | `https://abuse.ch/` |
| crt.sh | `https://crt.sh/` |
| GreyNoise | `https://www.greynoise.io/` |
| URLScan.io | `https://urlscan.io/` |
| VirusTotal | `https://www.virustotal.com/` |
| Shodan | `https://www.shodan.io/` |

---

*Map to NIST 800-53 PM-16, RA-3, RA-10, SI-5 | ATT&CK Reconnaissance (TA0043), Resource Development (TA0042)*
