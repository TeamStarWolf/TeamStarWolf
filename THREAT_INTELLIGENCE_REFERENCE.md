# Threat Intelligence Reference Library

> Comprehensive professional reference for Cyber Threat Intelligence practitioners, SOC analysts, incident responders, threat hunters, and security leadership.

---

## Table of Contents

1. [CTI Fundamentals](#_1-cti-fundamentals)
2. [Threat Intelligence Platforms](#_2-threat-intelligence-platforms)
3. [STIX & TAXII Standards](#_3-stix-amp-taxii-standards)
4. [IOC Management & Enrichment](#_4-ioc-management-amp-enrichment)
5. [Threat Actor Tracking & Attribution](#_5-threat-actor-tracking-amp-attribution)
6. [OSINT for Threat Intelligence](#_6-osint-for-threat-intelligence)
7. [Malware Intelligence for CTI](#_7-malware-intelligence-for-cti)
8. [Threat Intelligence Sharing](#_8-threat-intelligence-sharing)
9. [CTI Integration with Security Operations](#_9-cti-integration-with-security-operations)
10. [CTI Program Management & Metrics](#_10-cti-program-management-amp-metrics)

---

## 1. CTI Fundamentals

### 1.1 The Intelligence Cycle

The intelligence cycle is the foundational process that transforms raw data into actionable intelligence. All mature CTI programs operate around this iterative loop:

```
Planning & Direction
        |
        v
    Collection
        |
        v
    Processing
        |
        v
     Analysis
        |
        v
  Dissemination
        |
        v
     Feedback
        |
        +--------------> (back to Planning)
```

**Planning & Direction**
- Define Priority Intelligence Requirements (PIRs) with stakeholders
- Identify knowledge gaps and collection needs
- Allocate analyst resources to highest-value tasks
- Establish reporting cadences and consumer expectations
- Maintain standing collection plans for recurring requirements

**Collection**
- Gather raw data from technical feeds (OSINT, commercial TI, ISACs, dark web)
- Ingest malware samples, network logs, endpoint telemetry
- Conduct human source elicitation from sector peers and government liaisons
- Operate honeypots, sinkholes, and passive DNS sensors
- Subscribe to threat feeds (STIX/TAXII, CSV blocklists, API-based enrichment)

**Processing**
- Parse, normalize, and de-duplicate raw data
- Translate, transliterate, and OCR foreign-language content
- Decode malware configs, extract IOCs from sandbox reports
- Ingest into TIP (MISP, OpenCTI, ThreatConnect) with structured tagging
- Apply confidence scoring based on source reliability

**Analysis**
- Apply structured analytic techniques (ACH, timeline analysis, link analysis)
- Map TTPs to MITRE ATT&CK framework
- Assess adversary capability, intent, and opportunity
- Identify patterns, clusters, and campaign activity threads
- Produce finished intelligence products at appropriate classification

**Dissemination**
- Distribute finished intelligence to appropriate consumers
- Apply TLP markings and handling caveats
- Format products for consumer audience (technical IOCs vs. executive brief)
- Push machine-readable STIX bundles to SIEM/SOAR/TIP via TAXII
- Publish to sharing communities (ISACs, CISA AIS) with proper controls

**Feedback**
- Collect consumer feedback on product quality and relevance
- Measure whether intelligence drove defensive actions
- Adjust PIRs based on changing threat landscape and business priorities
- Refine collection plans to address identified gaps
- Track false positive rates and IOC efficacy

---

### 1.2 CTI Taxonomy

Intelligence is classified into four distinct levels, each serving different consumers and decision horizons:

#### Strategic Intelligence
- **Audience**: C-suite, board of directors, CISO, business unit leaders
- **Time horizon**: Months to years
- **Purpose**: Inform long-term security investment, risk appetite, and organizational posture
- **Examples**: Nation-state threat landscape briefings; geopolitical risk assessments; sector-wide campaign trend analysis; adversary intent assessments targeting the organization's industry
- **Products**: Quarterly threat landscape reports, annual risk assessments, board briefings

#### Operational Intelligence
- **Audience**: Security managers, incident response leads, red team leads
- **Time horizon**: Days to weeks
- **Purpose**: Understand ongoing adversary campaigns, TTPs, and targeting patterns to inform defensive operations and hunting priorities
- **Examples**: Active campaign analysis with actor attribution; C2 infrastructure mapping; spearphishing lure analysis; ransomware precursor activity tracking
- **Products**: Campaign reports, weekly threat digests, hunting briefs

#### Tactical Intelligence
- **Audience**: SOC analysts, tier-1/2/3 responders, threat hunters
- **Time horizon**: Hours to days
- **Purpose**: Provide IOCs and detection signatures for immediate defensive action
- **Examples**: Malicious IP lists, phishing domain feeds, file hash blocklists, Snort/Yara/Sigma rules
- **Products**: Structured IOC feeds (STIX/TAXII), blocklist updates, detection rule packages

#### Technical Intelligence
- **Audience**: Malware analysts, vulnerability researchers, platform engineers
- **Time horizon**: Real-time to days
- **Purpose**: Deep technical understanding of tools, exploits, and malware capabilities for detection engineering and platform hardening
- **Examples**: Malware reverse engineering reports, exploit PoC analysis, C2 protocol documentation, packers and evasion techniques
- **Products**: Technical reports with YARA rules, network signatures, configuration parser scripts

---

### 1.3 Pyramid of Pain

David Bianco's Pyramid of Pain (2013) describes the relative difficulty for adversaries to change different IOC types, and conversely, the impact to the adversary when defenders successfully detect and block each level:

```
                    +==================+
                    |      TTPs        |  <- Highest Impact
                    +==================+
                    |     Tools        |
              +=====+==================+=====+
              |    Network/Host Artifacts    |
        +=====+==============================+=====+
        |              Domain Names               |
    +===+=========================================+===+
    |                  IP Addresses                   |
+===+=====================================================+===+
|                     Hash Values                         |  <- Trivial to change
+=========================================================+
```

| Level | IOC Type | Adversary Cost to Change | Defender Value |
|-------|----------|--------------------------|----------------|
| 1 | Hash Values (MD5, SHA1, SHA256) | Trivial -- recompile or repack | Low -- trivially bypassed |
| 2 | IP Addresses | Easy -- rotate C2, use VPS/bulletproof | Low-medium |
| 3 | Domain Names | Easy -- register new domains, use DGA | Medium |
| 4 | Network/Host Artifacts | Moderate -- change tool configs, strings | Medium-high |
| 5 | Tools | Hard -- retool, rewrite, acquire new implant | High |
| 6 | TTPs | Very Hard -- change tradecraft, retrain operators | Highest |

**Operational Implication**: CTI programs should prioritize detection at the Tools and TTPs levels via behavioral detection (ATT&CK-mapped rules) rather than relying primarily on hash and IP blocklists.

---

### 1.4 Diamond Model of Intrusion Analysis

The Diamond Model (Caltagirone, Pendergast, Betz -- 2013) provides a structured framework for analyzing intrusion events and correlating activity across campaigns:

```
             Adversary
            /          \
           /            \
     (uses)              (targets)
         /                \
        /                  \
  Capability ---------- Infrastructure
              (delivers)
                   |
              (meta-features)
```

**Four Core Features**:
- **Adversary**: The threat actor or group conducting the intrusion
- **Capability**: The tools, exploits, malware, and TTPs employed
- **Infrastructure**: The IP addresses, domains, servers, email accounts used
- **Victim**: The targeted organization, individual, or asset

**Meta-Features** (extend the model for analytical depth):
- **Timestamp**: When the event occurred
- **Phase**: Which phase of the kill chain or ATT&CK the event maps to
- **Result**: Success/fail/unknown -- what the adversary achieved
- **Direction**: Victim-to-infrastructure vs. infrastructure-to-victim
- **Methodology**: Spearphishing, watering hole, supply chain, etc.
- **Resources**: External infrastructure, capabilities, and funding

**Activity Threads**: Multiple Diamond events can be linked into activity threads when they share adversary, capability, or infrastructure nodes, enabling campaign-level correlation across disparate intrusion events.

**Analytical Application**: When a new intrusion event is detected, populate all four nodes. Pivot from known nodes (e.g., shared C2 IP) to identify related events, cluster activity into campaigns, and ultimately attribute to known threat actors or create a new activity cluster.

---

### 1.5 F3EAD Process

Originally a military targeting methodology, F3EAD has been adapted for cyber threat intelligence to operationalize intelligence in support of defensive actions:

| Phase | Description | CTI Application |
|-------|-------------|-----------------|
| **Find** | Locate the target/threat | Identify IOCs, detect malware, find adversary infrastructure via OSINT |
| **Fix** | Confirm and track the target | Validate IOCs, track C2 infrastructure, confirm active campaign |
| **Finish** | Act on the target | Block IOCs, isolate endpoints, take down infrastructure, notify law enforcement |
| **Exploit** | Gather intelligence from the target | Analyze malware, extract configs, recover forensic artifacts |
| **Analyze** | Process intelligence gathered | Produce finished intelligence products, update actor profiles |
| **Disseminate** | Share intelligence with consumers | Push to SIEM, share with sector peers, brief leadership |

---

### 1.6 Intelligence-Led Security Program Design

A mature intelligence-led security program integrates CTI into every tier of the security operations stack:

- **Detection Engineering**: ATT&CK-mapped SIEM rules informed by current actor TTPs; detection coverage gap analysis vs. known actor playbooks
- **Threat Hunting**: Hypothesis-driven hunts based on CTI campaign reports; proactive search for actor-specific artifacts before alerting fires
- **Incident Response**: Pre-built playbooks per known actor group; rapid actor attribution during active incidents to predict next steps
- **Vulnerability Management**: Prioritize patching by CVEs actively exploited by actors targeting your sector (CISA KEV, Shadowserver data)
- **Red Team Operations**: Emulate specific threat actor TTPs identified through CTI; validate detection coverage against realistic adversary behavior

---

### 1.7 CTI Consumer Types

| Consumer | Primary Needs | Product Format |
|----------|---------------|----------------|
| **SOC Analysts (Tier 1-2)** | Actionable IOCs, quick context on alerts | STIX feeds, enrichment cards, alert annotations |
| **Incident Responders** | Actor TTP playbooks, forensic indicators, C2 infrastructure maps | Technical reports, actor profiles, IR briefs |
| **Threat Hunters** | Hypotheses, behavioral TTPs, ATT&CK coverage gaps | Hunt packages, ATT&CK heatmaps, analytics |
| **Vulnerability Management** | Exploited CVEs, actor exploit preferences | KEV-mapped priority lists, exploitation context |
| **Executives / CISO** | Business risk, threat landscape, adversary intent | 1-page threat briefs, risk heat maps |
| **Board of Directors** | Strategic risk, regulatory posture, industry benchmarks | Quarterly briefings, geopolitical risk summaries |

---

## 2. Threat Intelligence Platforms

### 2.1 MISP (Malware Information Sharing Platform)

MISP is the leading open-source TIP, developed by CIRCL (Computer Incident Response Center Luxembourg) and widely deployed across government CERTs, ISACs, and enterprise security teams.

#### Data Model
```
Event (container)
+-- Attributes (individual IOCs: ip-dst, domain, md5, url, email-src...)
+-- Objects (structured groups: file, domain-ip, email, network-traffic...)
+-- Tags (classification: TLP, threat-actor, MITRE ATT&CK technique)
+-- Galaxies (knowledge base clusters: threat-actor, tool, ransomware...)
+-- Relationships (correlations between events and objects)
```

#### MISP Galaxies
Galaxies provide curated knowledge base entries that can be attached to events:
- **Threat Actor Galaxy**: Nation-state and eCrime actor profiles (APT groups, FIN groups)
- **Tool Galaxy**: Malware families and offensive tools (Cobalt Strike, Mimikatz, etc.)
- **ATT&CK Galaxy**: MITRE ATT&CK Enterprise/Mobile/ICS techniques
- **Ransomware Galaxy**: Ransomware family profiles with IOCs and TTPs
- **Sector Galaxy**: Industry vertical targeting information

#### Correlation Engine
MISP automatically correlates attributes across events when values match. Correlation types:
- **Exact match**: Identical attribute values (IP, hash, domain)
- **CIDR correlation**: IP address within a known malicious subnet
- **Fuzzy hash**: ssdeep/TLSH similarity matching for file hashes
- **Disable correlation**: For high-frequency attributes (e.g., common legitimate IPs)

#### Sharing Groups
Granular sharing control beyond organization-level:
```
Sharing Group: "FS-ISAC Members Only"
+-- Member orgs: [Bank_A, Bank_B, Insurance_C]
+-- Routable: Yes/No (allow re-sharing to other trusted communities)
+-- Applied to: Individual events or attributes
```

#### MISP REST API
```bash
# Add new event
POST /events/add
Content-Type: application/json
{
  "info": "Cobalt Strike C2 Infrastructure - APT29 Campaign",
  "distribution": 1,
  "threat_level_id": 1,
  "analysis": 2,
  "Attribute": [
    {"type": "ip-dst", "value": "192.0.2.100", "category": "Network activity"},
    {"type": "domain", "value": "update-cdn-secure.com", "category": "Network activity"}
  ]
}

# Search for events by IOC value
GET /events/index?searchvalue=192.0.2.100&searchall=1

# Push to connected MISP server
POST /events/push/{serverid}

# Get event by ID
GET /events/view/{event_id}
```

#### PyMISP Examples
```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP('https://misp.example.com', 'API_KEY')

# Create and push a new event
event = MISPEvent()
event.info = "Phishing Campaign - FIN7 - 2024-Q1"
event.threat_level_id = 1
event.distribution = 1
event.add_tag('tlp:amber')
event.add_tag('misp-galaxy:threat-actor="FIN7"')

attr = event.add_attribute('ip-dst', '198.51.100.45')
attr.add_tag('misp-galaxy:mitre-attack-pattern="Phishing - T1566"')

result = misp.add_event(event)

# Search by IOC value
results = misp.search(value='198.51.100.45', type_attribute='ip-dst')

# Search across all attributes
results = misp.search(value='evil-domain.com', searchall=True)

# Retrieve specific event
event = misp.get_event(1337, pythonify=True)

# Bulk attribute search with filters
results = misp.search(
    type_attribute='md5',
    tags=['tlp:green'],
    date_from='2024-01-01',
    to_ids=True  # Only return IOCs marked for detection
)
```

#### MISP Feeds (Default)
| Feed Name | Source | Content |
|-----------|--------|---------|
| CIRCL OSINT | CIRCL | General threat intelligence |
| abuse.ch URLhaus | abuse.ch | Malware URLs and payloads |
| abuse.ch Feodo Tracker | abuse.ch | Botnet C2 IPs (Emotet, Dridex, TrickBot) |
| Botvrij.eu | Botvrij | IOC collections from public reports |
| ESET | ESET Research | Malware campaign IOCs |

---

### 2.2 OpenCTI

OpenCTI (Open Cyber Threat Intelligence Platform) is a newer open-source TIP built natively on STIX 2.1, developed by Filigran with backing from ANSSI (French CERT).

#### Architecture
- **Native STIX 2.1**: All objects stored as STIX SDOs/SCOs/SROs
- **GraphQL API**: Flexible query language for complex relationship traversal
- **Elasticsearch**: Full-text search across all objects
- **MinIO/S3**: Artifact storage for malware samples and reports
- **RabbitMQ**: Async connector message bus

#### Connector Ecosystem
```
Import Connectors:         Export Connectors:         Enrichment Connectors:
+-- MITRE ATT&CK           +-- STIX 2.1               +-- VirusTotal
+-- MISP                   +-- CSV                    +-- Shodan
+-- AlienVault OTX         +-- MISP                   +-- AbuseIPDB
+-- Mandiant               +-- OpenCTI Report         +-- Greynoise
+-- Recorded Future                                    +-- URLScan
+-- CISA KEV
```

#### OpenCTI Python Client
```python
from pycti import OpenCTIApiClient

opencti = OpenCTIApiClient('https://opencti.example.com', 'API_TOKEN')

# Create a threat actor
threat_actor = opencti.threat_actor_group.create(
    name="APT29",
    description="Russian SVR-linked espionage actor",
    aliases=["Cozy Bear", "The Dukes", "Midnight Blizzard"],
    sophistication="advanced",
    resource_level="government"
)

# Create malware and link to actor
malware = opencti.malware.create(
    name="SUNBURST",
    is_family=False,
    description="SolarWinds supply chain backdoor"
)

# Create relationship: threat actor uses malware
opencti.stix_core_relationship.create(
    fromId=threat_actor['id'],
    toId=malware['id'],
    relationship_type='uses'
)

# Search for indicators
indicators = opencti.indicator.list(
    filters=[{"key": "pattern_type", "values": ["stix"]}],
    search="evil.com"
)
```

---

### 2.3 ThreatConnect

ThreatConnect is a commercial TIP with a tiered intelligence model and built-in workflow automation (Playbooks).

#### Intelligence Hierarchy
```
Knowledge (contextualized, finished intelligence)
    ^
Intelligence (analyzed, correlated data with confidence)
    ^
Information (enriched, tagged IOCs with context)
    ^
Data (raw IOCs: hashes, IPs, domains, URLs)
    ^
Raw Data (unstructured feeds, reports, logs)
```

#### Key Features
- **Playbooks**: Low-code automation workflows for enrichment, scoring, and distribution
- **CAL (Collective Analytics Layer)**: Community-based IOC scoring using telemetry from ThreatConnect customers
- **STIX/TAXII**: Native import/export for interoperability
- **REST API**: Full CRUD operations on all intelligence objects
- **Tags & Associations**: Link IOCs to actors, campaigns, and incidents

---

### 2.4 Recorded Future

Recorded Future uses machine learning to collect and analyze intelligence from open web, dark web, and technical sources at scale.

#### Data Sources
- **Open Web**: News sites, blogs, paste sites, code repositories, social media
- **Dark Web**: Forums, marketplaces, ransomware leak sites, Telegram channels
- **Technical Sources**: Malware sandboxes, DNS data, certificate transparency, WHOIS
- **Premium Sources**: Analyst-curated reports, vulnerability databases

#### Key APIs
```bash
# IP Risk Score and context
GET https://api.recordedfuture.com/v2/ip/{ip}?fields=risk,intelCard,metrics
Authorization: Token RF_API_KEY

# Domain intelligence
GET https://api.recordedfuture.com/v2/domain/{domain}?fields=risk,relatedEntities

# Hash intelligence
GET https://api.recordedfuture.com/v2/hash/{hash}?fields=risk,timestamps,intelCard

# Playbook Alerts (proactive notifications)
GET https://api.recordedfuture.com/v2/alert/search
```

#### Threat Intelligence Cards
Each entity (IP, domain, hash, vulnerability, actor) has a Threat Intelligence Card with:
- **Risk Score** (0-100): ML-calculated based on observed evidence
- **Risk Rules**: Specific risk indicators that contributed to the score
- **Timeline**: Historical activity and first/last seen dates
- **Related Entities**: Linked actors, campaigns, malware families
- **Raw Intelligence**: Source references for analyst review

---

### 2.5 Anomali ThreatStream

Anomali ThreatStream focuses on aggregating and operationalizing threat feeds across a large ecosystem.

#### Key Capabilities
- **STIX/TAXII Ingestion**: Automated ingestion from hundreds of commercial and open-source feeds
- **Threat Bulletin Creation**: Analyst-authored reports with linked IOCs for team consumption
- **Actor Library**: Pre-populated actor profiles with associated IOCs and campaigns
- **ThreatStream Integrations**: Native connectors to Splunk, QRadar, Palo Alto, Cisco, etc.
- **Confidence Scoring**: Automated scoring based on feed source reliability and corroboration
- **Expiration Management**: Automatic IOC aging and removal based on configured TTLs

---

## 3. STIX & TAXII Standards

### 3.1 STIX 2.1 Overview

Structured Threat Information eXpression (STIX) is the de facto standard for machine-readable threat intelligence, maintained by OASIS. Version 2.1 introduced several new object types and relationship enhancements over 2.0.

---

### 3.2 STIX Domain Objects (SDOs)

STIX 2.1 defines 18 SDOs representing core intelligence concepts:

| SDO | Description | Key Properties |
|-----|-------------|----------------|
| **Attack-Pattern** | TTPs describing how attacks are carried out | name, description, external_references (ATT&CK ID) |
| **Campaign** | Grouping of adversary activity over time | name, aliases, first_seen, last_seen, objective |
| **Course-of-Action** | Recommended defensive action | name, description, action_bin |
| **Grouping** | Collection of STIX objects with shared context | name, context, object_refs |
| **Identity** | Organizations, individuals, or systems | name, identity_class, sectors, contact_information |
| **Indicator** | Pattern for detecting threats | name, pattern, pattern_type, valid_from, valid_until |
| **Infrastructure** | Systems used for adversary operations | name, infrastructure_types (C2, phishing, botnet) |
| **Intrusion-Set** | Named cluster of related adversary activity | name, aliases, goals, resource_level, primary_motivation |
| **Location** | Geographic or logical location | name, region, country, city, latitude, longitude |
| **Malware** | Malicious code and its characteristics | name, is_family, malware_types, capabilities, architecture |
| **Malware-Analysis** | Results of malware analysis | product, version, result, analysis_sco_refs |
| **Note** | Analyst commentary on STIX objects | content, authors, object_refs |
| **Observed-Data** | Raw observed data from sensors | first_observed, last_observed, number_observed, object_refs |
| **Opinion** | Analyst assessment of STIX content | opinion (strongly-disagree to strongly-agree), explanation |
| **Report** | Collection of intelligence on a topic | name, published, report_types, object_refs |
| **Threat-Actor** | Actors or groups behind intrusions | name, threat_actor_types, aliases, sophistication, goals |
| **Tool** | Legitimate software used for malicious purposes | name, tool_types, aliases, tool_version |
| **Vulnerability** | A security weakness | name, description, external_references (CVE) |

---

### 3.3 STIX Cyber-Observable Objects (SCOs)

SCOs represent actual observed data (not intelligence assertions):

| SCO | Key Properties | Example |
|-----|----------------|---------|
| **Domain-Name** | value | `evil-update.com` |
| **Email-Message** | from_ref, to_refs, subject, body | Phishing email content |
| **File** | name, hashes (MD5/SHA-1/SHA-256), size, mime_type | Malware sample metadata |
| **IPv4-Addr** | value | `192.0.2.1` |
| **IPv6-Addr** | value | `2001:db8::1` |
| **Network-Traffic** | src_ref, dst_ref, dst_port, protocols | C2 connection |
| **Process** | pid, name, command_line, created_time | Malicious process |
| **URL** | value | `https://evil.com/payload.exe` |
| **User-Account** | user_id, account_type, display_name | Compromised credential |
| **Windows-Registry-Key** | key, values | Persistence registry key |
| **Artifact** | mime_type, payload_bin (base64) | Raw file content |

---

### 3.4 STIX Relationship Objects (SROs)

Standard relationship types linking SDOs and SCOs:

| Relationship | Source | Target | Meaning |
|---|---|---|---|
| `uses` | Threat-Actor, Campaign, Intrusion-Set | Tool, Malware, Attack-Pattern | Actor employs TTPs |
| `indicates` | Indicator | Malware, Attack-Pattern, Campaign | IOC suggests threat |
| `attributed-to` | Campaign, Intrusion-Set | Threat-Actor | Cluster attributed to actor |
| `targets` | Threat-Actor, Campaign | Identity, Vulnerability, Location | Actor targets victim |
| `mitigates` | Course-of-Action | Attack-Pattern, Vulnerability | Control reduces risk |
| `subtechnique-of` | Attack-Pattern | Attack-Pattern | ATT&CK sub-technique link |
| `related-to` | Any | Any | Generic association |
| `impersonates` | Threat-Actor | Identity | Actor masquerades as entity |
| `exploits` | Malware | Vulnerability | Malware exploits CVE |
| `delivers` | Malware | Malware | Dropper delivers payload |

---

### 3.5 Python stix2 Library

```python
import stix2
from datetime import datetime, timezone

# Create an Indicator
indicator = stix2.Indicator(
    name="APT29 C2 Domain",
    description="Known APT29 command and control domain observed in StellarParticle campaign",
    pattern="[domain-name:value = 'update-secure-cdn.net']",
    pattern_type='stix',
    valid_from=datetime(2024, 1, 15, tzinfo=timezone.utc),
    valid_until=datetime(2024, 4, 15, tzinfo=timezone.utc),
    labels=['malicious-activity', 'attribution:apt29'],
    confidence=85,
    external_references=[
        stix2.ExternalReference(
            source_name='mitre-attack',
            external_id='G0016',
            url='https://attack.mitre.org/groups/G0016/'
        )
    ]
)

# Create a Threat Actor
threat_actor = stix2.ThreatActor(
    name="APT29",
    aliases=["Cozy Bear", "The Dukes", "Midnight Blizzard", "Nobelium"],
    threat_actor_types=["nation-state"],
    sophistication="advanced",
    resource_level="government",
    primary_motivation="organizational-gain",
    goals=["Espionage", "Intelligence collection"]
)

# Create relationship: indicator indicates threat actor
relationship = stix2.Relationship(
    relationship_type='indicates',
    source_ref=indicator.id,
    target_ref=threat_actor.id
)

# Bundle for distribution
bundle = stix2.Bundle(objects=[indicator, threat_actor, relationship])
json_output = bundle.serialize(pretty=True)
print(json_output)

# Parse incoming STIX bundle
incoming_bundle = stix2.parse(json_string, allow_custom=True)
for obj in incoming_bundle.objects:
    if obj.type == 'indicator':
        print(f"IOC: {obj.pattern} | Valid until: {obj.valid_until}")
```

---

### 3.6 TAXII 2.1

Trusted Automated eXchange of Intelligence Information (TAXII) is the transport protocol for STIX content, also maintained by OASIS.

#### TAXII Architecture
```
TAXII Server
+-- API Root: /taxii2/                    (discovery endpoint)
|   +-- Collection: /collections/         (list available collections)
|   |   +-- {id}/objects/                 (GET/POST STIX objects)
|   |   +-- {id}/manifest/               (GET object manifests)
|   |   +-- {id}/envelopes/              (POST to add objects)
```

#### taxii2client Usage
```python
from taxii2client.v21 import Server, Collection

# Connect to TAXII server
server = Server(
    'https://taxii.example.com/taxii2/',
    user='analyst',
    password='secret'
)

# List available API roots
for api_root in server.api_roots:
    print(f"API Root: {api_root.title}")
    for collection in api_root.collections:
        print(f"  Collection: {collection.title} | ID: {collection.id}")

# Pull STIX objects from collection
collection = Collection(
    'https://taxii.example.com/taxii2/root/collections/indicators/',
    user='analyst',
    password='secret'
)

# GET with filters
objects = collection.get_objects(
    added_after='2024-01-01T00:00:00Z',
    match_type=['indicator']
)

for obj in objects.get('objects', []):
    print(f"Type: {obj['type']} | ID: {obj['id']}")

# PUSH objects to TAXII server
bundle = stix2.Bundle(objects=[indicator, relationship])
collection.add_objects(bundle)
```

#### Major TAXII Endpoints
| Source | URL | Content |
|--------|-----|---------|
| MITRE ATT&CK | `https://attack-taxii.mitre.org/taxii2/` | ATT&CK Enterprise/Mobile/ICS |
| CISA AIS | `https://ais2.cisa.dhs.gov/` | US Government TI sharing |
| Anomali LIMO | `https://limo.anomali.com/api/v1/taxii2/` | Free open-source STIX/TAXII |

---

## 4. IOC Management & Enrichment

### 4.1 IOC Types and Context

#### IP Addresses
IP address intelligence requires contextual enrichment beyond simple blacklist matching:

```bash
# Shodan infrastructure context
curl -s "https://api.shodan.io/shodan/host/192.0.2.1?key=API_KEY" | jq '{
  org: .org,
  isp: .isp,
  country: .country_name,
  open_ports: .ports,
  hostnames: .hostnames,
  tags: .tags,
  vulns: .vulns
}'

# Passive DNS (CIRCL)
curl -s "https://www.circl.lu/pdns/query/192.0.2.1" | jq '.[]| {rrtype, rrname, rdata, time_last}'

# AbuseIPDB check
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=192.0.2.1&maxAgeInDays=90" \
  -H "Key: API_KEY" -H "Accept: application/json"
```

**Key Context Fields for IPs**:
- Hosting provider / ASN (bulletproof ASNs indicate higher risk)
- Open ports and banners (Cobalt Strike indicators: `Server: Cobalt Strike Beacon`)
- Passive DNS history (how many domains have resolved to this IP)
- First seen / last seen in threat intel
- Geolocation vs. claimed organization geography

#### Domain Names
```bash
# WHOIS data
curl -s "https://api.whoisxmlapi.com/whoisserver/WhoisService?domainName=evil.com&apiKey=KEY&outputFormat=JSON"

# DNS history via SecurityTrails
curl -s "https://api.securitytrails.com/v1/history/evil.com/dns/a" \
  -H "APIKEY: YOUR_KEY"

# Certificate transparency (subdomain enumeration)
curl -s "https://crt.sh/?q=%.evil.com&output=json" | jq '.[].name_value' | sort -u

# DGA detection indicators:
# - High entropy name (>3.5 bits/char suggests DGA)
# - No meaningful words in name
# - Registered very recently
# - Resolves to rotating IPs
# - Low Alexa/Tranco rank or unranked

python3 -c "
import math
domain = 'xkqzjmvprtlbnw.com'
freq = {c: domain.count(c)/len(domain) for c in set(domain) if c != '.'}
entropy = -sum(p * math.log2(p) for p in freq.values())
print(f'Entropy: {entropy:.2f} bits/char')
"
```

#### File Hashes
```python
import requests

# VirusTotal v3 file analysis
def vt_hash_lookup(sha256, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers)
    data = r.json()['data']['attributes']
    return {
        'name': data.get('meaningful_name'),
        'family': data.get('popular_threat_classification', {}).get('suggested_threat_label'),
        'detection_ratio': f"{data['last_analysis_stats']['malicious']}/{sum(data['last_analysis_stats'].values())}",
        'first_seen': data.get('first_submission_date'),
        'imphash': data.get('pe_info', {}).get('imphash'),
        'ssdeep': data.get('ssdeep')
    }

# ssdeep fuzzy hash similarity
import ssdeep
similarity = ssdeep.compare(hash1, hash2)  # Returns 0-100
print(f"Similarity: {similarity}%")  # >50 often indicates same family
```

---

### 4.2 IOC Lifecycle Management

```
Collection -> Validation -> Scoring -> Enrichment -> Distribution -> Review -> Expiry
    |              |            |           |              |           |         |
  Feeds          Remove      Admiralty    Add context   SIEM/TIP    FP rate   Archive
  Reports        FP/private   Code        enrich        Firewall    review    or extend
  Hunting        space IPs    weights     store         Blocklist   scoring   TTL
```

**Recommended TTLs by IOC Type**:
| IOC Type | Default TTL | Extended TTL | Notes |
|----------|-------------|--------------|-------|
| IPv4 Addresses | 7 days | 30 days | Rotate frequently; bulletproof hosting longer |
| IPv6 Addresses | 7 days | 30 days | Same as IPv4 |
| Domain Names | 30 days | 90 days | Registration cost creates delay in rotation |
| URLs | 14 days | 45 days | Often short-lived phishing/payload delivery |
| File Hashes (MD5/SHA) | 365 days | Indefinite | Immutable -- file does not change |
| YARA Rules | Indefinite | N/A | Behavioral -- update when actor retools |
| Network Signatures | Indefinite | N/A | Update when protocol changes |
| Email Addresses | 90 days | 365 days | Depends on campaign activity |

---

### 4.3 Automated Enrichment Pipeline

```python
import asyncio
import aiohttp

class IOCEnricher:
    def __init__(self, vt_key, shodan_key, abuseipdb_key):
        self.vt_key = vt_key
        self.shodan_key = shodan_key
        self.abuseipdb_key = abuseipdb_key

    async def enrich_ip(self, session, ip):
        results = {'ioc': ip, 'type': 'ip'}

        # AbuseIPDB
        async with session.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": self.abuseipdb_key}
        ) as r:
            if r.status == 200:
                data = await r.json()
                results['abuse_score'] = data['data']['abuseConfidenceScore']
                results['isp'] = data['data']['isp']

        # VirusTotal
        async with session.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.vt_key}
        ) as r:
            if r.status == 200:
                data = await r.json()
                stats = data['data']['attributes']['last_analysis_stats']
                results['vt_malicious'] = stats.get('malicious', 0)
                results['vt_total'] = sum(stats.values())

        return results

    async def enrich_batch(self, ioc_list):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for ioc in ioc_list:
                if ioc['type'] == 'ip':
                    tasks.append(self.enrich_ip(session, ioc['value']))
            return await asyncio.gather(*tasks)
```

---

### 4.4 IOC Scoring -- Admiralty Code

The Admiralty Code (NATO standardized) provides a structured way to rate source reliability and information credibility:

**Source Reliability (A-F)**:
| Rating | Description | Examples |
|--------|-------------|----------|
| A | Completely reliable | Own sensors, trusted government partner |
| B | Usually reliable | Established ISAC feeds, government advisories |
| C | Fairly reliable | Commercial TI vendors, sector peers |
| D | Not usually reliable | Anonymous feeds, unvetted OSINT |
| E | Unreliable | Single unvetted source, anonymous tip |
| F | Reliability cannot be judged | New source, no track record |

**Information Credibility (1-6)**:
| Rating | Description |
|--------|-------------|
| 1 | Confirmed by other sources |
| 2 | Probably true |
| 3 | Possibly true |
| 4 | Doubtful |
| 5 | Improbable |
| 6 | Truth cannot be judged |

**Composite IOC Score Formula** (example weighting):
```
score = (source_reliability * 0.4) + (info_credibility * 0.3) +
        (freshness * 0.2) + (corroboration_count * 0.1)

where:
  source_reliability: 1.0=A, 0.8=B, 0.6=C, 0.4=D, 0.2=E, 0.1=F
  info_credibility:   1.0=1, 0.8=2, 0.6=3, 0.4=4, 0.2=5, 0.1=6
  freshness:          1.0 if <24h, 0.8 if <7d, 0.6 if <30d, 0.4 if <90d
  corroboration:      0.1 per additional source confirming, max 1.0
```

---

## 5. Threat Actor Tracking & Attribution

### 5.1 Naming Conventions

Multiple vendors maintain their own actor naming schemes. Cross-referencing is critical:

#### CrowdStrike Adversary Naming (Animal-Based)
| Nation-State | Animal | Examples |
|---|---|---|
| Russia | BEAR | Fancy Bear (APT28), Cozy Bear (APT29), Voodoo Bear |
| China | PANDA | Gothic Panda, Wicked Panda (APT41), Stone Panda |
| North Korea | CHOLLIMA | Lazarus = Labyrinth Chollima, Stardust Chollima |
| Iran | KITTEN | Charming Kitten (APT35), Refined Kitten (APT33) |
| eCrime | SPIDER | Wizard Spider (Ryuk/TrickBot), Carbon Spider (FIN7) |
| Hacktivists | JACKAL | Corsair Jackal, Ghost Jackal |

#### Mandiant/Google Threat Intelligence Naming
- **APT1-APT41+**: Nation-state actors (APT = Advanced Persistent Threat)
  - APT1: China, PLA Unit 61398, Comment Crew
  - APT29: Russia SVR, Cozy Bear, Midnight Blizzard
  - APT41: China, dual-nexus espionage + financial crime
- **FIN1-FIN13**: Financially motivated threat actors
  - FIN7: POS attacks, Carbanak banking trojan
  - FIN11: Cl0p ransomware affiliation
- **UNC (Uncategorized)**: New clusters not yet merged into named groups

#### Microsoft Threat Actor Naming (Element-Based, 2023+)
| Nation-State | Element | Old Name Examples |
|---|---|---|
| Russia | BLIZZARD | Midnight Blizzard (was Nobelium/APT29) |
| China | TYPHOON | Volt Typhoon, Salt Typhoon |
| North Korea | SLEET | Emerald Sleet (was Thallium) |
| Iran | SANDSTORM | Peach Sandstorm (was Holmium/APT33) |
| eCrime | TEMPEST | Octo Tempest (was 0ktapus/Scattered Spider) |
| Influence Ops | FLOOD | Spamouflage, STORM- prefix for developing clusters |

#### MITRE ATT&CK Groups
MITRE maintains vendor-neutral group entries that aggregate cross-vendor names:
- Each group (G0001-G0XXX) lists aliases from all major vendors
- Linked to ATT&CK techniques used (software, techniques, campaigns)
- Reference: `https://attack.mitre.org/groups/`

---

### 5.2 Attribution Methodology

Attribution is probabilistic, not binary. Analysts must be explicit about confidence levels.

#### TTP Overlap Analysis
```python
# Simplified TTP similarity scoring
known_actor_ttps = {
    'APT29': {'T1566.001', 'T1078', 'T1021.001', 'T1550.002', 'T1560.001',
               'T1005', 'T1071.001', 'T1027', 'T1036.005'},
    'APT28': {'T1566.001', 'T1059.001', 'T1053.005', 'T1027', 'T1105',
               'T1074.001', 'T1090', 'T1583.001'}
}

observed_ttps = {'T1566.001', 'T1078', 'T1021.001', 'T1550.002', 'T1071.001', 'T1027'}

def ttp_similarity(observed, actor_ttps):
    overlap = observed & actor_ttps
    # Jaccard similarity
    jaccard = len(overlap) / len(observed | actor_ttps)
    # Coverage of observed TTPs
    coverage = len(overlap) / len(observed)
    return {'jaccard': jaccard, 'coverage': coverage, 'shared_ttps': list(overlap)}

for actor, ttps in known_actor_ttps.items():
    score = ttp_similarity(observed_ttps, ttps)
    print(f"{actor}: Jaccard={score['jaccard']:.2f} Coverage={score['coverage']:.2f}")
# APT29: Jaccard=0.50 Coverage=0.83  <- strong overlap, likely candidate
```

**Rule of thumb**: >70% TTP overlap with a known actor's documented playbook suggests same or related actor. Always corroborate with additional evidence.

#### Infrastructure Reuse Analysis
```bash
# Find related infrastructure via passive DNS
# If new malicious domain resolves to known bad IP, pivot:
# 1. Query passive DNS for the IP -- find other domains hosted there
# 2. Check those domains against threat intelligence
# 3. Look for registration patterns (same registrar, name server, registrant)

# Shodan pivot from known C2 banner
shodan search 'Server: Cobalt Strike Beacon' --fields ip_str,port,org,hostnames
```

#### Malware Code Similarity
| Method | Tool | What It Finds |
|--------|------|---------------|
| Import hash (imphash) | VirusTotal, YARA | Same compiler/linker toolchain |
| Binary diff | BinDiff, Diaphora | Code-level similarity between binaries |
| YARA family rules | Custom YARA | Same string artifacts, code patterns |
| PDB paths | PEStudio, DIE | Developer workstation artifacts |
| Rich header hash | pefile Python | Compiler version and tool fingerprint |
| TLSH fuzzy hash | TLSH, VT similarity | Similar-but-modified samples |

#### OPSEC Failure Indicators
Attribution accelerators when actors make mistakes:
- **Language artifacts**: Error messages in native language, Cyrillic/Chinese strings in binaries, comments in code
- **Metadata**: Compilation timestamps in local timezone (correlate to UTC offset of target country)
- **Infrastructure overlap**: Reusing C2 infrastructure across campaigns (can pivot via passive DNS)
- **Tool reuse**: Unique custom tools reappearing in new campaigns (high confidence same actor)
- **Operator errors**: Direct-connect from non-proxied IP, VPN dropout revealing real IP in logs

---

### 5.3 Major Actor Profiles

#### APT29 / Cozy Bear / Midnight Blizzard (Russia -- SVR)
| Attribute | Detail |
|-----------|--------|
| **Attribution** | Russian Foreign Intelligence Service (SVR) |
| **Naming** | APT29 (Mandiant), Cozy Bear (CrowdStrike), Midnight Blizzard (Microsoft), The Dukes (ESET) |
| **Targeting** | Government, think tanks, defense, technology, healthcare |
| **Motivation** | Espionage / political intelligence |
| **Notable Campaigns** | SolarWinds (SUNBURST/TEARDROP 2020), StellarParticle (Microsoft 2023), DNC breach 2016 |
| **Signature TTPs** | Spearphishing -> OAuth token theft -> lateral movement via living-off-the-land -> slow data exfiltration |
| **Key Malware** | SUNBURST, BOOMBOX, WINGMAN, EnvyScout, ROOTSAW (HTML smuggling), MagicWeb (ADFS), HALFRIG |

#### APT41 / Winnti (China -- Dual Nexus)
| Attribute | Detail |
|-----------|--------|
| **Attribution** | Chinese Ministry of State Security (MSS) + eCrime |
| **Naming** | APT41 (Mandiant), Wicked Panda (CrowdStrike), Barium (Microsoft old) |
| **Targeting** | Healthcare, telecoms, technology, gaming, pharmaceuticals |
| **Motivation** | Espionage + financial gain (supply chain compromise for financial fraud) |
| **Notable Campaigns** | ShadowPad supply chain, Asus Live Update, multiple gaming company compromises |
| **Signature TTPs** | Supply chain compromise, ProxyLogon exploitation, custom rootkits |
| **Key Malware** | ShadowPad, Winnti, DUSTPAN, DUSTTRAP |

#### Lazarus Group / Labyrinth Chollima (DPRK)
| Attribute | Detail |
|-----------|--------|
| **Attribution** | North Korean Reconnaissance General Bureau (RGB) |
| **Naming** | Lazarus (most vendors), Labyrinth Chollima (CrowdStrike), HIDDEN COBRA (US Gov) |
| **Targeting** | Financial institutions, cryptocurrency exchanges, defense, media |
| **Motivation** | Sanctions evasion through cryptocurrency theft; regime funding |
| **Notable Campaigns** | Bangladesh Bank SWIFT heist ($81M), WannaCry 2017, Ronin Network ($625M crypto) |
| **Signature TTPs** | Job-themed spearphishing, custom tooling, SWIFT exploitation, crypto mixing |
| **Key Malware** | BLINDINGCAN, HOPLIGHT, AppleJeus, TraderTraitor toolset |

#### APT34 / OilRig (Iran -- MOIS)
| Attribute | Detail |
|-----------|--------|
| **Attribution** | Iranian Ministry of Intelligence and Security (MOIS) |
| **Naming** | APT34 (Mandiant), Helix Kitten (CrowdStrike), Cobalt Gypsy (SecureWorks) |
| **Targeting** | Middle East governments, energy, financial, telecom |
| **Motivation** | Regional espionage and domestic dissident tracking |
| **Notable Campaigns** | DNSpionage, OopsIE, Shamoon wiper support |
| **Signature TTPs** | Watering hole attacks, custom backdoors, DNS tunneling for C2 |
| **Key Malware** | POWRUNER, BONDUPDATER, Saitama, SideTwist |

#### FIN7 / Carbanak (eCrime)
| Attribute | Detail |
|-----------|--------|
| **Attribution** | Eastern European criminal organization |
| **Naming** | FIN7 (Mandiant), Carbon Spider (CrowdStrike), Sangria Tempest (Microsoft) |
| **Targeting** | Retail, hospitality, restaurant POS systems; later ransomware |
| **Motivation** | Financial -- card theft, banking fraud, ransomware |
| **Notable Campaigns** | Carbanak banking trojan ($1B+ stolen), Cl0p ransomware affiliation |
| **Signature TTPs** | Spearphishing with malicious DOCX, JScript, PowerShell fileless |
| **Key Malware** | Carbanak, Griffon, LOADOUT, PILLOWMINT, Cl0p ransomware |

---

### 5.4 Campaign Tracking Methodology

Structured campaign tracking enables historical analysis and future-activity prediction:

```
Campaign Record Structure:
+-- Name/Designation: Internal designation + external names
+-- Start Date / End Date (if concluded)
+-- Activity Status: Active / Dormant / Concluded
+-- Attributed Actor: Primary actor + confidence level
+-- Targeting:
|   +-- Sectors: [Government, Energy, Finance]
|   +-- Geographies: [US, EU, Middle East]
|   +-- Specific Orgs: [If known from reporting]
+-- TTPs: [ATT&CK technique IDs with evidence]
+-- Infrastructure: [C2 IPs, domains, hosting providers]
+-- Malware: [Family names, YARA rule refs, MalwareBazaar tags]
+-- IOCs: [Reference to IOC collection with expiry dates]
+-- References: [External reports, vendor advisories, CVEs]
+-- Timeline: [Chronological event log with sources]
```

---

## 6. OSINT for Threat Intelligence

### 6.1 Technical OSINT

#### Shodan -- Internet-Wide Scanner
```bash
# Search for Cobalt Strike C2 servers
shodan search 'product:"Cobalt Strike Beacon"' --fields ip_str,port,org,hostnames

# Search by SSL certificate characteristics
shodan search 'ssl.cert.subject.cn:"My Company" port:443'

# Find infrastructure with specific Cobalt Strike default cert
shodan search 'ssl.cert.serial:146473198' --fields ip_str,port,org

# JARM fingerprint for Cobalt Strike
shodan search 'ssl.jarm:07d14d16d21d21d00042d43d000000e4badf5f94e6fd7d6a82f3ba24f49e8c'

# Look up specific IP
shodan host 203.0.113.1

# Find Brute Ratel C4 infrastructure
shodan search '"Brute Ratel C4"'
```

#### Shodan Python API
```python
import shodan

api = shodan.Shodan('YOUR_API_KEY')

# Host lookup with full details
host = api.host('203.0.113.1')
print(f"Organization: {host.get('org', 'N/A')}")
for item in host['data']:
    print(f"Port: {item['port']}")
    print(f"Banner: {item['data'][:200]}")

# Search with facets
results = api.search('cobalt strike', facets=['country', 'org'])
print(f"Total results: {results['total']}")
for match in results['matches']:
    print(f"{match['ip_str']}:{match['port']} - {match.get('org', 'N/A')}")
```

#### Censys Search
```python
import censys.search

c = censys.search.CensysHosts()

# Search for specific service characteristics
query = 'services.tls.certificates.leaf_data.subject_dn:"O=Cobalt Strike"'
for host in c.search(query, fields=['ip', 'services.port', 'services.service_name']):
    print(host)
```

#### GreyNoise -- Separating Signal from Noise
```bash
# IP context: Is this internet background noise or targeted?
curl "https://api.greynoise.io/v3/community/203.0.113.1" \
  -H "key: API_KEY"

# Response interpretation:
# "noise": true   -> Mass internet scanner, likely not targeted
# "riot": true    -> Likely legitimate (Google, Cloudflare, etc.)
# "classification": "malicious" -> Known malicious actor

# Bulk IP check
curl -X POST "https://api.greynoise.io/v1/noise/multi/quick" \
  -H "key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ips": ["203.0.113.1", "198.51.100.1", "192.0.2.1"]}'
```

#### SecurityTrails -- DNS & WHOIS History
```bash
# DNS history for a domain
curl "https://api.securitytrails.com/v1/history/evil-domain.com/dns/a" \
  -H "APIKEY: YOUR_KEY"

# All subdomains
curl "https://api.securitytrails.com/v1/domain/evil-domain.com/subdomains" \
  -H "APIKEY: YOUR_KEY"

# Search by registrant email to pivot to other domains
curl "https://api.securitytrails.com/v1/domains/list" \
  -H "APIKEY: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"filter": {"whois_email": "attacker@protonmail.com"}}'
```

#### Certificate Transparency (crt.sh)
```bash
# Find all subdomains via cert transparency logs
curl -s 'https://crt.sh/?q=%.target-organization.com&output=json' | \
  jq -r '.[].name_value' | sort -u

# Find certs issued to suspicious entities
curl -s 'https://crt.sh/?q=%.suspicious-actor-domain.com&output=json' | \
  jq '.[] | {domain: .name_value, issued: .not_before, issuer: .issuer_name}'
```

---

### 6.2 Dark Web Intelligence

#### Monitoring Methodology
Dark web intelligence collection requires specialized tooling and strict OPSEC:

**Ransomware Leak Site Monitoring**:
```
Active leak sites (as of 2024) -- access via Tor:
+-- LockBit 3.0:   Victim listing + file previews before payment deadline
+-- BlackCat/ALPHV: Victim portal with countdown timers
+-- Cl0p:          Public victim lists + searchable leaked data
+-- Play:          Victim announcements + data samples
+-- Akira:         Searchable leak portal
+-- RansomHub:     Newer 2024 entrant with active victim listing
```

**Commercial Dark Web Monitoring Platforms**:
| Platform | Strengths | Coverage |
|----------|-----------|----------|
| Flashpoint | Forum monitoring, threat actor profiles, marketplace data | Extensive deep/dark web |
| Kela (Cybersixgill) | Real-time forum posts, credential monitoring, actor tracking | Strong dark web forums |
| Digital Shadows (ReliaQuest) | Brand protection, data breach monitoring, executive tracking | Mixed OSINT + dark web |
| Recorded Future | Integrated with open/technical intel, dark web as one source | Comprehensive |

**Telegram Channel Intelligence**:
- Ransomware groups operate Telegram channels for victim announcements
- Initial access brokers advertise access in cybercriminal channels
- Malware authors sell stealer logs via Telegram bots
- Monitoring approach: dedicated burner accounts, never interact with criminal channels

---

### 6.3 Social Media CTI

#### Twitter/X for Real-Time Threat Intelligence
Key search strategies:
```bash
# Search operators for threat intelligence
"#malware"             # Malware sample shares
"c2" OR "c&c"          # Command and control discussion
"SHA256"               # Hash sharing
"IOC" OR "indicators"  # IOC sharing posts
"CVE-2024"             # Current CVE discussion
"0day" OR "0-day"      # Zero-day discussions
"ransomware"           # Active ransomware tracking
```

Key CTI community accounts: @malwrhunterteam, @James_inthe_box, @threatintel, @Unit42_Intel, @MsftSecIntel, @campuscodi, @BushidoToken, @vxunderground

#### Mastodon / Infosec.exchange
The security community has migrated significantly to Mastodon:
- `infosec.exchange` -- primary security-focused Mastodon instance
- `ioc.exchange` -- dedicated IOC sharing instance
- Search hashtags: `#threatintel`, `#malware`, `#IOC`, `#CTI`

---

### 6.4 OSINT OPSEC for Threat Intelligence Analysts

Protecting analyst identity and avoiding tipping off threat actors is critical:

#### Technical OPSEC
```
Dedicated Research Environment:
+-- Isolated VM (VirtualBox/VMware with snapshots)
|   +-- Separate browser profile with no personal data
|   +-- uBlock Origin, privacy badger installed
|   +-- JavaScript disabled for unknown .onion sites
+-- VPN -> Tor for sensitive research
|   +-- Never access dark web without Tor
+-- Sock puppet accounts for forum research
|   +-- Aged accounts, consistent backstory, different email provider
+-- Evidence preservation:
    +-- Hunchly browser extension (automatic archiving)
    +-- archive.org/save for web pages
    +-- Screenshot with timestamp + hash for legal evidence

Common OPSEC Failures:
X Accessing attacker infrastructure from corporate IP
X Downloading malware samples on unprotected systems
X Creating research accounts on personal email
X Visiting C2 URLs -- this confirms the C2 is being monitored
X Interacting with dark web actors without cover identity
```

#### Avoiding Actor Tipping
- Never visit known C2 infrastructure from a corporate or identifiable IP
- When investigating phishing pages, use a residential proxy or Tor
- Do not download files from attacker-controlled infrastructure directly
- Use VirusTotal, URLScan, or sandboxes to safely examine content
- Be aware that sophisticated actors track visits to their infrastructure (unique URLs per target, honeypot files)

---

## 7. Malware Intelligence for CTI

### 7.1 Malware Intelligence Sources

#### MalwareBazaar (abuse.ch)
```bash
# Search by tag
curl -s -X POST "https://mb.abuse.ch/api/v1/" \
  -d "query=get_taginfo&tag=Cobalt%20Strike&limit=100"

# Get specific sample by SHA256
curl -s -X POST "https://mb.abuse.ch/api/v1/" \
  -d "query=get_file&sha256_hash=SHA256_HASH_HERE"

# Search recent samples by file type
curl -s -X POST "https://mb.abuse.ch/api/v1/" \
  -d "query=get_recent&selector=dll"

# Download sample (requires API key)
curl -s -X POST "https://mb.abuse.ch/api/v1/" \
  -H "Auth-Key: YOUR_API_KEY" \
  -d "query=download_file&sha256_hash=SHA256_HASH_HERE" \
  --output malware_sample.zip
```

#### VirusTotal Intelligence
```python
import requests

VT_KEY = "YOUR_VT_API_KEY"
HEADERS = {"x-apikey": VT_KEY}

# File analysis with rich metadata
def get_file_report(sha256):
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=HEADERS)
    data = r.json()['data']['attributes']
    return {
        'family': data.get('popular_threat_classification', {}).get('suggested_threat_label'),
        'first_seen': data.get('first_submission_date'),
        'detections': data['last_analysis_stats']['malicious'],
        'imphash': data.get('pe_info', {}).get('imphash'),
        'sections': [s['name'] for s in data.get('pe_info', {}).get('sections', [])],
        'imports': list(data.get('pe_info', {}).get('import_list', {}).keys())[:10]
    }

# Get network IOCs from file relationships
def get_file_network_iocs(sha256):
    iocs = {'ips': [], 'domains': [], 'urls': []}
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}/contacted_ips", headers=HEADERS)
    iocs['ips'] = [ip['id'] for ip in r.json().get('data', [])]
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}/contacted_domains", headers=HEADERS)
    iocs['domains'] = [d['id'] for d in r.json().get('data', [])]
    return iocs

# VT Hunting -- Live YARA hunt on new submissions
def create_live_hunt(yara_rule):
    r = requests.post(
        "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets",
        headers=HEADERS,
        json={"data": {"attributes": {"name": "CTI Hunt", "rules": yara_rule, "enabled": True}}}
    )
    return r.json()

# Retrohunt -- historical hunt over VT corpus
def start_retrohunt(yara_rule):
    r = requests.post(
        "https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs",
        headers=HEADERS,
        json={"data": {"attributes": {"rules": yara_rule, "corpus": "main", "time_range": "90d"}}}
    )
    return r.json()
```

#### Malpedia
```bash
# Malpedia API -- family database with samples and references
BASE="https://malpedia.caad.fkie.fraunhofer.de/api"

# List all malware families
curl -s "$BASE/list/families"

# Get family details
curl -s "$BASE/get/family/win.cobalt_strike"

# Get YARA rules for a family
curl -s "$BASE/get/yara/family/win.cobalt_strike"

# Get actors associated with a family
curl -s "$BASE/get/family/win.cobalt_strike" | jq '.actors'
```

---

### 7.2 YARA Rules for CTI Hunting

YARA is the de facto standard for malware detection and threat hunting:

```yara
import "pe"
import "math"

rule APT29_SUNBURST_Backdoor
{
    meta:
        description = "Detects SUNBURST backdoor used in SolarWinds campaign"
        author = "CTI Team"
        date = "2024-01-15"
        hash = "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"
        mitre_attack = "T1195.002, T1078, T1071.001"
        tlp = "TLP:WHITE"

    strings:
        $s1 = "SolarWinds.Orion.Core.BusinessLayer.dll" ascii wide
        $s2 = "avsvmcloud.com" ascii wide nocase
        $s3 = "OrionImprovementBusinessLayer" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.is_dll() and
        (
            ($s1 and $s2) or
            ($s3) or
            (2 of ($s*))
        )
}

rule CobaltStrike_Beacon_Config
{
    meta:
        description = "Detects Cobalt Strike Beacon configuration block"
        author = "CTI Team"
        date = "2024-01-20"
        mitre_attack = "T1059.001, T1055, T1071.001"

    strings:
        $config_magic = { 00 01 00 01 00 02 ?? ?? 00 02 00 02 }
        $cs1 = "%s as %s\\%s" ascii wide
        $cs2 = "IEX (New-Object Net.Webclient).DownloadString" ascii wide
        $cs3 = "beacon.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $config_magic or
            (2 of ($cs*))
        )
}

rule Generic_DGA_Candidate
{
    meta:
        description = "Detects potential DGA domain generation algorithm artifacts"
        author = "CTI Team"

    strings:
        $seed1 = "getaddrinfo" ascii
        $date_format = { 25 59 25 6D 25 64 }
        $tld_array = { 2E 63 6F 6D 00 2E 6E 65 74 00 2E 6F 72 67 00 }

    condition:
        uint16(0) == 0x5A4D and
        $seed1 and
        ($date_format or $tld_array) and
        math.entropy(0, filesize) > 7.0
}
```

#### YARA Rule Libraries
| Source | Repository | Content |
|--------|-----------|---------|
| Florian Roth / Neo23x0 | `github.com/Neo23x0/signature-base` | Broad malware detection rules |
| Elastic Security | `github.com/elastic/protections-artifacts` | Endpoint protection YARA |
| CISA | `github.com/cisagov/` | Government-curated rules |
| AlienVault OTX | OTX platform export | Community-contributed rules |

---

### 7.3 Malware Config Extraction for CTI

Extracting configurations from malware samples reveals current C2 infrastructure:

```python
# CAPE (Community Automated Malware Platform) API
import requests

CAPE_URL = "https://cape.contextis.com"

# Submit sample for analysis
def submit_sample(filepath):
    with open(filepath, 'rb') as f:
        r = requests.post(f"{CAPE_URL}/api/tasks/create/file/",
                         files={"file": f},
                         data={"options": "procmemdump=1", "package": "auto"})
    return r.json()['data']['task_ids'][0]

# Get extracted config
def get_config(task_id):
    r = requests.get(f"{CAPE_URL}/api/tasks/get/config/{task_id}/")
    return r.json()
```

#### C2 Infrastructure Tracking Workflow
```
1. Obtain malware sample (MalwareBazaar, sandbox report, incident)
       |
2. Extract config (CAPE, CAPEv2, manual RE, MalConf/Volatility)
       |
3. Identify C2 domains/IPs from config
       |
4. Pivot on infrastructure (passive DNS, Shodan, Censys)
       |
   +-- Find other domains/IPs on same server (related C2)
   +-- Track certificate changes (actor may reuse same cert)
   +-- Monitor for new samples connecting to same C2
       |
5. Add to TIP with expiry dates and campaign linkage
       |
6. Distribute to SIEM/firewall/DNS blocklist
       |
7. Monitor for infrastructure rotation -> repeat from step 3
```

---

### 7.4 Malware Family Tracking Dashboard

| Family | Platform | Category | Primary TI Sources | Config Extract |
|--------|----------|----------|-------------------|----------------|
| Cobalt Strike | Windows | Post-exploit framework | MalwareBazaar, VT Hunt | cs-decrypt-metadata, CAPE |
| Emotet | Windows | Banking Trojan/Dropper | Abuse.ch Feodo Tracker | CAPE, Malpedia |
| QakBot/Qbot | Windows | Banking Trojan | MalwareBazaar tag:Qakbot | CAPE |
| BruteRatel C4 | Windows | Post-exploit framework | Shodan, VT | CAPE |
| Sliver | Cross-platform | Post-exploit framework | GitHub, Shodan | Config embedded |
| AsyncRAT | Windows | Remote Access Trojan | MalwareBazaar tag:asyncrat | Automatic extractor |
| RedLine Stealer | Windows | Infostealer | MalwareBazaar, darkweb | CAPE, config extract |
| LockBit 3.0 | Windows | Ransomware | Leak site monitoring | N/A (encryptor) |

---

## 8. Threat Intelligence Sharing

### 8.1 Sharing Communities and ISACs

Information Sharing and Analysis Centers (ISACs) are sector-specific sharing communities:

| ISAC | Sector | Platform | Notes |
|------|--------|----------|-------|
| **FS-ISAC** | Financial Services | Portal + STIX/TAXII | Largest, most mature; includes banking, insurance |
| **H-ISAC** | Healthcare | Portal + threat feeds | Ransomware focus; critical infrastructure |
| **E-ISAC** | Electricity | Portal + CRISP program | Grid security; interconnects with NERC |
| **Auto-ISAC** | Automotive | Portal | OT/vehicle cybersecurity |
| **Aviation ISAC** | Aviation | Portal | ATC and airline cybersecurity |
| **IT-ISAC** | IT Sector | Portal + feeds | Technology companies |
| **MS-ISAC** | State/Local Gov | Portal + Albert sensors | CISA-funded; free for SLTT |
| **WaterISAC** | Water Sector | Portal | Critical infrastructure |

#### Government Sharing Programs
```
CISA Automated Indicator Sharing (AIS):
+-- Free STIX/TAXII feed for US organizations
+-- Enrollment: https://www.cisa.gov/ais
+-- TAXII 2.x server: ais2.cisa.dhs.gov
+-- Content: DHS/FBI/NSA shared indicators, foreign adversary activity

US-CERT / CISA Advisories:
+-- ICS-CERT Advisories for OT/ICS vulnerabilities
+-- AA series advisories for APT actor activity
+-- #StopRansomware advisories with IOCs and TTPs

FBI InfraGard:
+-- Public-private partnership for critical infrastructure
+-- Regional chapters + national portal
+-- Classified threat briefings for members
```

---

### 8.2 TLP v2.0 Markings

Traffic Light Protocol (TLP) standardizes sharing restrictions. Version 2.0 (October 2022) added TLP:AMBER+STRICT:

```
TLP:RED
  Sharing: Named recipients ONLY
  Use: Highly sensitive information shared with specific individuals
  Example: Live incident details, classified technical indicators

TLP:AMBER+STRICT
  Sharing: Organization ONLY (no subsidiaries or partners)
  Use: Internal use strictly, no sharing beyond org boundary
  Example: Proprietary vendor IOCs with commercial use restrictions

TLP:AMBER
  Sharing: Organization + need-to-know partners
  Use: Limited sharing with trusted sector partners
  Example: ISAC-shared indicators, government-shared TTPs

TLP:GREEN
  Sharing: Community -- not for public posting
  Use: Broad sharing within sector/community, not internet-public
  Example: ISAC threat bulletins, community forum posts

TLP:CLEAR
  Sharing: Unlimited -- can be posted publicly
  Use: Public threat reports, blog posts, advisories
  Example: Vendor threat reports, CVE details, CISA advisories
```

**Applying TLP in MISP**:
```python
from pymisp import MISPEvent

event = MISPEvent()
event.add_tag('tlp:amber')  # Apply TLP:AMBER to entire event

# Apply different TLP to specific attributes
attr = event.add_attribute('ip-dst', '192.0.2.1')
attr.add_tag('tlp:red')  # This specific IOC is TLP:RED
```

---

### 8.3 Chatham House Rule

Widely applied in CTI sharing forums and tabletops:

> "When a meeting, or part thereof, is held under the Chatham House Rule, participants are free to use the information received, but neither the identity nor the affiliation of the speaker(s), nor that of any other participant, may be revealed."

**CTI Application**:
- ISAC calls routinely operate under Chatham House Rule
- Analysts can share IOCs and TTPs received on calls, but cannot attribute the source organization
- Enables organizations to share sensitive intelligence without reputational or legal exposure

---

### 8.4 Legal Considerations for Intelligence Sharing

#### United States
- **CISA Cybersecurity Act of 2015**: Safe harbor provisions for sharing cybersecurity threat indicators with CISA; protects organizations from antitrust and privacy liability when sharing through DHS-designated portals
- **Computer Fraud and Abuse Act (CFAA)**: Active defense and attribution activities can create legal risk; consult legal counsel before any offensive-adjacent intelligence gathering
- **Export Control (ITAR/EAR)**: Certain offensive security tools and intelligence methods may be controlled; sharing with foreign partners requires review

#### European Union
- **NIS2 Directive (2022/2555)**: Mandates security incident reporting for essential entities; encourages threat intelligence sharing with national CSIRTs
- **GDPR**: Personal data in threat indicators (IP addresses as PII, email addresses) requires legal basis for processing and sharing; document legitimate interest or consent
- **ECSM**: ENISA coordinates pan-EU threat intelligence sharing via the CSIRTs Network

#### Protecting Proprietary Intelligence
Before sharing with ISACs or community portals:
1. Remove any classified or proprietary business intelligence
2. Strip customer PII from indicators (anonymize victim data)
3. Verify commercial TI license allows redistribution
4. Apply appropriate TLP marking based on source restrictions
5. Document the sharing decision and legal basis

---

### 8.5 Intelligence Quality Before Sharing

Pre-share checklist:
```
Quality Gates Before Sharing IOCs:
[ ] False positive rate < 5% (validate against known-good traffic)
[ ] Confidence score documented (Admiralty Code or percentage)
[ ] Corroboration: Confirmed by at least 2 independent sources
[ ] Source reliability: Known and documented
[ ] Expiry date set: Appropriate TTL for IOC type
[ ] TLP marking applied: Appropriate for source sensitivity
[ ] Context included: Why is this malicious? What campaign/actor?
[ ] ATT&CK mapping: Which technique does this indicator map to?
[ ] Private IP ranges excluded: No RFC1918, loopback, link-local
[ ] Benign infrastructure excluded: CDNs, cloud providers, Google DNS
```

---

### 8.6 Machine-Speed Sharing

Automated intel sharing enables real-time defensive action:

```python
# Automated MISP-to-SIEM workflow
import requests
from pymisp import PyMISP

def sync_misp_to_siem(misp_url, misp_key, siem_api_url):
    misp = PyMISP(misp_url, misp_key)

    # Get IOCs marked for detection (to_ids=True) updated in last hour
    results = misp.search(
        to_ids=True,
        timestamp='1h',
        type_attribute=['ip-dst', 'domain', 'md5', 'sha256'],
        tags=['tlp:green', 'tlp:clear']
    )

    ioc_batch = []
    for event in results:
        for attr in event.get('Attribute', []):
            ioc_batch.append({
                'type': attr['type'],
                'value': attr['value'],
                'comment': attr.get('comment', ''),
                'event_id': event['Event']['id']
            })

    # Push batch to SIEM
    if ioc_batch:
        r = requests.post(
            f"{siem_api_url}/intelligence/bulk",
            json={'indicators': ioc_batch},
            headers={'Authorization': 'Bearer SIEM_TOKEN'}
        )
        print(f"Pushed {len(ioc_batch)} IOCs to SIEM: {r.status_code}")

    return len(ioc_batch)
```

---

## 9. CTI Integration with Security Operations

### 9.1 SIEM Integration

#### Microsoft Sentinel
```kql
// Join network events with threat intelligence indicators
SecurityAlert
| where TimeGenerated > ago(24h)
| join kind=inner (
    ThreatIntelligenceIndicator
    | where Active == true
    | where ExpirationDateTime > now()
    | where ConfidenceScore > 50
    | project NetworkIP, IndicatorId, ThreatType, Description, Tags
) on $left.RemoteIP == $right.NetworkIP
| project TimeGenerated, AlertName, RemoteIP, ThreatType, Description, ConfidenceScore
| order by TimeGenerated desc

// Domain-based threat intel matching
DnsEvents
| where TimeGenerated > ago(1h)
| join kind=inner (
    ThreatIntelligenceIndicator
    | where Active == true and isnotempty(DomainName)
    | project DomainName, ThreatType, ConfidenceScore, ExpirationDateTime
) on $left.Name == $right.DomainName
| where ExpirationDateTime > now()
| project TimeGenerated, Computer, Name, ThreatType, ConfidenceScore
| order by ConfidenceScore desc
```

#### Splunk Threat Intelligence
```spl
# Search against threat intel lookup table
index=network sourcetype=proxy
| lookup threat_intel_ips dest_ip as dest OUTPUT threat_score, campaign, actor
| where threat_score > 70
| table _time, src_ip, dest_ip, threat_score, campaign, actor, url, status

# DNS-based detection
index=dns sourcetype=stream:dns
| lookup threat_domains query AS query_name OUTPUT threat_score, malware_family
| where isnotnull(threat_score) AND threat_score > 50
| stats count by query_name, malware_family, threat_score
| sort -count
```

#### Elastic SIEM Threat Intelligence Module
```yaml
# filebeat.yml -- Threat Intelligence input configuration
filebeat.inputs:
  - type: httpjson
    name: misp-indicators
    interval: 5m
    request.url: "https://misp.example.com/attributes/restSearch"
    request.method: POST
    request.body: '{"returnFormat":"json","type":["ip-dst","domain","md5"],"to_ids":1,"published":1}'
    request.headers:
      Authorization: "ApiKey YOUR_MISP_KEY"
    response.split:
      target: body.response.Attribute
```

#### QRadar -- IBM X-Force Integration
```bash
# QRadar Reference Set bulk upload via REST API
curl -X POST "https://qradar.example.com/api/reference_data/sets/bulk_load/MaliciousIPs" \
  -H "SEC: QR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '["192.0.2.1", "198.51.100.1", "203.0.113.1"]'
```

---

### 9.2 SOAR-TIP Integration

Automated enrichment workflows dramatically reduce analyst workload:

```python
# SOAR Playbook: Alert Enrichment with TIP
# Platforms: Splunk SOAR, Palo Alto XSOAR, Swimlane

def alert_enrichment_playbook(alert):
    iocs = extract_iocs_from_alert(alert)
    enrichment_results = {}

    for ioc in iocs:
        misp_results = query_misp(ioc['value'], ioc['type'])
        vt_results = query_virustotal(ioc['value'], ioc['type'])
        if ioc['type'] == 'ip':
            abuse_results = query_abuseipdb(ioc['value'])
        enrichment_results[ioc['value']] = {
            'misp_events': misp_results.get('event_count', 0),
            'misp_actor': misp_results.get('threat_actor'),
            'vt_detections': vt_results.get('malicious'),
            'abuse_score': abuse_results.get('abuseConfidenceScore', 0) if ioc['type'] == 'ip' else None,
            'threat_type': determine_threat_type(misp_results, vt_results),
            'actor_attribution': misp_results.get('actor'),
            'campaign': misp_results.get('campaign'),
            'confidence': calculate_composite_score(misp_results, vt_results)
        }

    update_alert_with_enrichment(alert['id'], enrichment_results)

    # Auto-escalate if high-confidence actor attribution
    if any(r.get('actor_attribution') and r.get('confidence', 0) > 80
           for r in enrichment_results.values()):
        escalate_to_tier3(alert, enrichment_results)
        notify_cti_team(alert, enrichment_results)

    # Auto-block if abuse score > 90 or MISP malware tag
    for ioc_value, data in enrichment_results.items():
        if data.get('abuse_score', 0) > 90 or data.get('threat_type') == 'malware-c2':
            push_to_firewall_blocklist(ioc_value, data)
            create_ticket_with_context(ioc_value, data)
```

---

### 9.3 EDR Integration

#### CrowdStrike Falcon
```python
from falconpy import IOC

falcon = IOC(client_id="CLIENT_ID", client_secret="CLIENT_SECRET")

# Upload custom IOCs from CTI feed
response = falcon.indicator_create(
    body={
        "indicators": [
            {
                "type": "domain",
                "value": "malicious-c2.example.com",
                "action": "detect",
                "severity": "HIGH",
                "description": "APT29 C2 domain -- StellarParticle campaign",
                "tags": ["APT29", "SUNBURST", "Campaign-2024-01"],
                "applied_globally": True,
                "expiration": "2024-04-01T00:00:00Z"
            }
        ]
    }
)
```

#### Microsoft Defender for Endpoint
```powershell
# Upload IOCs via MDE API
$headers = @{
    'Authorization' = "Bearer $accessToken"
    'Content-Type'  = 'application/json'
}

$ioc = @{
    indicatorValue = "malicious-c2.example.com"
    indicatorType  = "DomainName"
    action         = "Alert"
    severity       = "High"
    title          = "APT29 C2 Domain"
    description    = "Known APT29 command and control infrastructure"
    expirationTime = "2024-04-01T00:00:00Z"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/indicators" `
    -Method POST -Headers $headers -Body $ioc
```

---

### 9.4 Firewall and DNS Integration

#### Palo Alto Networks -- MineMeld / Dynamic Address Groups
```xml
<!-- MineMeld node config for dynamic blocklist from MISP -->
<node>
  <name>misp_c2_ips</name>
  <class>minemeld.ft.misp.MISPTAXII</class>
  <config>
    <misp_url>https://misp.example.com</misp_url>
    <misp_key>API_KEY</misp_key>
    <type>ip</type>
    <to_ids>true</to_ids>
  </config>
</node>
```

#### DNS Response Policy Zones (RPZ) -- BIND
```bind
; /etc/named/rpz.db -- DNS RPZ for IOC blocking
$TTL 300
@ IN SOA rpz.example.com. admin.example.com. (
    2024011501 ; Serial
    3600       ; Refresh
)
@ IN NS rpz.example.com.

; Block malicious domains -- return NXDOMAIN
malicious-c2.example.com    CNAME .
evil-phishing.com            CNAME .
update-secure-cdn.net        CNAME .

; Redirect to sinkhole instead of NXDOMAIN
dga-seed-domain.com          CNAME sinkhole.example.com.
```

---

### 9.5 Detection Rule Enrichment

High-quality detection rules include CTI context for faster analyst triage:

```yaml
# Sigma rule enriched with CTI context
title: APT29 PowerShell Download Cradle -- StellarParticle Campaign
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
description: Detects PowerShell download cradle pattern consistent with APT29 StellarParticle tooling
author: CTI Team
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.001
  - attack.collection
  - attack.t1005
  - cti.actor.apt29
  - cti.campaign.stellarparticle
  - cti.confidence.high
  - cti.tlp.amber
logsource:
  product: windows
  category: ps_script
detection:
  keywords:
    - 'IEX (New-Object Net.Webclient).DownloadString'
    - 'IEX(New-Object System.Net.WebClient).DownloadString'
    - '[System.Net.WebRequest]::Create'
  filter_legitimate:
    ScriptBlockText|contains:
      - 'chocolatey.org'
      - 'powershellgallery.com'
  condition: keywords and not filter_legitimate
falsepositives:
  - Software installation scripts
  - IT admin tooling (validate against known admin workstations)
level: high
cti_context:
  actor: APT29 / Cozy Bear / Midnight Blizzard
  campaign: StellarParticle (2021-2023)
  attribution_confidence: 0.85
  ttl: 2025-01-15
```

---

## 10. CTI Program Management & Metrics

### 10.1 Team Structure

A mature CTI team balances technical depth with analytical rigor and stakeholder communication:

| Role | Primary Responsibilities | Key Skills |
|------|-------------------------|------------|
| **CTI Analyst (Junior)** | IOC processing, feed triage, enrichment, basic reporting | STIX/TAXII, TIP tools, OSINT |
| **CTI Analyst (Senior)** | All-source analysis, campaign tracking, actor profiles, hunting briefs | ATT&CK mapping, threat modeling, structured analytic techniques |
| **Malware Analyst** | Sample analysis, YARA authoring, config extraction, technical reports | Reverse engineering, sandboxing, scripting |
| **Threat Hunter** | Operationalize CTI into hunting hypotheses; proactive threat detection | SIEM/EDR query, ATT&CK, behavioral analysis |
| **CTI Engineer** | TIP administration, API integrations, automation, feed management | Python, STIX/TAXII, SIEM integrations |
| **All-Source Analyst** | Strategic/operational intelligence products, geopolitical context | Intelligence tradecraft, report writing |
| **CTI Manager** | Program strategy, stakeholder management, budget, personnel | Leadership, communication, program management |

**Team sizing by organization**:
| Org Size | Revenue / Users | Recommended CTI FTE |
|----------|----------------|---------------------|
| Small | <$100M / <500 employees | 0.5-1 FTE (hybrid SOC role) |
| Mid-market | $100M-$1B | 1-3 FTE dedicated CTI |
| Enterprise | $1B-$10B | 3-8 FTE CTI team |
| Large Enterprise | $10B+ / Critical Infrastructure | 8-20+ FTE, specialized subteams |

---

### 10.2 Requirements Management

Effective CTI programs are requirements-driven, not IOC-dumping operations:

#### Priority Intelligence Requirements (PIRs)
PIRs are the 3-5 most critical intelligence questions driving the CTI program:

```
Example PIR Set (Financial Services Organization):

PIR-1: Are threat actors actively targeting our SWIFT infrastructure
       or correspondent banking relationships?

PIR-2: Is there imminent ransomware activity targeting our sector
       that could impact business continuity?

PIR-3: Are nation-state actors conducting pre-positioning or
       espionage operations against our organization specifically?

PIR-4: Are threat actors exploiting vulnerabilities in our
       critical technology stack (specific vendor/versions)?

PIR-5: Are insider threat indicators present in our environment
       consistent with current threat actor recruitment tactics?
```

#### Standing Intelligence Requirements (SIRs)
Ongoing collection and monitoring needs that remain constant:
- Monitor ISAC feeds for sector-specific IOCs (daily)
- Track exploitation of CVEs in our environment's technology stack (continuous)
- Monitor dark web for credential exposure and data breach discussions mentioning the org (continuous)
- Review government advisories (CISA, FBI, NSA) for relevant TTP updates (weekly)
- Track ransomware groups and their victim targeting patterns (weekly)

#### Requirements Lifecycle
```
1. Requirements Elicitation
   +-- Executive / board input (strategic questions)
   +-- IR team input (what do they need during incidents?)
   +-- SOC input (what context helps triage?)
   +-- Threat hunter input (what hypotheses to test?)

2. Requirements Documentation
   +-- PIRs approved by CISO
   +-- SIRs maintained by CTI manager
   +-- Collection plan aligned to requirements

3. Requirements Review Cadence
   +-- PIR review: Quarterly with CISO
   +-- SIR review: Monthly with security leadership
   +-- Ad-hoc: When major threat landscape shift occurs
```

---

### 10.3 CTI Program Metrics

Metrics should demonstrate value to stakeholders at each level:

#### IOC Quality Metrics
| Metric | Definition | Target |
|--------|-----------|--------|
| **False Positive Rate** | % of CTI-sourced blocks/alerts that are not malicious | < 2% |
| **IOC Coverage** | % of known actor infrastructure represented in our TIP | > 60% of tracked actors |
| **IOC Freshness** | Average age of active IOCs in SIEM at time of block | < 14 days for IPs |
| **Corroboration Rate** | % of IOCs confirmed by 2+ independent sources | > 70% |
| **Enrichment Rate** | % of IOCs with full context (actor, campaign, TTPs) | > 80% |

#### Operational Metrics
| Metric | Definition | Target |
|--------|-----------|--------|
| **Attacks Blocked via CTI IOCs** | Confirmed blocks where CTI-sourced IOC was the detection | Track monthly trend |
| **MTTD Reduction** | Reduction in mean time to detect when CTI context applied | > 20% reduction |
| **Hunts Generated from CTI** | Hunting hypotheses derived from CTI analysis | 2-4 per month |
| **Hunt Success Rate** | % of CTI-based hunts that find malicious activity | > 15% |
| **IR Enrichment Speed** | Time from IR escalation to CTI context delivery | < 30 minutes |

#### Strategic Metrics
| Metric | Definition | Target |
|--------|-----------|--------|
| **Products Delivered** | CTI reports, briefs, and products produced | Per agreed schedule |
| **Executive Consumption** | % of executive products reported as "useful" | > 80% |
| **Board Briefings** | Quarterly briefings delivered to board | 4 per year |
| **Requirements Satisfaction** | % of PIRs with current actionable intelligence | > 70% |

#### Sharing Metrics
| Metric | Definition | Target |
|--------|-----------|--------|
| **Indicators Shared** | IOCs shared with ISAC/community per month | Track trend |
| **IOCs Received and Operationalized** | Inbound community IOCs imported to SIEM | > 90% ingestion rate |
| **Sharing Reciprocity** | Ratio of sent:received indicators | > 0.5 (give as much as received) |

---

### 10.4 Intelligence Product Types

| Product | Length | Audience | Frequency | Contents |
|---------|--------|----------|-----------|----------|
| **Flash Report** | 1 page | SOC, IR, Management | As-needed (hours) | Immediate threat: actor, IOCs, TTPs, recommendations |
| **Technical Report** | 5-20 pages | Malware analysts, Detection engineers | Weekly/campaign-driven | Deep-dive malware/campaign analysis with IOCs, YARA, ATT&CK mapping |
| **Threat Assessment** | 3-8 pages | CISO, Security management | Monthly | Strategic risk rating of top threats; likelihood and impact |
| **Actor Profile** | 5-15 pages | All technical teams | Updated per new campaign | Comprehensive actor dossier: history, TTPs, infrastructure, campaigns |
| **Landscape Briefing** | 5-10 pages/slides | Executives, Board | Quarterly | Threat landscape overview; sector trends; strategic risk |
| **Hunt Package** | 2-5 pages + queries | Threat Hunters | Monthly | Hypothesis + ATT&CK technique + hunting queries for SIEM/EDR |
| **Vulnerability Intelligence** | 1-3 pages | Vuln Management | Per critical CVE | Exploitation activity, affected products, CVSS context, CISA KEV status |

---

### 10.5 TIP Evaluation Criteria

When selecting or replacing a Threat Intelligence Platform:

| Criterion | Weight | Evaluation Questions |
|-----------|--------|---------------------|
| **STIX/TAXII 2.1 Support** | High | Native STIX 2.1 data model? TAXII server and client? |
| **Integration Ecosystem** | High | Out-of-box connectors to SIEM, SOAR, EDR, firewall? |
| **Enrichment Automation** | High | Automated IOC enrichment via API? Which sources? |
| **Analyst Workflow** | Medium | Investigation workspace? Case management? Collaboration? |
| **IOC Lifecycle Management** | Medium | Expiry, scoring, and active/inactive state management? |
| **Sharing Capabilities** | Medium | ISAC integration? TLP enforcement? Sharing group control? |
| **ATT&CK Integration** | Medium | Native ATT&CK mapping? Coverage heatmap? |
| **Scalability** | Medium | IOC volume limits? Search performance at scale? |
| **Total Cost of Ownership** | Variable | License + infrastructure + staffing to maintain |
| **Vendor Support & Roadmap** | Medium | Support SLAs? Frequency of updates? Community? |

---

### 10.6 Budget Allocation by Org Size

```
Small Organization (1-2 FTE, $150K-$400K total budget):
+-- Open-source TIP (MISP):          $0
+-- Commercial feeds (1-2):          $30K-$80K/year
+-- VirusTotal/Shodan subscriptions: $15K-$30K/year
+-- ISAC membership:                 $5K-$25K/year
+-- Training & conferences:          $5K-$15K/year

Mid-Market (2-5 FTE, $400K-$1.5M total):
+-- Commercial TIP:                  $80K-$200K/year
+-- Multiple commercial feeds:       $100K-$300K/year
+-- Dark web monitoring:             $50K-$150K/year
+-- Threat hunting platform:         $50K-$100K/year
+-- Training, conferences, ISAC:     $30K-$80K/year

Enterprise (5+ FTE, $1.5M+ total):
+-- Enterprise TIP:                  $200K-$500K/year
+-- Recorded Future / Mandiant:      $200K-$600K/year
+-- Dark web intelligence platform:  $100K-$300K/year
+-- VT Enterprise:                   $100K-$250K/year
+-- Personnel (largest cost):        $600K-$2M+/year
```

---

## Quick Reference

### Essential CTI Links

| Resource | URL |
|----------|-----|
| MITRE ATT&CK | https://attack.mitre.org |
| MISP Project | https://www.misp-project.org |
| OpenCTI | https://www.opencti.io |
| MalwareBazaar | https://bazaar.abuse.ch |
| Feodo Tracker | https://feodotracker.abuse.ch |
| URLhaus | https://urlhaus.abuse.ch |
| VirusTotal | https://www.virustotal.com |
| Shodan | https://www.shodan.io |
| Censys | https://search.censys.io |
| GreyNoise | https://www.greynoise.io |
| crt.sh | https://crt.sh |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA AIS | https://www.cisa.gov/ais |
| CIRCL PDNS | https://www.circl.lu/services/passive-dns/ |
| Malpedia | https://malpedia.caad.fkie.fraunhofer.de |
| TLP Standard | https://www.cisa.gov/tlp |

### ATT&CK Quick Reference -- Common Techniques by Phase

| ATT&CK Tactic | Common Techniques (IDs) |
|---|---|
| Initial Access | T1566 Phishing, T1190 Public-Facing App Exploit, T1195 Supply Chain, T1078 Valid Accounts |
| Execution | T1059 Command Interpreter, T1203 Exploitation, T1204 User Execution, T1053 Scheduled Task |
| Persistence | T1053 Scheduled Task, T1543 System Service, T1547 Boot Autostart, T1078 Valid Accounts |
| Privilege Escalation | T1068 Exploitation, T1055 Process Injection, T1134 Access Token Manipulation |
| Defense Evasion | T1027 Obfuscation, T1036 Masquerading, T1055 Injection, T1562 Impair Defenses |
| Credential Access | T1003 OS Credential Dumping, T1110 Brute Force, T1555 Credentials from Stores |
| Discovery | T1082 System Info, T1083 File Discovery, T1018 Remote System Discovery |
| Lateral Movement | T1021 Remote Services, T1550 Pass-the-Hash/Ticket, T1534 Internal Spearphishing |
| Collection | T1005 Local Data, T1074 Data Staged, T1113 Screen Capture, T1560 Archive Data |
| Exfiltration | T1041 Exfil over C2, T1048 Exfil over Alt Protocol, T1567 Exfil to Web Service |
| Command & Control | T1071 App Layer Protocol, T1090 Proxy, T1095 Non-App Layer, T1102 Web Service |

---

*Last updated: 2026-05-06 | Maintained by CTI Team | TLP:GREEN -- For internal use and trusted community sharing*
