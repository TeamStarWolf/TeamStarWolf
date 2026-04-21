# Active Defense & Deception

> Going beyond passive monitoring to actively mislead, detect, and study adversaries using deceptive environments, honeypots, honeytokens, and adversary engagement techniques.

## What Active Defense Engineers Do

- Design and deploy deception layers: honeypots, honeynets, and deceptive credentials
- Plant and monitor honeytokens (fake files, API keys, DNS entries, email addresses) to detect unauthorized access
- Operate deception grids that mirror production environments to entice and trap attackers
- Analyze attacker behavior observed in deception environments: TTPs, tooling, objectives
- Build canary tokens and breadcrumbs that alert on access without disrupting real operations
- Integrate deception telemetry into SIEM/SOAR for high-fidelity alerting (near-zero false positives)
- Conduct adversary engagement: slow down, frustrate, and collect intelligence on active attackers
- Build and operate cyber threat intelligence from deception environment observations

---

## Core Concepts

### Active Defense Spectrum

```
Passive ◄──────────────────────────────────────────────► Active
Monitor    Detect    Deny    Disrupt    Deceive    Manipulate
  │          │        │        │           │           │
 SIEM      IDS/IPS  Firewall  Honeypot  Honeynet   Tarpit
```

The [Cyber Active Defense Continuum](https://www.sans.org/white-papers/36022/) defines five escalating levels:
1. **Annoy** — Slow attackers down (tarpits, false credentials)
2. **Attribute** — Identify attacker origin (beacon payloads, tracking pixels)
3. **Attack** — Counterattack (legally complex; typically off-limits)

Most enterprise programs operate at levels 1–2 (annoy + attribute).

### Deception Technology Taxonomy

| Type | Description | Example |
|---|---|---|
| Honeypot | Isolated decoy system designed to attract attackers | Fake Windows Server, fake database |
| Honeynet | Network of honeypots that mimics a real environment | Full fake corporate network segment |
| Honeytoken | Fake credential, file, or data item that triggers on access | Fake AWS key, fake password in vault |
| Canary Token | Instrumented file/URL/token that beacons when opened | canary.tools tokens, AWS canary keys |
| Honey Credential | Fake username/password planted in memory or files | Fake domain admin creds in LSASS bait |
| Deceptive DNS | DNS entries pointing to honeypots | Fake internal service records |
| Tarpitting | Slow down automated scanning/brute force | SMTP tarpits, SSH tarpits |

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [MITRE ENGAGE](https://engage.mitre.org/) | Adversary engagement and deception framework |
| [MITRE ATT&CK](https://attack.mitre.org/) | TTPs observed in deception environments |
| [Cyber Active Defense Continuum (SANS)](https://www.sans.org/white-papers/36022/) | Active defense escalation model |
| [NIST SP 800-160 Vol 2](https://csrc.nist.gov/publications/detail/sp/800-160/vol-2-rev-1/final) | Developing Cyber Resilient Systems (includes deception) |
| [Project HIVE (CISA)](https://www.cisa.gov/) | Government deception best practices |

---

## Free & Open-Source Tools

### Honeypots

| Tool | Type | Notes |
|---|---|---|
| [OpenCanary](https://github.com/thinkst/opencanary) | Multi-service honeypot | SSH, HTTP, FTP, SMB, MySQL, RDP honeypot services |
| [Cowrie](https://github.com/cowrie/cowrie) | SSH/Telnet honeypot | Records all attacker commands; widely deployed |
| [Dionaea](https://github.com/DinoTools/dionaea) | Malware-catching honeypot | Captures malware samples via SMB, HTTP, FTP |
| [Heralding](https://github.com/johnnykv/heralding) | Credential-capturing honeypot | Logs all creds submitted to fake services |
| [HoneyDrive](https://bruteforcelab.com/honeydrive) | Honeypot distro | Pre-configured Linux distro with 10+ honeypots |
| [T-Pot](https://github.com/telekom-security/tpotce) | All-in-one honeypot platform | 20+ honeypots + Elastic + Kibana dashboard |
| [SNARE/TANNER](https://github.com/mushorg/snare) | Web application honeypot | Clones real sites; captures web attacks |
| [Glutton](https://github.com/mushorg/glutton) | General-purpose honeypot | Protocol-agnostic; MitM capabilities |

### Honeytokens & Canary Tokens

| Tool | Purpose | Notes |
|---|---|---|
| [Canarytokens.org](https://canarytokens.org/) | Free canary token generator | Word docs, PDFs, URLs, AWS keys, DNS tokens |
| [Thinkst Canary (OSS)](https://github.com/thinkst/canarytokens) | Self-hosted canary tokens | Same as canarytokens.org, self-hosted |
| [dcept](https://github.com/secureworks/dcept) | Active Directory honey credentials | Plants honey tickets in domain |
| [HoneyBadger](https://github.com/lanmaster53/honeybadger) | Geolocation canary system | Tracks token access with geolocation |

### Deception Infrastructure

| Tool | Purpose | Notes |
|---|---|---|
| [HIHAT](https://github.com/ukhomeoffice/hihat) | Honeypot-in-a-hurry | Docker-based rapid honeypot deployment |
| [MHN (Modern Honey Network)](https://github.com/pwnlandia/mhn) | Honeypot management | Centralized honeypot deployment + data collection |
| [Artillery](https://github.com/BinaryDefense/artillery) | Honeypot + hardening tool | Port scanner detection + fake services |
| [Portspoof](https://github.com/drk1wi/portspoof) | Port spoofing | Makes every port appear open (scanner confusion) |
| [LaBrea](http://labrea.sourceforge.net/) | Tarpit | Traps worms and port scanners |

### Intelligence Collection from Deception

| Tool | Purpose | Notes |
|---|---|---|
| [Kippo-Graph](https://github.com/ikoniaris/kippo-graph) | SSH honeypot visualization | Visualize Cowrie/Kippo attacker data |
| [DShield](https://isc.sans.edu/tools/submit.html) | Honeypot data sharing | Submit honeypot logs to SANS Internet Storm Center |
| [Elastic SIEM](https://www.elastic.co/security) | Honeypot log analysis | Index honeypot logs for threat intel |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Thinkst Canary](https://canary.tools/) | Enterprise canary tokens + honeypots | Gold standard; near-zero false positives |
| [Attivo Networks (SentinelOne)](https://www.sentinelone.com/platform/attivo-identity/) | Identity deception | AD decoys, fake credentials; acquired by SentinelOne |
| [Illusive Networks (Crowdstrike)](https://www.illusivenetworks.com/) | Deception grid | Lateral movement detection via deception |
| [Acalvio ShadowPlex](https://www.acalvio.com/) | AI-driven deception | Autonomous deception deployment |
| [Cymulate](https://cymulate.com/) | BAS + deception validation | Breach and attack simulation with deception |
| [Smokescreen](https://www.smokescreen.io/) | Enterprise deception grid | Full network deception; lateral movement tripwires |

---

## MITRE ENGAGE Framework

MITRE ENGAGE organizes active defense into three goal categories:

### Expose
Reveal adversary capabilities and intent by allowing controlled access:
- **Collect** — Gather data on adversary tools and TTPs
- **Detect** — Identify adversary activity with high confidence
- **Contain** — Limit adversary movement to controlled environments

### Affect
Negatively impact adversary operations:
- **Disrupt** — Interrupt adversary task execution
- **Degrade** — Reduce adversary effectiveness
- **Redirect** — Move adversary into monitored environment

### Elicit
Draw out adversary behavior for intelligence:
- **Motivate** — Encourage adversary to take specific actions
- **Test** — Probe adversary for responses

---

## Deployment Patterns

### Internal Deception Layer
```
Corporate Network
├── Production Segment (real systems)
└── Deception Layer (transparent to attackers)
    ├── Honey credentials in AD (fake domain admin)
    ├── Canary files on file shares (fake "passwords.xlsx")
    ├── Fake internal services (fake HR portal, fake DB)
    └── Honey tokens in source code repos (fake API keys)
```

### High-Fidelity Alert Logic
Deception alerts are near-zero false positive because legitimate users never touch decoys:
```
IF access_to(honey_resource) → HIGH CONFIDENCE ALERT
  - Who accessed it?
  - From where (IP, hostname)?
  - What did they do next?
  - → Immediate escalation to IR
```

---

## ATT&CK Coverage

Deception technology primarily detects **post-initial-access** techniques — adversaries already inside the network:

| Technique | Deception Detection |
|---|---|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Honey credentials in password managers, AD |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Honey RDP/SSH/SMB services |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Canary files in shares trigger on access |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Fake AWS keys, fake DB passwords |
| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Honey AD groups with canary members |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Monitoring honey account for re-use |
| [T1071](https://attack.mitre.org/techniques/T1071/) | App Layer Protocol | C2 callback from honey documents |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Honey tasks that alert if modified |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GIAC GDAT](https://www.giac.org/certifications/defending-advanced-threats-gdat/) | GIAC | Defending Advanced Threats (includes deception) |
| [SANS FOR578](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/) | SANS | Cyber Threat Intelligence (deception for intel) |
| [CPTC](https://www.nationalcptc.org/) | RIT | Collegiate Penetration Testing (attacker perspective) |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [MITRE ENGAGE](https://engage.mitre.org/) | Framework | Active defense and adversary engagement matrix |
| [Thinkst Applied Research](https://thinkst.com/research/) | Blog | Canary token research and deception theory |
| [Active Defense & Cyber Deception (SANS)](https://www.sans.org/white-papers/36022/) | White paper | Foundational active defense paper |
| [The Art of Deception (Mitnick)](https://www.wiley.com/en-us/The+Art+of+Deception) | Book | Social engineering and deception fundamentals |
| [Honeypots for Windows (Spitzner)](https://link.springer.com/book/9781590593357) | Book | Classic honeypot deployment guide |
| [T-Pot Documentation](https://github.com/telekom-security/tpotce/wiki) | Reference | All-in-one honeypot platform setup |
| [Canarytokens Docs](https://docs.canarytokens.org/) | Reference | Token types and deployment guide |

---


## Deception Technology Deep Dive

### Honeypot Types and Deployment

| Type | Interaction Level | Purpose | Examples |
|---|---|---|---|
| Low-interaction honeypot | Emulate services; no real OS | Network recon detection | Cowrie (SSH/Telnet), Dionaea (malware capture), OpenCanary |
| Medium-interaction | Partial emulation | Credential harvest detection | Cowrie with realistic shell, Heralding |
| High-interaction | Real OS and services | Full attacker behavior capture | Actual vulnerable system in isolated VLAN |
| Production honeypot | Blend with real infra | Early warning; lower false positive | OpenCanary deployed alongside real servers |
| Research honeypot | Isolated lab | Malware/attacker behavior analysis | KFSensor, Sebek |

### Honeytoken Categories

| Token Type | Implementation | Detects | Tools |
|---|---|---|---|
| AWS honey credentials | IAM user with CloudTrail alerts | Cloud credential theft | SpaceSiren, CanaryTokens |
| Honey documents | Office files with web beacon | Document exfiltration | Canarytokens.org (Word/PDF/Excel) |
| Honey database records | Fake customer records with alert trigger | Database exfiltration (data appears in breach) | canary fields with unique values |
| Honey DNS entries | DNS records that should never be queried | Internal recon / lateral movement | Internal DNS + alerting |
| Honey email addresses | Addresses seeded in internal docs | Phishing list generation | Monitor incoming mail to honey address |
| Active Directory decoy accounts | Fake DA account with no legit logins | AD enumeration and credential use | PurpleSharp, AD honeypot accounts |
| Browser saved credentials | Fake credentials in browser password store | Endpoint compromise, credential harvester | canarytoken browser credential type |

### Canary Token Deployment (Thinkst Canary)

- Free tier: canarytokens.org — generate URL, file, AWS key, email address tokens
- Enterprise: Thinkst Canary hardware devices; realistic honeypot infrastructure; per-device pricing
- HTTPS web bug: Embed in documents; fires when document opened online
- Usage: Seed fake credentials in password managers; embed URL tokens in sensitive directories; place DNS tokens in internal documentation

### Deception Grid Architecture

- Coverage points: Every subnet should have at least one honeypot; cover all common attack pivot paths
- Realistic appearance: Decoys should look identical to real systems (same OS, same open ports, same naming convention)
- Low noise: Honeypots should generate near-zero legitimate traffic — any connection is suspicious
- Alert fidelity: Honeypot alerts are high-fidelity (very few false positives); treat every alert as real
- Integration: Feed honeypot alerts to SIEM as high-priority events; auto-create incident tickets

---

## Adversary Engagement

### Active Defense Spectrum (David Dittrich Framework)

- Passive defense: Standard hardening, patching, detection (fully legal everywhere)
- Active defense: Using deception and engagement techniques against attackers within your own network (legal)
- Offensive countermeasures: Hacking back — illegal in almost all jurisdictions; significant legal risk
- Legal boundary: Everything within your own network is generally permissible; never hack back into external systems

### Adversary Engagement Goals

- Intelligence collection: Understand TTPs, tools, objectives, indicators
- Slow attackers down: Tarpit interactions; time wasted on deception = time not attacking real systems
- Attribution data: Collect artifacts that may aid attribution (C2 infrastructure, unique tool signatures)
- Feed threat intelligence: IOCs from honeypots become actionable intelligence

### MITRE ENGAGE Framework

- Prepare: Plan deception operations; understand adversary objectives
- Expose: Reveal adversary presence through deception artifacts
- Affect: Manipulate adversary actions by influencing their environment
- Elicit: Capture adversary TTPs through controlled engagement
- Understand: Analyze collected data; improve defenses

### Deception Playbooks

- Honey credentials workflow: Create fake AD account → monitor authentication logs → alert if account used → auto-isolate source IP
- Honey document exfiltration workflow: Seed document with canarytoken → employee receives alert email on open → SOC investigates source IP/device

---

## Tools Reference

| Tool | Type | Use Case | Cost |
|---|---|---|---|
| OpenCanary | OSS | Lightweight honeypot daemon (SSH/HTTP/FTP/SMB/MySQL) | Free |
| Canarytokens.org | SaaS | Web tokens, DNS tokens, Office docs, AWS keys | Free (self-host option) |
| Thinkst Canary | Commercial | Hardware + cloud deception platform | Commercial |
| Cowrie | OSS | High-fidelity SSH/Telnet honeypot with session recording | Free |
| Dionaea | OSS | Malware capture honeypot (SMB, HTTP, FTP) | Free |
| Conpot | OSS | ICS/SCADA protocol honeypot (Modbus, S7, IPMI) | Free |
| HoneyDB | OSS | Honeypot data aggregation and threat intelligence | Free |
| HoneySAP | OSS | SAP-specific honeypot for enterprise ERP attacks | Free |
| PurpleSharp | OSS | AD attack simulation including honey account triggering | Free |

---

## Related Disciplines

- [Detection Engineering](detection-engineering.md) — Integrating deception alerts into detection pipeline
- [Threat Intelligence](threat-intelligence.md) — Extracting intel from attacker behavior in deception environments
- [Security Operations](security-operations.md) — Triaging high-fidelity deception alerts
- [Incident Response](incident-response.md) — Using deception to slow and study active intrusions
- [Network Security](network-security.md) — Network-layer deception (fake VLANs, honey services)
