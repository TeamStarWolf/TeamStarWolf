# Incident Response Reference Library

> In one minute: This is the working reference for handling security incidents end to end: frameworks (NIST 800-61, SANS PICERL), triage checklists, and hands-on response procedures for ransomware, business email compromise, endpoint/network forensics, and cloud (AWS/Azure/GCP) incidents. It is useful because it pairs the process side (severity levels, team roles, notification templates, regulatory deadlines) with copy-paste commands for the tools you actually use mid-incident (EDR containment, audit-log queries, firewall blocks). Reach for it when the clock is running and you need the next concrete step, not theory.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Incident responders, SOC leads, and incident commanders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 27 min (6,302 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

An alert or user report needs triage in the next five minutes, ransomware or a suspicious wire request just landed, or you are building or testing an IR plan and tabletop program

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Detection & Initial Triage](#_2-detection-amp-initial-triage), [Ransomware Response](#_3-ransomware-response), [IR Frameworks & Preparation](#_1-ir-frameworks-amp-preparation)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, matching learning path, last corrected, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[IR Playbooks](IR_PLAYBOOKS.md), [Ransomware Defense Reference](RANSOMWARE_DEFENSE_REFERENCE.md), [Network Forensics Reference](NETWORK_FORENSICS_REFERENCE.md), [Notable Incidents](NOTABLE_INCIDENTS.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Matching learning path</th><td>

[Incident Response](/disciplines/incident-response.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last corrected</th><td>

2026-11-24, GDPR/SEC/HIPAA/PCI/California breach-notification details corrected against primary sources; forensic, containment and persistence commands fixed by running them (jq IAM, security-group/NSG isolation, Zeek/tshark/nfdump, PowerShell service and task queries); the threat-actor technique table reconciled to the library's own data; AzureAD cmdlets replaced with Microsoft Graph; vendor, ISAC and reporting-framework names and dates updated ([#418](https://github.com/TeamStarWolf/TeamStarWolf/pull/418))

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

---

## Table of Contents

1. [IR Frameworks & Preparation](#_1-ir-frameworks-amp-preparation)
2. [Detection & Initial Triage](#_2-detection-amp-initial-triage)
3. [Ransomware Response](#_3-ransomware-response)
4. [Business Email Compromise Response](#_4-business-email-compromise-response)
5. [Endpoint Forensics](#_5-endpoint-forensics)
6. [Network Forensics](#_6-network-forensics)
7. [Cloud Incident Response](#_7-cloud-incident-response)
8. [Threat Intelligence During IR](#_8-threat-intelligence-during-ir)
9. [Containment, Eradication & Recovery](#_9-containment-eradication-amp-recovery)
10. [Post-Incident & Legal](#_10-post-incident-amp-legal)

---

## 1. IR Frameworks & Preparation

### 1.1 NIST SP 800-61 Incident Response Lifecycle

NIST's current incident response guidance is [SP 800-61 Revision 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, published in April 2025. It builds incident response into the cybersecurity risk management activities of the NIST Cybersecurity Framework (CSF) 2.0 and frames it with the CSF 2.0 Functions (Govern, Identify, Protect, Detect, Respond, Recover), so incident response is a continuous risk-management activity rather than a separate linear sequence. Rev. 3 superseded [SP 800-61 Revision 2](https://csrc.nist.gov/pubs/sp/800/61/r2/final), the *Computer Security Incident Handling Guide* (August 2012), which NIST withdrew on April 3, 2025.

The four phases below are the Rev. 2 lifecycle that Rev. 3 replaced: Preparation; Detection & Analysis; Containment, Eradication & Recovery; and Post-Incident Activity. It remains a useful mental model for organizing playbooks, so the library keeps it; when you align a plan with Rev. 3, map each phase to the CSF 2.0 Functions. The popular six-step PICERL sequence (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) is the SANS model, not NIST's, and is covered separately in §1.2. Each phase has distinct objectives and deliverables.

Phase 1: Preparation
Preparation is the most investment-heavy phase and the primary determinant of IR effectiveness. Key activities include:
- Developing and approving the IR policy, plan, and procedures
- Establishing the CSIRT with defined roles, authorities, and escalation paths
- Deploying detection and analysis capabilities (SIEM, EDR, NTA, honeypots)
- Acquiring and staging the IR toolkit (forensic workstations, write blockers, imaging software)
- Conducting tabletop exercises and simulation drills quarterly
- Establishing retainer relationships with IR firms, legal counsel, and PR/crisis communications
- Pre-positioning out-of-band communication channels (Signal groups, satellite phones for catastrophic scenarios)
- Maintaining current asset inventory, network diagrams, data flow maps, and crown-jewel registers
- Documenting system baselines and approved software lists

Phase 2: Detection & Analysis
- Monitoring alerts from SIEM, EDR, IDS/IPS, MSSP, threat feeds, and user reports
- Performing initial triage to distinguish true positives from false positives
- Classifying incident type and assigning severity level
- Notifying stakeholders per the escalation matrix
- Opening an IR ticket and initiating evidence preservation

Phase 3: Containment, Eradication & Recovery
NIST groups these three activities into a single phase because they interleave in practice: you often eradicate and recover system-by-system while still containing others.

*Containment*
- Short-term containment: isolate affected systems to stop immediate damage spread
- Long-term containment: apply temporary fixes that allow business operations to continue
- Evidence preservation before eradication to support forensics and legal proceedings
- Out-of-band communication if primary channels are compromised

*Eradication*
- Identify and eliminate all attacker footholds: malware, backdoors, compromised accounts, modified configurations
- Patch or mitigate exploited vulnerabilities
- Verify eradication completeness via endpoint scanning and threat hunting

*Recovery*
- Restore systems from clean backups or rebuild from scratch
- Validate system integrity before reconnecting to production networks
- Increase monitoring during the recovery period (elevated alert thresholds)
- Confirm business operations have returned to normal

Phase 4: Post-Incident Activity
- Conduct lessons-learned meeting within 2 weeks of resolution
- Produce post-incident report
- Update IR plan, playbooks, and detection rules based on findings
- Share IOCs with sector ISACs and government partners

---

### 1.2 SANS PICERL Framework

The SANS PICERL model extends NIST with explicit Recovery and Lessons Learned phases:

| Phase | Key Questions |
|-------|--------------|
| Preparation | Are we ready to detect and respond? |
| Identification | Is this a real incident? What type? What scope? |
| Containment | How do we stop the bleeding without destroying evidence? |
| Eradication | Have we removed all attacker artifacts and access? |
| Recovery | How do we restore to a known-good state? |
| Lessons Learned | What can we improve? |

---

### 1.3 IR Team Structure & RACI

Core CSIRT Roles:

| Role | Responsibility | Typical Owner |
|------|---------------|---------------|
| Incident Commander (IC) | Overall coordination, decision authority, stakeholder comms | CISO / Senior IR Manager |
| Technical Lead | Forensic analysis, containment execution, eradication | Senior Analyst / IR Engineer |
| Communications Lead | Internal/external messaging, legal liaison | CISO / PR Lead |
| Legal Counsel | Regulatory obligations, law enforcement coordination, litigation hold | General Counsel |
| Scribe | Real-time documentation, action items, timeline | Junior Analyst / PM |
| Business Liaison | Business impact assessment, recovery prioritization | Business Unit Owner |
| Threat Intel Analyst | IOC enrichment, actor attribution, feed updates | CTI Team |

RACI Matrix Template:

| Task | IC | Tech Lead | Comms | Legal | Scribe |
|------|----|-----------|-------|-------|--------|
| Declare Incident | A | C | I | I | I |
| Contain Systems | I | R/A | I | C | I |
| Notify Regulators | A | I | R | R | I |
| Issue Press Statement | A | I | R | C | I |
| Close Incident | A | C | I | C | R |

*R=Responsible, A=Accountable, C=Consulted, I=Informed*

---

### 1.4 IR Policy Components

A complete IR policy must address:
1. Scope: Systems, data types, geographic locations covered
2. Definitions: Incident, event, alert, breach, severity levels
3. Roles & Authorities: Who can declare an incident, who can authorize containment actions
4. Escalation Paths: Contact lists, on-call rotations, executive notification thresholds
5. Reporting Requirements: Internal SLAs, regulatory obligations, law enforcement triggers
6. Evidence Handling: Chain of custody, retention periods, legal hold procedures
7. Communication Protocols: Approved channels, media handling, customer notification templates
8. Training & Testing: Annual tabletop requirements, purple team exercises
9. Plan Maintenance: Review cycle (annually minimum, or after major incidents)

---

### 1.5 Severity Classification

| Severity | Label | Criteria | Response SLA | Escalation |
|----------|-------|----------|-------------|-----------|
| P1 | Critical | Active ransomware, confirmed data exfiltration, critical infrastructure impact, executive account compromise | 15 min acknowledgment, immediate response | CISO, CxO, Legal, Board |
| P2 | High | Malware on critical server, suspected breach, BEC with financial loss, widespread phishing | 30 min acknowledgment, 2h response | CISO, Legal |
| P3 | Medium | Malware on workstation, isolated phishing, policy violation, suspicious login | 2h acknowledgment, 8h response | IR Manager |
| P4 | Low | Spam campaign, minor policy violation, failed brute force | Next business day | IR Analyst |

---

### 1.6 IR Retainer Services

Retainer engagements provide guaranteed response times and pre-negotiated rates. Key considerations:
- Minimum hour commitments: Typically 40-200 hours/year retainer; unused hours may roll over or expire
- SLA guarantees: Ensure contract specifies on-site response SLAs (e.g., IR firm on-site within 4h for P1)
- Scope definition: Forensics, legal support, ransomware negotiation, crisis PR: verify what is included
- Pre-engagement: Share network diagrams, asset inventory, IR plan with retainer firm before an incident occurs
- Key vendors: Mandiant, CrowdStrike Services, Secureworks (now part of Sophos), Palo Alto Unit 42, Kroll

---

### 1.7 Tabletop Exercise Design

Effective tabletops follow a structured format:
1. Scenario Selection: Base on realistic threats to your sector (ransomware, supply chain, BEC)
2. Inject Sequence: Prepare 6-10 injects that escalate over 2-3 hours
3. Participants: Include technical, legal, HR, finance, communications, and executive representatives
4. Facilitation: Neutral facilitator; timekeeper; scribe capturing decisions and gaps
5. Hot Wash: Immediate debrief (30 min) after exercise
6. After Action Report: Document gaps, action owners, and remediation timelines within 1 week
7. Frequency: Quarterly tabletops; annual full-scale simulation

---

### 1.8 Key IR Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| MTTD (Mean Time to Detect) | Time from initial compromise to detection | < 24 hours |
| MTTA (Mean Time to Acknowledge) | Time from alert to analyst acknowledgment | < 15 min (P1) |
| MTTC (Mean Time to Contain) | Time from detection to containment | < 4 hours (P1) |
| MTTR (Mean Time to Recover) | Time from detection to full recovery | < 72 hours (P1) |
| False Positive Rate | % of alerts that are not true incidents | < 20% |
| Incidents per Month | Volume trend | Track for seasonality/spikes |
| % Incidents with Playbook | Coverage of incident types | > 90% |

---

### 1.9 IR Toolkit Contents

Software (bootable forensic USB or IR jump bag):
- Kali Linux / SIFT Workstation (bootable)
- Volatility 3 (memory forensics)
- KAPE (triage collection)
- Velociraptor (live response agent)
- Autopsy / FTK Lite (disk analysis)
- Wireshark / tcpdump (packet capture)
- NetworkMiner (PCAP analysis)
- Sysinternals Suite (Windows)
- Eric Zimmerman Tools (Windows artifact parsing)
- CyberChef (data decoding/transformation)

Hardware:
- Write blockers (Tableau TX1, WiebeTech)
- Forensic imaging drives (multiple 4TB+ portable drives)
- Network tap (PassMark)
- Serial console cables
- Out-of-band laptop with cellular hotspot

Documentation:
- Chain of custody forms
- Evidence label templates
- Network diagram templates
- Contact lists (legal, IR retainer, law enforcement, regulators)

---

### 1.10 On-Call Procedures

- PagerDuty / OpsGenie: Configure escalation policies with 5-minute auto-escalation for P1/P2
- On-Call Rotation: Minimum 2 analysts per shift; 24/7/365 coverage for P1
- Runbooks: Accessible offline via printed binder and encrypted USB; not solely on systems that may be compromised
- Warm Transfer Protocol: On-call analyst briefs incoming shift within 15 minutes at each handoff using SBAR format (Situation, Background, Assessment, Recommendation)
- Executive Notification: P1 requires automated notification to CISO within 15 minutes; do not wait for full assessment


---

## 2. Detection & Initial Triage

### 2.1 Alert Sources

SIEM (Security Information & Event Management)
- Aggregates logs from network devices, endpoints, cloud, applications
- Correlation rules surface multi-stage attacks that individual tools miss
- Key SIEM platforms: Splunk Enterprise Security, Microsoft Sentinel, IBM QRadar, Elastic SIEM, Exabeam
- UEBA (User and Entity Behavior Analytics) detects anomalous patterns without predefined signatures

EDR (Endpoint Detection & Response)
- Real-time telemetry from endpoints: process trees, file writes, network connections, registry changes
- Key platforms: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Carbon Black
- Provides automated containment capability (host isolation with one command)

MSSP / MDR (Managed Security Service Providers)
- 24/7 SOC monitoring offloaded to third-party specialists
- Common providers: Secureworks (now part of Sophos), Arctic Wolf, Expel, Red Canary (acquired by Zscaler in 2025), Deepwatch
- Ensure SLA includes P1 escalation to client within 15 minutes

Threat Intelligence Feeds
- Commercial: Recorded Future, Google Threat Intelligence (formerly Mandiant Advantage), CrowdStrike Intelligence
- Open source: AbuseIPDB, AlienVault OTX, MISP community feeds, Emerging Threats rules

User Reports
- Phishing report button (Microsoft Report Message, KnowBe4 PAB)
- Help desk tickets: first line for detecting BEC, ransomware, insider threat
- Executive assistant reports of suspicious executive impersonation emails

Other Detection Sources
- Honeypots / deception technology (Thinkst Canary, Canarytokens)
- DLP alerts (data exfiltration to personal cloud, USB usage)
- DNS security (Cisco Umbrella, Infoblox, NextDNS): DNS request anomalies
- NDR (Network Detection & Response): Darktrace, ExtraHop, Vectra AI

---

### 2.2 Five-Minute Triage Checklist

Upon receiving an alert or report, complete the following within the first 5 minutes:

```
[ ] 1. Confirm alert source and timestamp (UTC)
[ ] 2. Identify affected host(s): hostname, IP, owner, criticality tier
[ ] 3. Identify affected user(s): username, department, admin privileges?
[ ] 4. Classify preliminary incident type (see taxonomy below)
[ ] 5. Assign initial severity (P1–P4)
[ ] 6. Open IR ticket and log initial observations
[ ] 7. Notify on-call IR lead if P1 or P2
[ ] 8. Begin evidence preservation (do NOT restart systems without authorization)
[ ] 9. Check for related alerts in SIEM (correlation search, ±2h window)
[ ] 10. Determine if incident is isolated or potentially widespread
```

---

### 2.3 Incident Type Taxonomy

| Category | Sub-type | Initial Indicators |
|----------|----------|-------------------|
| Ransomware | Crypto ransomware, wiper, double extortion | File extension changes, ransom note, EDR alert on shadow copy deletion |
| Business Email Compromise | CEO fraud, vendor impersonation, payroll diversion | Forwarding rules, impossible travel, financial request from exec |
| Insider Threat | Data theft, sabotage, privilege abuse | Large data transfers to personal cloud/USB, off-hours access, terminated employee activity |
| DDoS | Volumetric, protocol, application layer | Traffic spike, service unavailability, ISP notification |
| Data Breach | Exfiltration, accidental exposure, third-party breach | DLP alert, large outbound transfers, dark web mention |
| Account Compromise | Credential stuffing, phishing, MFA bypass | Impossible travel, unfamiliar MFA device, password spray in logs |
| Malware Infection | RAT, keylogger, cryptominer, botnet | EDR detection, C2 beaconing, unusual process execution |
| Supply Chain Attack | Software update compromise, vendor lateral movement | Legitimate signed binary with malicious behavior, unexpected vendor connections |
| Vulnerability Exploitation | Web app, network service, zero-day | WAF/IDS alerts, exploit-like traffic, unexpected process spawning from service |
| Physical Security | Tailgating, device theft, unauthorized access | Badge system alerts, missing assets, camera footage |

---

### 2.4 Initial Evidence Preservation Principles

Do NOT:
- Power off systems unless absolutely necessary (volatile memory will be lost)
- Reboot systems (clears RAM, modifies timestamps)
- Run antivirus scans on live systems (can destroy artifacts)
- Install software on potentially compromised systems
- Open suspicious files on your administrative workstation

DO:
- Capture volatile memory (RAM dump) with Winpmem, DumpIt, or EDR live response when it can be done without delaying containment; isolate affected systems promptly, and power down only if you cannot isolate them (powering down loses volatile evidence)
- Take forensic disk images before any remediation
- Preserve network logs, firewall logs, and proxy logs for the incident timeframe (±48h minimum)
- Screenshot active processes, network connections (netstat -ano), and logged-in users
- Document timestamps of all actions taken by responders
- Photograph physical evidence before moving

---

### 2.5 Chain of Custody Documentation

Every piece of evidence must have documented chain of custody from collection through legal proceedings:

Chain of Custody Form fields:
- Case/Incident number
- Evidence item number and description
- Acquisition date/time (UTC)
- Acquiring analyst name and role
- Hash values (MD5 + SHA-256) of acquired image
- Storage location and access controls
- All transfers: who transferred, when, to whom, why

Digital Evidence Handling:
- Store evidence on write-protected media or in read-only forensic containers
- Use forensic image formats: E01 (EnCase), AFF4, or raw DD with separate hash manifest
- Maintain original evidence; work only on forensic copies
- Use BitLocker or VeraCrypt encryption on evidence storage drives

---

### 2.6 IR Ticketing Platforms

TheHive
- SIRP (Security Incident Response Platform): NOTE: TheHive 5 is now a commercial StrangeBee product; the open-source TheHive repository (AGPLv3) is archived on GitHub. For a maintained open-source alternative see DFIR-IRIS (github.com/dfir-iris/iris-web)
- Integrates with MISP for IOC sharing and Cortex for automated enrichment
- Case templates for incident types; task management within cases
- Observable tracking: IP, domain, hash, email, URL with automatic enrichment
- Automate via the TheHive REST API or the thehive4py library (there is no official `thehive-cli`); the open-source TheHive repository is archived (see the note above)

ServiceNow Security Incident Response
- Enterprise ITSM integration; links security incidents to change management and asset management
- SLA tracking built-in; dashboards for MTTD/MTTR reporting
- Workflow automation for common playbooks
- Integrates with Splunk SOAR, IBM SOAR for automated enrichment

Jira + Security Plugin
- Flexible for teams already using Jira for project management
- Create IR project board with swimlanes (Triage / Active / Containment / Recovery / Closed)
- Link incidents to Confluence knowledge base articles and playbooks
- Automation rules: auto-assign P1 tickets, auto-notify Slack channel

SOAR Platforms (Complementary)
- Splunk SOAR (Phantom): Playbook automation, case management, IOC enrichment
- Palo Alto XSOAR: 700+ integrations, automated playbooks, threat intel management
- IBM Security SOAR: Enterprise-grade, compliance workflow integration

---

### 2.7 Initial Notification Template

Use this template for the first stakeholder notification (within 30 minutes of P1/P2 detection):

```
INCIDENT NOTIFICATION | [SEVERITY] | [INCIDENT ID]
Time: [UTC timestamp]
Detected: [How detected]
Affected Systems: [Hostname/IP/System name]
Affected Users: [Count/names if known]
Preliminary Classification: [Incident type]
Business Impact: [Current known impact]
Current Status: [Active investigation / Contained / etc.]
Next Update: [Time of next scheduled update]
IR Lead: [Name and contact]
```


---

## 3. Ransomware Response

### 3.1 Detection Indicators

EDR Alerts (High Fidelity)
- Shadow copy deletion: `vssadmin delete shadows /all`, `wmic shadowcopy delete`
- Mass file rename/encrypt events (thousands of file modifications in seconds)
- Ransomware note creation: `HOW_TO_DECRYPT.txt`, `README_FOR_DECRYPT.html`
- Known ransomware process hashes or behavioral signatures
- Disabling Windows Defender: `Set-MpPreference -DisableRealtimeMonitoring $true`

SIEM Correlation Rules
- Host generating >10,000 file write events per minute
- SMB lateral spread: single source accessing multiple remote shares
- Credential harvesting tools: Mimikatz, ProcDump targeting LSASS, secretsdump.py
- Cobalt Strike beacon patterns: regular callback intervals, HTTPS to unusual domains

User Reports
- "All my files have a weird extension and I can't open them"
- Ransom note visible on desktop
- Mapped drives showing encrypted files

---

### 3.2 Immediate Containment Steps

Step 1: Confirm and Escalate (0-5 min)
```
1. Verify it is ransomware (not false positive)
2. Immediately escalate to P1: notify IC, CISO, Legal
3. Activate IR team (all hands)
4. Open war room (bridge line + collaboration channel)
```

Step 2: Network Isolation (5-15 min)

*CrowdStrike Falcon (contain host):*
```bash
# Via Falcon console UI: Hosts > Find host > Contain
# Via API:
curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["<device_id>"]}'
```

*SentinelOne (network quarantine):*
```bash
# Via console: Sentinels > Select Agent > Actions > Isolate (Disconnect from Network)
# Via API: use the agent "Disconnect from Network" action in the SentinelOne API.
#   The exact path and request body vary by tenant/version - see your console's
#   API reference (Settings > Users > Service Users / API Token > API Doc).
```

*Carbon Black Cloud (quarantine endpoint):*
```bash
# No single-binary CLI; quarantine via one of:
# - Console: Investigate > select the device > Take Action > Quarantine
# - Devices API: POST /appservices/v6/orgs/{org_key}/device_actions  (action: QUARANTINE)
# - Python SDK (cbc_sdk): device.quarantine(True)
```

*Emergency Firewall Block (Palo Alto):*
```bash
# Block known C2 IP at perimeter (enter config mode with `configure` first)
set rulebase security rules BLOCK-C2 from any to any source any destination [ <C2_IP> ] application any service any action deny
commit
```

*Windows Firewall (emergency local block):*
```powershell
# Isolate host via Windows Firewall
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
# Or block specific C2:
netsh advfirewall firewall add rule name="BLOCK-C2" dir=out action=block remoteip=<C2_IP>
```

Step 3: Preserve Evidence (concurrent with containment)
```bash
# Memory dump (Windows): use winpmem or EDR live response
winpmem_mini_x64.exe memory.dmp

# Capture running processes
tasklist /v > processes.txt
wmic process get ProcessId,Name,CommandLine,ExecutablePath > wmic_processes.txt

# Capture network connections
netstat -ano > netstat.txt

# Collect event logs before they roll over
wevtutil epl System system.evtx
wevtutil epl Security security.evtx
wevtutil epl Application application.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" sysmon.evtx
```

---

### 3.3 Business Impact Assessment

Within 30-60 minutes of P1 declaration, the IC must assess:

| Question | Source |
|----------|--------|
| Which business functions are impacted? | Business liaisons |
| What revenue is at risk per hour of downtime? | Finance |
| Are safety systems affected (OT/ICS)? | Facilities/OT team |
| Are patient care systems affected? | Clinical leadership (healthcare) |
| What is the RTO for affected systems? | BCDR plan |
| Are cloud resources affected in addition to on-prem? | Cloud team |
| What is the backup status for affected systems? | Infrastructure team |

---

### 3.4 Patient Zero Investigation

Identifying the initial compromise vector is critical for eradication:

```
1. Review EDR telemetry for earliest ransomware-related activity
2. Correlate with email logs: phishing delivery at T-X hours?
3. Check VPN logs: remote access from unusual location at T-X?
4. Review RDP logs (Event ID 4624 Logon Type 10): brute force entry?
5. Check vulnerability scanner reports: recent unpatched systems?
6. Review software installation logs: malicious installer or update?
7. Query EDR for first occurrence of ransomware binary hash across fleet
8. Use EDR process tree to trace ransomware back to initial loader/dropper
```

---

### 3.5 Ransomware Family Identification

ID Ransomware (https://id-ransomware.malwarehunterteam.com)
- Upload a ransom note or an encrypted file sample (prefer a sanitized note or an expendable, non-sensitive sample; it is sent to a third party, so get authorization first and record what was shared)
- Identifies 1,000+ ransomware families
- Indicates if decryptor exists

VirusTotal
- Submit ransomware binary hash for family identification
- Check detections, behavioral analysis, and community comments

No More Ransom Project (https://www.nomoreransom.org)
- Law enforcement + industry partnership offering free decryptors
- Check before paying ransom or beginning lengthy recovery

Common Ransomware Families & Indicators:

| Family | Extension | Ransom Note | Known Vector |
|--------|-----------|-------------|--------------|
| LockBit | `.lockbit` | `Restore-My-Files.txt` (2.0; 3.0 uses `<id>.README.txt`) | RDP, phishing |
| BlackCat/ALPHV | `.sykzx` (random) | `RECOVER-<id>-FILES.txt` | Stolen creds, ESXi vulns |
| Cl0p | `.clop` | `ClopReadMe.txt` | MOVEit/GoAnywhere exploitation |
| REvil/Sodinokibi | `.random` | `<ext>-readme.txt` (note name reuses the random extension) | RDP, supply chain |
| Conti | `.CONTI` | `CONTI_README.txt` | BazarLoader, TrickBot |
| Royal | `.royal` | `README.TXT` | Phishing, RDP |

Status (as of 2026): treat these as historical signatures and cross-check current families. Conti disbanded in 2022; REvil/Sodinokibi is defunct; ALPHV/BlackCat had its infrastructure disrupted and leak site seized in an FBI-led action in December 2023 (CISA AA23-353A), then collapsed in an apparent exit scam in early 2024; LockBit was disrupted by Operation Cronos in 2024; Royal rebranded to BlackSuit in 2023.

---

### 3.6 Law Enforcement Notification

FBI via IC3 (https://www.ic3.gov)
- File a complaint for ransomware incidents regardless of whether you pay
- FBI may have decryption keys for specific variants seized during takedowns
- Proactive engagement can accelerate law enforcement investigation

CISA Reporting
- Report to CISA at https://www.cisa.gov/report or call 1-844-SAY-CISA (1-844-729-2472)
- CISA may provide technical assistance and threat intelligence

What to Include in LE Reports:
- Incident timeline and discovery circumstances
- Ransomware family (if identified)
- Ransom demand amount and cryptocurrency wallet address
- Known IOCs (IP addresses, domains, file hashes)
- Extent of data accessed or exfiltrated

---

### 3.7 Recovery Sequencing

Recover in dependency order; never reconnect compromised systems to clean networks:

```
Phase 1: Validate backup integrity (hash comparison, test restore in isolated environment)
Phase 2: Rebuild identity infrastructure (AD DCs, PKI) in an isolated recovery environment, following Microsoft's Active Directory forest recovery plan: restore a verified backup predating the compromise, validate domain and PKI trust, and rotate credentials and keys before reconnecting
Phase 3: Restore critical business systems (ERP, email, CRM), prioritized by business impact
Phase 4: Restore user endpoints, reimaging preferred over cleaning
Phase 5: Reconnect systems to network in stages with enhanced monitoring
Phase 6: Validate functionality and business operations
Phase 7: Return to normal operations with sustained enhanced monitoring
```

---

### 3.8 Post-Ransomware Hardening Checklist

```
[ ] Implement or enforce MFA on all remote access (VPN, RDP, cloud apps)
[ ] Disable RDP externally; restrict to jump host with MFA
[ ] Patch all externally-facing systems within 48h of critical CVE publication
[ ] Implement network segmentation to limit lateral movement
[ ] Deploy immutable backups (3-2-1-1: 3 copies, 2 media, 1 offsite, 1 immutable)
[ ] Enable Credential Guard and LSA Protection on all Windows endpoints
[ ] Block common living-off-the-land tools (wscript, cscript, mshta, regsvr32) where not needed
[ ] Enable PowerShell logging (script block, module, transcription)
[ ] Deploy application allowlisting on servers
[ ] Test backup restoration quarterly
[ ] Implement privileged access workstations (PAWs) for admin tasks
[ ] Enable EDR prevention mode (not just detection mode)
[ ] Reset krbtgt account password twice (24h apart) if AD compromise is confirmed
[ ] Rotate all service account and privileged account credentials post-incident
```


---

## 4. Business Email Compromise Response

### 4.1 BEC Attack Types

| BEC Type | Description | Key Indicator |
|----------|-------------|---------------|
| CEO Fraud | Attacker impersonates CEO/executive to request urgent wire transfer | Email from lookalike domain; pressure for secrecy |
| Vendor Impersonation | Compromised or spoofed vendor email requests change to payment banking details | Invoice with new bank account; urgency |
| Payroll Diversion | Attacker poses as employee to redirect payroll to attacker-controlled account | HR email request from personal address; recent password reset |
| W-2 / Tax Fraud | Impersonation of executive requesting employee W-2 data | Annual spike during tax season; targets HR/payroll staff |
| Attorney Impersonation | Fake lawyer contact regarding confidential acquisition needing urgent funds | Pressure for secrecy; unusual request channel |
| Gift Card Fraud | Impersonation requests purchase of gift cards "for employees" | Unusual purchase request; urgency |

---

### 4.2 Microsoft 365 Investigation

Search-UnifiedAuditLog (PowerShell)
```powershell
# Search audit log for suspicious mailbox activity
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

# Find forwarding rules created
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
  -Operations "New-InboxRule","Set-InboxRule" `
  -ResultSize 1000 | Select-Object -ExpandProperty AuditData | ConvertFrom-Json

# Find email sent to external addresses
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
  -Operations "Send" -UserIds "victim@company.com" `
  -ResultSize 5000

# Check for mailbox permission changes
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
  -Operations "Add-MailboxPermission","AddFolderPermission"

# Find OAuth app consent grants
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
  -Operations "Consent to application"
```

Message Trace (Exchange Online) - Get-MessageTrace is being replaced by Get-MessageTraceV2 and will eventually be deprecated. Get-MessageTraceV2 searches the last 90 days but returns at most 10 days of data per query; use Start-HistoricalSearch for longer look-backs
```powershell
# Trace messages for a compromised user (last 10 days; for older data use historical search in the admin center)
Get-MessageTraceV2 -SenderAddress "victim@company.com" `
  -StartDate (Get-Date).AddDays(-10) `
  -EndDate (Get-Date) | Export-Csv message_trace.csv

# Find messages containing a specific subject (e.g., invoice-related)
Get-MessageTraceV2 -SenderAddress "vendor@partner.com" `
  -StartDate (Get-Date).AddDays(-10) | Where-Object {$_.Subject -like "*invoice*"}
```

Hawk Tool (Open Source BEC Investigation)
```powershell
# Install Hawk
Install-Module -Name Hawk -Force

# Run full tenant investigation
Start-HawkTenantInvestigation

# Investigate specific user
Start-HawkUserInvestigation -UserPrincipalName victim@company.com

# Hawk collects: mailbox rules, delegates, admin changes, sign-in logs, OAuth grants
```

Microsoft Entra ID Sign-in Investigation
```powershell
# Via Graph PowerShell: get sign-in logs for user
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'victim@company.com'" `
  -Top 200 | Select CreatedDateTime, IpAddress, Location, ClientAppUsed, ConditionalAccessStatus

# Look for:
# - Impossible travel (logins from multiple countries in short time)
# - Unfamiliar ASN/ISP (especially VPN/proxy providers)
# - Legacy auth protocols (IMAP/POP/BasicAuth)
# - MFA bypasses or MFA fatigue attacks
```

---

### 4.3 Google Workspace Audit Logs

```bash
# Admin SDK Reports API: OAuth token activity (third-party app grants)
curl "https://admin.googleapis.com/admin/reports/v1/activity/users/victim@company.com/applications/token" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Check login activity
curl "https://admin.googleapis.com/admin/reports/v1/activity/users/victim@company.com/applications/login" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# List Gmail filters/forwarding rules via Admin console:
# Admin Console > Users > [user] > Security > View third-party app access
# Admin Console > Reports > Audit > Gmail

# GAM (Google Apps Manager) commands:
gam user victim@company.com show filters
gam user victim@company.com show forwards
gam user victim@company.com show delegates
gam user victim@company.com show imap
gam user victim@company.com show pop
```

---

### 4.4 Compromised Account Remediation

Immediate Actions (within minutes of confirmation):
```powershell
# Connect with the scopes these actions need (the AzureAD module is deprecated; use Microsoft Graph).
# Resetting another user's password needs User-PasswordProfile.ReadWrite.All (least-privileged) plus a role that can
# reset the target: delegated, the signed-in admin needs e.g. Helpdesk/User/Password Administrator for members, or
# Privileged Authentication Administrator for admins. App-only is supported if the app itself holds at least the
# User Administrator role (Privileged Authentication Administrator to reset administrators).
Connect-MgGraph -Scopes "User.ReadWrite.All","User-PasswordProfile.ReadWrite.All"

# Revoke all active sessions / refresh tokens (M365)
Revoke-MgUserSignInSession -UserId <user-id>

# Disable account temporarily
Update-MgUser -UserId <user-id> -AccountEnabled:$false

# Force a password reset at next sign-in
Update-MgUser -UserId <user-id> -PasswordProfile @{ ForceChangePasswordNextSignIn = $true; Password = "<NewSecurePassword>" }

# Remove all inbox rules
Get-InboxRule -Mailbox victim@company.com | Remove-InboxRule -Confirm:$false

# Remove forwarding addresses
Set-Mailbox -Identity victim@company.com -DeliverToMailboxAndForward $false `
  -ForwardingSmtpAddress $null -ForwardingAddress $null

# Revoke OAuth app access
# Microsoft Entra admin center > Enterprise Applications > review and remove malicious apps

# Re-enable with MFA enforced
# Verify MFA method is a legitimate device (not attacker-added)
```

Review and Remove Attacker Artifacts:
- All inbox rules (especially forwarding, move-to-folder, delete)
- Mailbox delegates and Full Access permissions
- OAuth application consents
- Additional email addresses or aliases added
- Changes to out-of-office messages (used to confirm account is active)
- Sent items reviewed for data exfiltration or fraud emails sent

---

### 4.5 Financial Transaction Recall Process

Immediate (within hours of discovery):
1. Contact your bank's fraud department immediately: time is critical (hours, not days)
2. Request SWIFT recall message (gpi STOP payment) if wire has been sent
3. Request the receiving bank freeze the funds: banks can hold for 24-72h pending investigation
4. Obtain wire transfer confirmation number, beneficiary account, and receiving bank SWIFT code

FBI IC3 Financial Fraud Kill Chain
- Submit complaint at https://www.ic3.gov
- For active wire fraud, call FBI Financial Fraud (1-800-CALL-FBI) immediately
- IC3's FFKC can freeze funds in transit: success rate highest within first few hours
- Provide: sender/receiver account info, wire amount, transfer date/time, beneficiary bank info

Supporting Documentation:
- Original fraudulent email headers (full)
- Wire transfer confirmation
- Internal approval chain documentation
- All communications with attacker (preserve originals)

---

### 4.6 BEC Indicators of Compromise

Email Header Red Flags:
```
# Check Return-Path vs From header mismatch
# Check Reply-To header pointing to attacker domain
# Check X-Originating-IP for unexpected geolocation
# Verify DKIM signature and DMARC policy alignment
# Check if domain is registered recently (WHOIS lookup)

# Full header analysis tools:
# - MXToolbox Header Analyzer: https://mxtoolbox.com/EmailHeaders.aspx
# - Google Admin Toolbox: https://toolbox.googleapps.com/apps/messageheader/
```

Common Attacker Infrastructure Patterns:
- Lookalike domains: `company-inc.com`, `company.co`, `cornpany.com` (rn vs m)
- Free email services: Gmail, Yahoo, Outlook accounts impersonating executives
- VPN/proxy exit nodes in Eastern Europe or Southeast Asia
- Fast-flux infrastructure for C2


---

## 5. Endpoint Forensics

### 5.1 Live Response Platforms

CrowdStrike Real Time Response (RTR)
```bash
# Connect to host via RTR
# Falcon Console > Hosts > Select Host > Real Time Response

# RTR commands:
ls C:\\Users\\victim\\Downloads     # List directory
cat C:\\Users\\victim\\Desktop\\ransom.txt  # Read file
ps                                  # List processes
netstat                             # Network connections
reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run  # Startup entries
get C:\\Windows\\Temp\\malware.exe  # Download file for analysis
put evil_hunter.exe                 # Upload tool to host
run evil_hunter.exe --scan          # Execute uploaded tool
```

SentinelOne Remote Shell
```bash
# Via console: Sentinels > Agent > Remote Shell
# Available commands: Similar to RTR, file ops, process listing, network state

# Key commands:
dir /s /b C:\Users\*\AppData\Roaming\*.exe  # Find executables in AppData
netstat -ano                                  # Active connections with PIDs
tasklist /v /fo csv                          # Verbose process list
wmic process where "name='malware.exe'" get commandline  # Get command line
```

Velociraptor (Open Source Live Response)
```yaml
# Query for suspicious processes
SELECT Pid, Name, CommandLine, Exe, hash(path=Exe).SHA256 AS SHA256
FROM pslist()
WHERE Name =~ "powershell|cmd|wscript|mshta|regsvr32"

# Find recently modified executables
SELECT OSPath, Mtime, Size, hash(path=OSPath).SHA256 AS SHA256
FROM glob(globs="C:/Users/**/*.exe")
WHERE Mtime > now() - 86400  # Last 24 hours

# Network connections
SELECT Pid, FamilyString, Status, Laddr, Raddr, Timestamp
FROM netstat()
WHERE Status = "ESTABLISHED" AND NOT Raddr.IP =~ "^(10\\.|172\\.16\\.|192\\.168\\.)"

# Deploy artifact collection
velociraptor.exe -v artifacts collect Windows.KapeFiles.Targets --output collection.zip
```

---

### 5.2 Windows Forensic Artifacts

Critical Windows Event Log IDs

| Event ID | Description | Log Source | IR Relevance |
|----------|-------------|-----------|--------------|
| 4624 | Successful logon | Security | Track attacker movement; check Logon Type |
| 4625 | Failed logon | Security | Brute force detection |
| 4627 | Group membership on logon | Security | Privilege escalation detection |
| 4648 | Logon with explicit credentials (runas) | Security | Lateral movement |
| 4663 | File access attempt | Security | Data access/exfiltration |
| 4688 | Process creation | Security (requires policy) | Malicious process execution |
| 4698 | Scheduled task created | Security | Persistence mechanism |
| 4720 | User account created | Security | Backdoor account creation |
| 4732 | Member added to security group | Security | Privilege escalation |
| 4768 | Kerberos TGT request | Security | Account usage, pass-the-hash |
| 4769 | Kerberos service ticket request | Security | Lateral movement via Kerberoasting |
| 4776 | NTLM authentication | Security | Pass-the-hash, NTLM relay |
| 7034 | Service crashed unexpectedly | System | Malware stability issues |
| 7045 | New service installed | System | Malware/backdoor persistence |
| 1102 | Audit log cleared | Security | Anti-forensic activity |

Logon Type Reference:
- Type 2: Interactive (console)
- Type 3: Network (SMB, shared resources)
- Type 4: Batch (scheduled tasks)
- Type 5: Service logon
- Type 7: Unlock workstation
- Type 10: Remote Interactive (RDP)
- Type 11: Cached interactive

Prefetch Analysis
```powershell
# Location: C:\Windows\Prefetch\*.pf
# Parse with PECmd (Eric Zimmerman)
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Evidence" --csvf prefetch.csv
# Reveals: execution count, last run times, files accessed, directories accessed
```

ShimCache (AppCompatCache)
```powershell
# Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
# Parse with AppCompatCacheParser (Eric Zimmerman)
AppCompatCacheParser.exe --csv "C:\Evidence" -t
# Reveals: programs that ran (and many that didn't, shimcache ≠ execution)
# Useful for finding malware even after deletion
```

Amcache
```powershell
# Location: C:\Windows\AppCompat\Programs\Amcache.hve
# Parse with AmcacheParser (Eric Zimmerman)
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Evidence"
# Reveals: SHA1 hashes of executed programs, install paths, compile timestamps
```

LNK Files (Shortcut Files)
```powershell
# Locations:
# C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\
# C:\Users\*\AppData\Roaming\Microsoft\Office\Recent\
# Parse with LECmd (Eric Zimmerman)
LECmd.exe -d "C:\Users\victim\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Evidence"
# Reveals: accessed files (even if deleted), target path, MAC times, volume serial number
```

MFT ($MFT)
```powershell
# Master File Table: metadata for every file on NTFS volume
# Parse with MFTECmd (Eric Zimmerman)
MFTECmd.exe -f "C:\$MFT" --csv "C:\Evidence" --csvf mft.csv
# Reveals: file creation/modification/access times, deleted file names
# Anti-forensics: timestomping modifies Standard Information timestamps but not $FN timestamps
```

---

### 5.3 Linux Forensic Artifacts

Log Files
```bash
# Authentication logs
/var/log/auth.log          # Debian/Ubuntu: SSH, sudo, PAM
/var/log/secure            # RHEL/CentOS: SSH, sudo
/var/log/wtmp              # Binary: login history (parse with 'last')
/var/log/btmp              # Binary: failed logins (parse with 'lastb')
/var/log/lastlog           # Binary: last login per user

# System logs
/var/log/syslog            # General system events
/var/log/kern.log          # Kernel events
journalctl -xe             # systemd journal: all logs
journalctl -u sshd         # SSH service logs specifically

# Web server logs
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/httpd/access_log
```

User Activity
```bash
# Bash history (often incomplete: attacker may clear)
~/.bash_history
~/.zsh_history
# Check HISTFILE variable and HISTSIZE

# Reconstruct commands from other artifacts:
strings /proc/<pid>/environ  # Environment variables of running process
ls -la /proc/<pid>/fd/       # Open file descriptors
cat /proc/<pid>/cmdline      # Command line of process (null-delimited)
```

Persistence Locations
```bash
# Cron jobs
/etc/cron*                  # System cron directories
/var/spool/cron/crontabs/*  # User crontabs
crontab -l -u root          # List root crontab

# Startup scripts
/etc/rc.local
/etc/init.d/
/etc/systemd/system/        # systemd service files
grep -l "ExecStart" /etc/systemd/system/*.service   # service units that define an ExecStart

# SSH authorized keys (common backdoor location)
~/.ssh/authorized_keys
/root/.ssh/authorized_keys
```

Temporary and Suspicious Locations
```bash
# Common malware drop locations
ls -la /tmp/
ls -la /dev/shm/           # Shared memory, often used by in-memory malware
ls -la /var/tmp/
find / -name ".*" -type f -newer /tmp -maxdepth 4 2>/dev/null  # Hidden recent files
```

---

### 5.4 macOS Forensic Artifacts

Unified Log
```bash
# Parse unified log
log show --predicate 'eventMessage contains "sudo"' --last 7d
log show --style syslog --last 24h > unified_log.txt

# Key processes to filter:
# loginwindow, sudo, sshd, bash, python, curl, osascript
```

Persistence Mechanisms
```bash
# LaunchAgents and LaunchDaemons (most common persistence)
ls -la ~/Library/LaunchAgents/          # User LaunchAgents
ls -la /Library/LaunchAgents/           # System LaunchAgents
ls -la /Library/LaunchDaemons/          # System LaunchDaemons (root)
ls -la /System/Library/LaunchDaemons/   # Apple LaunchDaemons

# Parse plist files:
plutil -p ~/Library/LaunchAgents/com.malware.plist

# Login Items
osascript -e 'tell application "System Events" to get the name of every login item'
```

FSEvents
```bash
# File system event log: records all file system changes
# Location: /.fseventsd/
# Parse with FSEParser (the FSEventsParser project) or mac_apt
python3 FSEParser_V4.py -s /.fseventsd/ -o /evidence/fsevents -t folder
```

---

### 5.5 KAPE (Kroll Artifact Parser and Extractor)

KAPE rapidly collects and processes forensic artifacts from live systems or mounted images.

Common Triage Targets:
```powershell
# Collect key artifacts for IR (run as Administrator)
kape.exe --tsource C: --tdest "D:\Evidence\Collection" ^
  --target "!BasicCollection,Antivirus,Chrome,Edge,EventLogs,Firefox,$MFT,Prefetch,RecycleBin,RegistryHives,ScheduledTasks,WebBrowsers"

# Full collection for ransomware:
kape.exe --tsource C: --tdest "D:\Evidence\Ransomware" ^
  --target "!BasicCollection,Antivirus,EventLogs,$MFT,Prefetch,RegistryHives,ScheduledTasks,Amcache"

# Process collected artifacts immediately
kape.exe --msource "D:\Evidence\Collection" --mdest "D:\Evidence\Processed" ^
  --module "!EZParser"  # Runs all Eric Zimmerman parsers
```

KAPE Module Outputs:
- Parsed prefetch CSV with execution times
- Parsed event log CSVs (Security, System, Application, Sysmon)
- Shimcache and Amcache CSVs
- LNK file details
- Browser history (Chrome, Edge, Firefox)
- Scheduled tasks XML


---

## 6. Network Forensics

### 6.1 Evidence Sources

| Source | Data Captured | Retention Typical | IR Value |
|--------|--------------|------------------|----------|
| Firewall Logs | Allow/deny decisions, source/dest IP+port, bytes | 30-90 days | Lateral movement, exfiltration volume |
| Proxy Logs | HTTP/HTTPS request URLs, user-agent, response codes | 30-90 days | C2 beacon patterns, exfiltration URLs |
| DNS Logs | Query/response, requester IP, record type | 7-30 days | DGA domains, DNS tunneling, C2 |
| NetFlow/IPFIX | 5-tuple summary, bytes/packets, duration | 30-90 days | Traffic volume analysis, lateral movement |
| PCAP (Full Packet) | Complete network traffic content | Hours to days (expensive) | Deep protocol analysis, data recovery |
| IDS/IPS Alerts | Signature matches with packet context | 30-90 days | Known attack signatures |
| VPN/Remote Access | User, source IP, session duration, bytes | 30-90 days | Initial access vector |
| Email Gateway | SMTP metadata, attachment hashes | 30-90 days | Phishing delivery, BEC |
| NDR Platform | Behavioral anomalies, protocol analysis | 30-90 days | Zero-day detection, insider |

---

### 6.2 Zeek Log Analysis for IR

Zeek (formerly Bro) generates structured logs that are ideal for IR investigations. Key log types:

conn.log: All network connections
```bash
# Find connections to suspicious IP
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes | \
  grep "203.0.113.66"

# Find large data transfers (potential exfiltration): bytes >10MB
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes | \
  awk '$4 > 10485760 {print}' | sort -k4 -rn | head -20

# Connections by destination country (requires GeoIP)
cat conn.log | zeek-cut id.orig_h id.resp_h | sort | uniq -c | sort -rn
```

http.log: HTTP requests
```bash
# Find POST requests (potential exfiltration or C2)
cat http.log | zeek-cut method id.orig_h id.resp_h uri user_agent request_body_len | \
  grep "^POST" | sort -t$'\t' -k6,6 -rn   # zeek-cut is tab-delimited; user_agent has spaces, so sort the tab field

# Suspicious user agents (PowerShell, Python, curl in production HTTP)
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -rn | head -30

# Requests to newly observed domains
cat http.log | zeek-cut host uri | sort -u
```

dns.log: DNS queries
```bash
# High volume of failed DNS queries (DGA or beaconing)
cat dns.log | zeek-cut id.orig_h query qtype_name rcode_name | \
  grep "NXDOMAIN" | awk '{print $1, $2}' | sort | uniq -c | sort -rn | head -20

# Long subdomains (DNS tunneling)
cat dns.log | zeek-cut query | awk 'length($1) > 50 {print}' | sort -u

# DNS queries from unexpected internal hosts
cat dns.log | zeek-cut id.orig_h query | grep -v "10\." | head -50
```

ssl.log: SSL/TLS connections
```bash
# Self-signed or invalid certificates (common for C2)
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name validation_status | \
  grep -v "ok" | grep -v "^-"

# JA3 fingerprint lookup for known malware/C2 families
cat ssl.log | zeek-cut ja3 ja3s server_name | sort -u

# Connections without SNI (Server Name Indication): suspicious
cat ssl.log | zeek-cut server_name id.orig_h id.resp_h | grep "^-" | head -20
```

files.log: File transfers
```bash
# Extract file hashes for all transferred files
cat files.log | zeek-cut sha256 mime_type tx_hosts rx_hosts | grep -v "^-"

# Look for executable transfers
cat files.log | zeek-cut sha256 mime_type source | \
  grep -E "application/x-dosexec|application/x-executable|application/x-msdos-program"
```

---

### 6.3 Wireshark Display Filters for C2 Detection

```
# HTTP C2 beaconing (regular intervals to same host)
http.request.method == "POST" && ip.dst == 203.0.113.66

# DNS tunneling (long subdomains, high TXT query volume)
dns.qry.name.len > 50
dns.qry.type == 16  # TXT records: common in DNS tunneling

# Suspicious TCP connections
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst_host matches ".*\\.ru$"

# Cobalt Strike common listener/team-server ports (tune to your environment)
tcp.port == 4444 || tcp.port == 8080 || tcp.port == 8443

# TLS alert: bad certificate
tls.alert_message.desc == 42

# ICMP tunneling detection
icmp.type == 8 && frame.len > 100  # Large ICMP echo requests

# SMB lateral movement
smb2.cmd == 3 && smb2.tree contains "ADMIN$"  # Tree connect to the ADMIN$ share (contains is case-sensitive; the share is upper-case on the wire)

# Kerberoasting traffic
kerberos.msg_type == 12 && kerberos.etype == 23  # RC4 encryption: Kerberoast indicator

# Pass-the-Hash NTLM indicators
ntlmssp.messagetype == 3 && ip.src != ip.dst  # NTLM auth from unexpected source
```

---

### 6.4 Data Exfiltration Volume Analysis

```bash
# Using NetFlow data: identify top talkers by destination
nfdump -r /var/cache/nfdump/ -n 20 -s ip/bytes \
  -t 2026/05/03.00:00:00-2026/05/04.00:00:00 \
  -o "fmt:%sa %da %byt %pkt %fl"

# Filter outbound traffic over 1GB to single destination
nfdump -r /var/cache/nfdump/ \
  "src net 10.0.0.0/8 and dst net not 10.0.0.0/8" \
  -a -n 100 -s dstip/bytes | awk '$3 > 1073741824'

# Baseline comparison: compare current week to prior 4-week average
# Flag any destination with >3 standard deviations above baseline

# Key thresholds for exfiltration alerts:
# - >1GB to single external IP in <1 hour
# - >100MB via DNS in <24 hours (DNS tunneling)
# - Outbound HTTPS to newly registered domain (< 30 days old)
# - After-hours large transfers from non-batch systems
```

---

### 6.5 DNS Tunneling Detection Patterns

DNS tunneling encodes data within DNS queries/responses to bypass network controls.

Detection Indicators:
- Query length > 50 characters in subdomain portion
- High entropy in subdomain labels (random-looking: `aGVsbG8gd29ybGQ.attacker.com`)
- Volume: > 1,000 DNS queries/hour to single domain from single host
- Unusual record types: TXT, NULL, CNAME, MX being queried repeatedly
- NXDOMAIN ratio < 5% (tunneling tools use valid responses)
- Subdomain label count > 5

Tools for DNS Tunnel Detection:
```bash
# DNScat2 (common tool) network signature:
# Queries to *.c2domain.com with base32/hex encoded subdomains

# iodine signature:
# Queries starting with version handshake subdomain 'v[version]'

# Passive DNS analysis with Zeek:
cat dns.log | zeek-cut query | \
  awk -F. '{for(i=1;i<=NF-2;i++) printf $i "."; print ""}' | \
  awk '{print length($0), $0}' | sort -rn | head -20
```

---

### 6.6 Lateral Movement in Network Logs

Indicators in Firewall Logs:
- Single source IP connecting to multiple internal hosts on ports 445 (SMB), 135 (RPC), 3389 (RDP)
- Sequential connection pattern to entire IP range (scanner behavior)
- Service account authenticating from unexpected source workstation

Indicators in DNS Logs:
- New internal host resolving many other internal hostnames rapidly (reconnaissance)
- Reverse DNS lookups for entire internal subnets

Indicators in NetFlow:
- East-west traffic spikes (workstation-to-workstation)
- Connections between security zones that violate firewall policy

Timeline Construction from Multiple Sources:
```
1. Establish T0 (initial compromise time) from EDR or email gateway
2. Build timeline: for each hop, record:
   - Source host, destination host
   - Protocol and port used
   - Authentication method (Kerberos ticket, NTLM, SSH key)
   - Tools used (from EDR process telemetry)
   - Files accessed or copied
3. Map to ATT&CK techniques (Lateral Movement: T1021.002 SMB/Windows Admin Shares, etc.)
4. Identify "blast radius": all systems the attacker touched
5. Prioritize forensic investigation based on dwell time and data access
```


---

## 7. Cloud Incident Response

### 7.1 AWS Incident Response

CloudTrail: Key Suspicious API Calls

| API Call | Service | IR Significance |
|----------|---------|----------------|
| `ConsoleLogin` | AWS Sign-In | Successful/failed console logins (event source signin.amazonaws.com) |
| `CreateUser` | IAM | New IAM user (backdoor creation) |
| `AttachUserPolicy` / `PutUserPolicy` | IAM | Privilege escalation |
| `CreateAccessKey` | IAM | New API key (persistence) |
| `AssumeRole` | STS | Role assumption: check unusual principals |
| `GetSecretValue` | Secrets Manager | Secret exfiltration |
| `GetPasswordData` | EC2 | Windows instance password retrieval |
| `CreateKeyPair` | EC2 | New SSH key (persistence) |
| `AuthorizeSecurityGroupIngress` | EC2 | Firewall rule opened |
| `ModifyInstanceAttribute` | EC2 | Instance modification |
| `RunInstances` | EC2 | New instance launched (crypto mining) |
| `PutBucketPolicy` | S3 | Bucket policy changed (data exposure) |
| `GetObject` (high volume) | S3 | Data exfiltration from S3 |
| `CreateFunction` | Lambda | New Lambda (persistence/execution) |
| `UpdateFunctionCode` | Lambda | Lambda code modification |
| `DescribeInstances` | EC2 | Reconnaissance |

GuardDuty Finding Types (High Priority)
- `UnauthorizedAccess:IAMUser/TorIPCaller`: API calls from Tor exit nodes
- `UnauthorizedAccess:EC2/TorClient`: EC2 instance connecting to Tor
- `Backdoor:EC2/C&CActivity.B`: Known C2 communication
- `CryptoCurrency:EC2/BitcoinTool.B`: Crypto mining activity
- `Stealth:IAMUser/PasswordPolicyChange`: Weakening password policy
- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`: Unusual console login
- `Persistence:IAMUser/AnomalousBehavior`: Anomalous IAM persistence activity (the per-API `NetworkPermissions` type was retired)
- `PrivilegeEscalation:IAMUser/AnomalousBehavior`: Anomalous privilege-escalation activity (the per-API `AdministrativePermissions` type was retired)

AWS CLI Forensic Commands
```bash
# List all IAM users and their last activity
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  python3 -c "import sys,csv; [print(r) for r in csv.DictReader(sys.stdin)]"

# Find access keys created in last 30 days
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} aws iam list-access-keys --user-name {} \
  --query 'AccessKeyMetadata[?CreateDate>`2026-04-04`]'

# List all EC2 instances with their security groups
aws ec2 describe-instances --query \
  'Reservations[*].Instances[*].{ID:InstanceId,IP:PublicIpAddress,SG:SecurityGroups}' \
  --output table

# Check CloudTrail events for specific user (last 24h)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=suspicious_user \
  --start-time $(date -d "24 hours ago" -u +"%Y-%m-%dT%H:%M:%SZ") \
  --output json | jq '.Events[].CloudTrailEvent | fromjson'   # CloudTrailEvent is a JSON string; fromjson parses each event

# Find S3 buckets with public access
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  xargs -I {} aws s3api get-bucket-acl --bucket {}

# List Lambda functions modified recently
aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Modified:LastModified}' \
  --output table | sort -k2
```

AWS Containment Actions
```bash
# Isolate EC2 instance: attach a security group with no allowed traffic.
# A new security group has no inbound rules but a DEFAULT rule allowing ALL outbound,
# so revoke that egress rule or the instance keeps talking out. Security groups are
# allow-only; use a restrictive network ACL to express an explicit deny.
aws ec2 create-security-group \
  --group-name "INCIDENT-ISOLATION-$(date +%Y%m%d)" \
  --description "IR isolation - no allowed traffic" \
  --vpc-id vpc-xxxx

aws ec2 revoke-security-group-egress \
  --group-id sg-isolation-group-id \
  --ip-permissions IpProtocol=-1,IpRanges='[{CidrIp=0.0.0.0/0}]'

aws ec2 modify-instance-attribute \
  --instance-id i-xxxx \
  --groups sg-isolation-group-id

# Disable IAM user (compromised credential)
aws iam delete-login-profile --user-name compromised_user   # removes console password (update-login-profile does not disable access)
aws iam update-access-key --user-name compromised_user --access-key-id AKIAXXXX --status Inactive
aws iam attach-user-policy --user-name compromised_user \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

# Snapshot EC2 for forensics before remediation
aws ec2 create-snapshot --volume-id vol-xxxx \
  --description "IR-FORENSIC-$(date +%Y%m%d)-case-001"
```

---

### 7.2 Azure Incident Response

Entra ID Sign-in Log Investigation (KQL)
```kql
// Find sign-ins from high-risk locations for specific user
SigninLogs
| where UserPrincipalName == "victim@company.com"
| where TimeGenerated > ago(30d)
| where RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, IPAddress, Location, DeviceDetail, Status, ConditionalAccessStatus
| order by TimeGenerated desc

// Impossible travel detection
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0  // Successful sign-in
| summarize SignIns = make_list(pack('time', TimeGenerated, 'ip', IPAddress,
    'location', Location, 'city', LocationDetails.city)) by UserPrincipalName
| mv-expand SignIns
// Additional logic needed to calculate travel speed between consecutive logins

// Find MFA bypass attempts
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where Status.additionalDetails contains "MFA"
| where ResultType != 0
| summarize count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where count_ > 5  // MFA fatigue pattern
```

Azure Activity Log Investigation (KQL)
```kql
// Find new role assignments (privilege escalation)
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceGroup, Properties

// Find unusual resource creations (cryptomining, persistence)
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue endswith "/WRITE"
| where ActivityStatusValue == "Success"
| where ResourceProviderValue in ("MICROSOFT.COMPUTE", "MICROSOFT.WEB", "MICROSOFT.LOGIC")
| summarize count() by Caller, ResourceProviderValue, bin(TimeGenerated, 1h)
| where count_ > 10

// Audit policy and security setting changes
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has_any ("POLICY", "SECURITY", "DEFENDER", "SENTINEL")
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue
```

Azure Containment Actions
```bash
# Disable compromised service principal
az ad sp update --id <service-principal-id> --set accountEnabled=false

# Block compromised user account
az ad user update --id victim@company.com --account-enabled false

# Remove malicious role assignment
az role assignment delete --assignee <principal-id> \
  --role "Contributor" --scope /subscriptions/<sub-id>

# Isolate Azure VM: a new NSG keeps Azure's default rules (AllowVnetInBound,
# AllowVnetOutBound, AllowInternetOutBound), so add explicit deny rules that outrank them.
az network nsg create --resource-group IR-RG --name INCIDENT-ISOLATION
az network nsg rule create --resource-group IR-RG --nsg-name INCIDENT-ISOLATION \
  --name deny-all-out --priority 100 --direction Outbound --access Deny --protocol '*' \
  --source-address-prefixes '*' --destination-address-prefixes '*' \
  --source-port-ranges '*' --destination-port-ranges '*'
az network nsg rule create --resource-group IR-RG --nsg-name INCIDENT-ISOLATION \
  --name deny-all-in --priority 100 --direction Inbound --access Deny --protocol '*' \
  --source-address-prefixes '*' --destination-address-prefixes '*' \
  --source-port-ranges '*' --destination-port-ranges '*'
# Attach the isolation NSG to the VM's NIC
az network nic update --resource-group <rg> --name <nic> \
  --network-security-group INCIDENT-ISOLATION

# Take forensic snapshot
az snapshot create --resource-group IR-RG \
  --name forensic-snapshot-$(date +%Y%m%d) \
  --source /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/disks/<disk>
```

---

### 7.3 GCP Incident Response

Cloud Audit Log Types:
- Admin Activity logs: API calls that modify configuration (always enabled, cannot disable)
- Data Access logs: API calls that read data or metadata (disabled by default except for some BigQuery services; enable for IR)
- System Event logs: Google Cloud system events (always enabled)
- Policy Denied logs: Failed access due to policy (enabled by default)

Key GCP CLI Commands for IR
```bash
# List recent admin activity for project
gcloud logging read 'logName="projects/<project>/logs/cloudaudit.googleapis.com%2Factivity"' \
  --freshness=1d --format json | jq '.[] | {time: .timestamp, user: .protoPayload.authenticationInfo.principalEmail, method: .protoPayload.methodName}'

# Find service account key creation
gcloud logging read \
  'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \
  --freshness=30d --format json | jq '.[] | {time: .timestamp, user: .protoPayload.authenticationInfo.principalEmail}'

# Find anomalous GCS data access
gcloud logging read \
  'logName="projects/<project>/logs/cloudaudit.googleapis.com%2Fdata_access" AND protoPayload.methodName="storage.objects.get"' \
  --freshness=1d --format json | jq '.[] | {time: .timestamp, user: .protoPayload.authenticationInfo.principalEmail, resource: .protoPayload.resourceName}'

# GCP containment: disable service account
gcloud iam service-accounts disable suspicious-sa@project.iam.gserviceaccount.com

# Remove a user from all IAM bindings. Remove the member, not the whole binding,
# or every other member in that binding loses its role too; then drop empty bindings.
gcloud projects get-iam-policy <project> --format json | \
  jq '(.bindings[].members) |= map(select(. != "user:attacker@gmail.com"))
      | .bindings |= map(select(.members | length > 0))' | \
  gcloud projects set-iam-policy <project> /dev/stdin
```

Security Command Center (Event Threat Detection) finding categories (examples):
- `Malware: Bad Domain`: connection to or lookup of a known-bad domain
- `Active Scan: Log4j Vulnerable to RCE`: Log4Shell scanning detected
- `Initial Access: Log4j Compromise Attempt`: JNDI lookup in a header or URL parameter
- `Defense Evasion: Modify VPC Service Control`: VPC Service Controls perimeter change
- `Exfiltration: BigQuery Data Extraction`: BigQuery data extracted to an external or public bucket


---

## 8. Threat Intelligence During IR

### 8.1 IOC Extraction and Enrichment Workflow

Step 1. Extract IOCs from raw evidence:
```
From malware samples: hashes (MD5, SHA1, SHA256), PDB paths, embedded IPs/domains, mutex names
From memory dumps: injected code, C2 URLs, encryption keys, configuration data
From network logs: IP addresses, domains, URLs, JA3 fingerprints, certificate hashes
From email: sender domain, reply-to, X-headers, attachment hashes, embedded URLs
From log files: usernames, hostnames, API endpoints, file paths, registry keys
```

Step 2. Normalize and deduplicate IOCs
- Remove known-good infrastructure (CDNs, Microsoft IPs, Google IPs)
- Check against internal asset inventory (don't flag your own systems)
- Tag with context: `source=phishing_email`, `confidence=high`, `first_seen=2026-05-03`

Step 3. Enrich IOCs
```python
# VirusTotal lookups
import requests
VT_KEY = "your_vt_api_key"

def vt_lookup_hash(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    r = requests.get(url, headers={"x-apikey": VT_KEY})
    return r.json()

def vt_lookup_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    r = requests.get(url, headers={"x-apikey": VT_KEY})
    return r.json()

def vt_lookup_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers={"x-apikey": VT_KEY})
    return r.json()
```

Step 4. Deploy IOCs to detection stack
- SIEM: Add IOC-based correlation rules or threat intelligence feeds
- EDR: Push hashes to blocklist; enable prevention for known-bad hashes
- Firewall: Block malicious IPs and domains at perimeter
- DNS: Sink-hole malicious domains at DNS resolver level
- Email gateway: Block malicious sender domains, attachment hashes, embedded URLs

---

### 8.2 Key Enrichment Platforms

VirusTotal (https://www.virustotal.com)
- File hash, IP, domain, URL lookups
- Behavioral analysis sandbox (Jujubox, Triage integration)
- Retrohunt for new IOC matches across historical submissions
- VT Enterprise: pivot on JARM, JA3, SSL cert, network indicators

AbuseIPDB (https://www.abuseipdb.com)
- Community-sourced IP reputation database
- Confidence score and report count
- Categories: web attack, brute force, scan, spam, port scan
```bash
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=198.51.100.1&maxAgeInDays=90" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq '.data'
```

Shodan (https://www.shodan.io)
- Internet-wide scanning data on hosts, services, banners
- Find attacker infrastructure: same banner across IPs, self-signed cert reuse
- Useful for identifying if attacker exposed your stolen data on an open server
```bash
# Find all hosts with specific SSL certificate
shodan search "ssl.cert.fingerprint:SHA1_HASH"
# Find hosts with Cobalt Strike default certificate
shodan search "ssl.cert.subject.cn:'Major Cobalt Strike'"
# Find domains hosted on same IP
shodan host <ip>
```

Recorded Future / Google Threat Intelligence (formerly Mandiant Advantage) / CrowdStrike Intel
- Commercial threat intelligence with actor tracking
- Dark web monitoring for data breach mentions
- Malware family analysis and YARA rules
- Actor TTPs and infrastructure tracking

---

### 8.3 Threat Actor Identification via ATT&CK

Process:
1. Map observed TTPs to ATT&CK techniques (Initial Access, Execution, Persistence, etc.)
2. Cross-reference technique combinations with ATT&CK Groups (https://attack.mitre.org/groups/)
3. Check Navigator layer files shared by vendors for actor TTPs

```python
# Using attackcti (the ATT&CK CTI Python client: pip install attackcti)
from attackcti import attack_client
client = attack_client()
techniques = client.get_techniques()
groups = client.get_groups()

# Find the groups that use a given technique. In ATT&CK's STIX model a "uses"
# relationship runs source_ref (the intrusion-set / group) -> target_ref (the
# attack-pattern / technique), so the group is the source_ref. Match on the
# technique's STIX id (attack-pattern--...), not its Txxxx id.
def groups_using_technique(technique_stix_id):
    rels = client.get_relationships()
    return [r.source_ref for r in rels
            if getattr(r, "relationship_type", None) == "uses"
            and getattr(r, "target_ref", None) == technique_stix_id]
```

Common Actor-to-Technique Signatures:
| Actor | Common Techniques | Targeted Sectors |
|-------|------------------|-----------------|
| APT29 (Cozy Bear, G0016) | T1566.001 Spearphishing Attachment, T1059.001 PowerShell, T1078 Valid Accounts | Government, Defense, Healthcare |
| APT41 (G0096) | T1190 Exploit Public-Facing Application, T1053.005 Scheduled Task, T1136.001 Local Account | Multiple sectors, financial crime |
| FIN7 (G0046) | T1566.001 Spearphishing Attachment, T1204.002 Malicious File, T1486 Data Encrypted for Impact | Retail, Hospitality, Finance |
| Lazarus Group (G0032) | T1189 Drive-by Compromise, T1588.002 Tool, T1041 Exfiltration Over C2 Channel | Finance, Crypto, Defense |
| LockBit (a RaaS brand, not an ATT&CK Group) | Commonly observed: T1078 Valid Accounts, T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery | Opportunistic, all sectors |

---

### 8.4 Pivoting on IOCs

IP to Domain:
```bash
# Passive DNS: RiskIQ PassiveTotal was absorbed into Microsoft Defender Threat Intelligence
# and the standalone passivetotal.org API/portal was retired, so use Defender TI (the
# Microsoft Graph threat-intelligence API) or another passive-DNS source. The VirusTotal
# query below is one working alternative.

# VirusTotal: domains related to IP
curl "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.66/resolutions" \
  -H "x-apikey: $VT_KEY" | jq '.data[].attributes.host_name'
```

Domain to Certificate:
```bash
# Certificate transparency logs: find certs for domain and related domains
curl "https://crt.sh/?q=%.attacker.com&output=json" | \
  jq '.[].name_value' | sort -u

# Find all domains sharing same certificate serial number
shodan search "ssl.cert.serial:<serial_number>"
```

Certificate to Infrastructure:
```bash
# Find all hosts serving same SSL cert (fingerprint pivot)
shodan search "ssl.cert.fingerprint:<sha1_fingerprint>" --fields ip_str,hostnames,port
```

JARM Fingerprint Pivot:
```bash
# JARM fingerprints a server by its TLS configuration. A JARM is 62 hex characters and
# varies by the C2 server's TLS profile/version, so derive the fingerprint from a known
# sample and search for that exact value.
shodan search "ssl.jarm:<62-character-jarm>"
```

---

### 8.5 MISP for IR IOC Sharing

```python
# Connect to MISP and create event from IR
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP(url="https://misp.company.com", key="$MISP_KEY")

# Create event
event = MISPEvent()
event.info = "IR-2026-0503 - Ransomware Campaign"
event.distribution = 1  # This community
event.threat_level_id = 1  # High
event.analysis = 1  # Ongoing

# Add IOCs
event.add_attribute('ip-dst', '203.0.113.66')
event.add_attribute('domain', 'malware-c2.com')
event.add_attribute('md5', 'abc123...')
event.add_attribute('sha256', 'def456...')

result = misp.add_event(event)
```

---

### 8.6 Sector ISAC Notification

| Sector | ISAC | Contact |
|--------|------|---------|
| Financial | FS-ISAC | https://www.fsisac.com (member reporting via admin@fsisac.com) |
| Healthcare | Health-ISAC | https://health-isac.org |
| Energy | E-ISAC | https://www.eisac.com |
| IT / Technology | IT-ISAC | https://www.it-isac.org |
| Aviation | A-ISAC | https://www.a-isac.com |
| Water | WaterISAC | https://waterisac.org |
| Retail and hospitality | RH-ISAC | https://rhisac.org |

Government Reporting Partners:
- CISA: https://www.cisa.gov/report | 1-844-SAY-CISA (1-844-729-2472)
- FBI Cyber Division: https://www.fbi.gov/contact-us/field-offices (contact local field office)
- IC3: https://www.ic3.gov (FBI Internet Crime Complaint Center)
- U.S. Secret Service Cyber Fraud Task Forces (CFTF): financial and cyber crime: contact a local field office (the ECTFs were reorganized into CFTFs)
- DoD Cyber Crime Center (DC3 / DCISE): defense industrial base cyber incident reporting via the DIBNet portal, mandatory under DFARS 252.204-7012 (NSA's DIB engagement is its separate Cybersecurity Collaboration Center)


---

## 9. Containment, Eradication & Recovery

### 9.1 Containment Decision Framework

Before taking containment action, evaluate:

| Factor | Consider |
|--------|---------|
| Evidence Preservation | Will containment destroy forensic evidence? If yes, collect evidence first. |
| Business Impact | What is the business cost of taking system offline vs. leaving it connected? |
| Attacker Awareness | Will containment alert the attacker to change TTPs or destroy evidence? |
| Scope | Is this isolated or part of a wider compromise requiring coordinated containment? |
| Legal Requirements | Is law enforcement conducting an investigation requiring continued attacker access? |
| System Criticality | Is this a life-safety, revenue-critical, or administrative system? |

Containment Options (least to most disruptive):
1. Increased monitoring (no disruption, attacker unaware)
2. Rate limiting or blocking specific traffic
3. Firewall micro-segmentation (block lateral movement, allow production traffic)
4. Disable specific user account or API key
5. Network isolation of host (retain management access, block production traffic)
6. Full network isolation (complete disconnect)
7. Powered shutdown (last resort: destroys volatile evidence)

---

### 9.2 Firewall Emergency Blocks

Palo Alto Networks (PAN-OS)
```bash
# Block C2 IP immediately via CLI (enter config mode with `configure` first;
# on Panorama prefix with `device-group <dg> pre-rulebase`)
set rulebase security rules "BLOCK-C2-IR" from any
set rulebase security rules "BLOCK-C2-IR" to any
set rulebase security rules "BLOCK-C2-IR" source any
set rulebase security rules "BLOCK-C2-IR" destination [ 203.0.113.66 198.51.100.22 ]
set rulebase security rules "BLOCK-C2-IR" application any
set rulebase security rules "BLOCK-C2-IR" service any
set rulebase security rules "BLOCK-C2-IR" action deny
commit

# Move rule to top (before permissive rules)
move rulebase security rules "BLOCK-C2-IR" top
commit
```

Cisco ASA / Firepower
```bash
# Block C2 IP via access control entry. On classic ASA a new ACE is appended to the
# bottom of the named ACL, so insert it near the top with a line number, and ensure the
# ACL is bound to the interface (access-group OUTSIDE_IN in interface outside).
access-list OUTSIDE_IN line 1 extended deny ip any host 203.0.113.66 log
access-list OUTSIDE_IN line 2 extended deny ip host 203.0.113.66 any log

# Block a domain via DNS sinkhole (Cisco Umbrella - not ISE; ISE is NAC/policy, not DNS):
# Cisco Umbrella: Policies > Security Settings > Add destination list
```

Windows Firewall (Emergency Host Block)
```powershell
# Block outbound by DEFAULT, then allow only management traffic. An explicit Block rule
# overrides any Allow, so set the profile's default outbound action to Block (do not add a
# block-all rule) and add Allow rules for the traffic you must keep reachable.
Set-NetFirewallProfile -All -DefaultOutboundAction Block
New-NetFirewallRule -DisplayName "IR-ALLOW-MGT" -Direction Outbound `
  -RemoteAddress 10.10.10.0/24 -Action Allow -Enabled True -Profile Any
```

---

### 9.3 Active Directory Remediation

Compromised Account Remediation
```powershell
# Reset compromised account password
Set-ADAccountPassword -Identity compromised_user -Reset `
  -NewPassword (ConvertTo-SecureString "NewPass!@#$%" -AsPlainText -Force)

# Disable compromised account
Disable-ADAccount -Identity compromised_user

# Remove from privileged groups
Remove-ADGroupMember -Identity "Domain Admins" -Members compromised_user -Confirm:$false

# Force logoff all active sessions
query session /server:DC01 | Where-Object { $_ -match "compromised_user" }
logoff <session_id> /server:DC01

# Clear cached Kerberos tickets. klist purge clears the CALLING session's tickets, so a
# remote Invoke-Command purges the admin's own context, not the compromised user's; run
# klist in the target logon session (klist -li <LogonId> purge). The krbtgt reset below is
# what actually invalidates stolen tickets.
klist purge
```

KRBTGT Reset (Golden Ticket Invalidation)

The krbtgt account secret is used to sign all Kerberos tickets. Resetting it invalidates all existing Kerberos tickets, including any golden tickets created by an attacker.

```powershell
# Step 1: Get current krbtgt password metadata
Get-ADUser -Identity krbtgt -Properties PasswordLastSet, msDS-KeyVersionNumber

# Step 2: First reset (set new password)
Set-ADAccountPassword -Identity krbtgt -Reset `
  -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)

# Step 3: Wait 10+ hours (Kerberos maximum ticket lifetime default is 10 hours)
# Users will need to re-authenticate: expect disruption

# Step 4: Second reset. AD keeps the previous krbtgt password (N-1) valid, so a single
# reset still honors tickets signed with the stolen key; reset again, after replication, to invalidate it.
# Wait for AD replication (and ideally the 10-hour ticket lifetime) between the two resets
Set-ADAccountPassword -Identity krbtgt -Reset `
  -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)

# Verify replication of new password to all DCs
repadmin /showrepl
repadmin /syncall /AdeP
```

Note: After krbtgt reset, all service tickets must be re-issued. Coordinate with business during low-traffic window. Some services may require manual restart.

---

### 9.4 Endpoint Reimaging vs. Cleaning Decision Criteria

Reimage (preferred for):
- Any confirmed ransomware infection
- Systems with confirmed rootkit presence
- Systems where full scope of compromise is unknown
- High-criticality servers with confirmed malware
- Any system where attacker had SYSTEM/root access
- Systems with firmware compromise indicators
- When cleaning would take longer than reimaging

Clean (acceptable for):
- Isolated adware or PUP (Potentially Unwanted Program) with no privilege escalation
- Confirmed, fully remediated credential stuffing attempt (no code execution)
- Known, easily removable malware families with high-confidence signatures
- When system cannot be quickly reimaged (e.g., physical OT equipment)

Reimaging Procedure:
```
1. Capture forensic image and memory dump before wiping (evidence preservation)
2. Verify clean, tested backup or gold image is available
3. Wipe disk using certified media sanitization (NIST SP 800-88 Rev. 2; Rev. 1 was withdrawn on 26 September 2025. The DoD 5220.22-M overwrite is legacy and is no longer a current sanitization standard)
4. Deploy clean OS image from known-good source (verified hash)
5. Apply all current patches before reconnecting to network
6. Install and configure EDR agent (prevention mode enabled)
7. Restore data from pre-incident backup (verified clean)
8. Monitor with elevated sensitivity for 30 days post-recovery
```

---

### 9.5 Persistence Removal Checklist

Verify ALL locations are clear before declaring eradication complete:

Windows Persistence Locations:
```powershell
# 1. Run Keys (most common)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"

# 2. Services
Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" } | Select-Object Name, DisplayName, PathName, StartMode
sc.exe query type= all state= all

# 3. Scheduled Tasks
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } |
  Select-Object TaskName, TaskPath, @{N="Action";E={$_.Actions.Execute}}
schtasks /query /fo LIST /v | findstr /i /C:"TaskName" /C:"Run As User" /C:"Task To Run"

# 4. WMI Subscriptions (stealthy persistence)
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer

# 5. Startup Folders
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# 6. Browser Extensions (often overlooked)
Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Recurse
Get-ChildItem "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions"

# 7. COM Object Hijacking
reg query "HKCU\Software\Classes\CLSID" /s

# 8. DLL Search Order Hijacking: find PATH directories writable by non-admins
$env:PATH -split ";" | Where-Object { $_ } | ForEach-Object {
  $p = $_
  (Get-Acl $p -ErrorAction SilentlyContinue).Access |
    Where-Object { $_.AccessControlType -eq "Allow" -and
      $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
      $_.FileSystemRights -match "Write|Modify|FullControl" } |
    ForEach-Object { "$p : $($_.IdentityReference) $($_.FileSystemRights)" }
}

# 9. AppInit_DLLs
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs

# 10. Image File Execution Options (IFEO): debugger hijacking
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s
```

---

### 9.6 Business Continuity During IR

Communication Strategy:
- Establish command center separate from potentially compromised systems
- Use out-of-band communication (personal cell phones, Signal, physical meetings)
- Provide business leaders status updates every 2 hours for P1 incidents
- Coordinate with business continuity team on manual process fallbacks

System Priority Tiers for Recovery:
| Tier | Systems | RTO Target |
|------|---------|-----------|
| 1 | Life-safety, emergency services, payment processing | 0-4 hours |
| 2 | Core business operations, ERP, email, VPN | 4-24 hours |
| 3 | Internal productivity tools, reporting systems | 24-72 hours |
| 4 | Development environments, analytics, archival | 72+ hours |

Backup Validation Before Restore:
```bash
# Verify backup integrity before restoring
sha256sum backup.tar.gz  # Compare to recorded hash
# Test restore to isolated environment, NEVER restore directly to production without testing
# Verify backup date precedes compromise (check patient zero timeline)
# Scan backup contents with updated AV/EDR before restoration
```


---

## 10. Post-Incident & Legal

### 10.1 Lessons Learned Blameless Postmortem

The lessons learned meeting should occur within 10-14 days of incident closure, while details are fresh.

Principles:
- Blameless: Focus on system and process failures, not individual blame
- Data-driven: Work from the documented timeline, not memory
- Action-oriented: Every finding must have an owner and due date
- Inclusive: Involve all participants: technical, business, legal, communications

Agenda (2-hour session):
```
0:00 - 0:10  Ground rules and blameless culture reminder
0:10 - 0:40  Timeline walkthrough (scribe-recorded, factual)
0:40 - 1:00  What went well? (capture and reinforce)
1:00 - 1:30  What could be improved? (detection gaps, response delays, tool gaps)
1:30 - 1:50  Action items: owner, priority, due date
1:50 - 2:00  Next steps and PIR draft timeline
```

Five Whys Root Cause Analysis Example:
```
Incident: Ransomware spread through 80% of network before detection

Why 1: Why did it spread to so many systems?
  → No network segmentation; flat network allowed SMB lateral movement

Why 2: Why was there no network segmentation?
  → Segmentation project was deprioritized in Q3 budget review

Why 3: Why was it deprioritized?
  → Risk was not quantified in business terms for leadership decision-making

Why 4: Why wasn't risk quantified?
  → Security team lacked process for translating technical risk to business impact

Why 5: Why does that process not exist?
  → No formal risk quantification framework has been adopted

Root Cause: Absence of business-aligned risk quantification leading to under-investment in segmentation
```

---

### 10.2 Post-Incident Report Template

```markdown
# Post-Incident Report
**Incident ID:** IR-2026-XXXX
**Classification:** [Confidential / Attorney-Client Privileged]
**Date:** YYYY-MM-DD
**Author:** [IR Lead]
**Status:** [Draft / Final]

## 1. Executive Summary
[2–3 paragraph non-technical summary: what happened, business impact, current status, key recommendations]

## 2. Incident Timeline
| Date/Time (UTC) | Event | Source |
|----------------|-------|--------|
| 2026-04-15 14:32 | Attacker accessed VPN using stolen credentials | VPN logs |
| 2026-04-15 14:45 | Lateral movement via SMB to file server | Firewall logs |
| 2026-04-16 02:10 | Ransomware encryption began | EDR telemetry |
| 2026-04-16 06:22 | Ransomware detected by EDR | CrowdStrike alert |
| 2026-04-16 06:35 | IR team notified | PagerDuty |
| 2026-04-16 07:00 | P1 declared, IC appointed | IR ticket |
| 2026-04-20 18:00 | Recovery complete, monitoring enhanced | IR log |

## 3. Root Cause Analysis
[Technical description of initial access vector, attacker path, enabling vulnerabilities]

## 4. Business Impact
- Systems affected: [list]
- Data accessed/exfiltrated: [description and data classification]
- Downtime: [X hours for Y systems]
- Financial impact: [$X estimated]
- Regulatory impact: [notification obligations]
- Reputational impact: [customer, partner, media impact]

## 5. Response Effectiveness
- MTTD: [X hours]
- MTTC: [X hours]
- MTTR: [X hours]
- What worked well: [list]
- Detection gaps identified: [list]
- Response gaps identified: [list]

## 6. Recommendations
| Priority | Recommendation | Owner | Due Date | Estimated Effort |
|----------|---------------|-------|---------|-----------------|
| P1 | Implement network segmentation | Infrastructure | 30 days | High |
| P1 | Enforce MFA on all remote access | IAM team | 14 days | Medium |
| P2 | Deploy UEBA for insider threat | Security Ops | 60 days | High |

## 7. Appendices
- A: Technical IOC List
- B: Forensic Evidence Inventory
- C: Regulatory Notification Log
- D: Evidence Chain of Custody
```

---

### 10.3 Regulatory Notification Requirements

GDPR (EU General Data Protection Regulation)
- Trigger: Personal data breach within the GDPR's Article 3 territorial scope
- Timeline: notify the competent supervisory authority (DPA) without undue delay and, where feasible, within 72 hours of becoming aware, unless the breach is unlikely to result in a risk to individuals; a processor notifies its controller without undue delay
- Subject matter: Nature of breach, categories and approximate number of data subjects/records, DPO contact, likely consequences, measures taken
- Individual notification: without undue delay when the breach is likely to be a high risk to individuals, subject to the Article 34(3) exceptions
- Documentation: All breaches must be documented even if no notification is required

SEC Cybersecurity Disclosure Rule (Item 1.05 Form 8-K)
- Trigger: "Material" cybersecurity incident
- Who and when: domestic registrants file Item 1.05 within 4 business days of determining materiality, and must make that determination without unreasonable delay. A disclosure delay is allowed only when the U.S. Attorney General notifies the SEC in writing that disclosure poses a substantial risk to national security or public safety
- Foreign private issuers: furnish the same information on Form 6-K
- Content: Nature, scope, timing of incident; material impact or reasonably likely material impact
- Annual disclosure: 10-K (Form 20-F for foreign private issuers) must include cybersecurity risk management and governance disclosures

HIPAA Breach Notification Rule
- Trigger: Breach of unsecured Protected Health Information (PHI)
- Individuals: without unreasonable delay and no later than 60 days after discovery
- HHS Secretary: for breaches affecting 500 or more individuals, without unreasonable delay and within 60 days; for fewer than 500, in the annual log due within 60 days after the end of the calendar year of discovery
- Media: for a breach affecting more than 500 residents of a state or jurisdiction, notify prominent media without unreasonable delay and within 60 days
- Content: Description of breach, PHI involved, steps individuals should take, steps covered entity is taking
- Business Associates: notify the Covered Entity without unreasonable delay and within 60 days of discovery

State Breach Notification Laws (US)
- All 50 states + DC have breach notification laws with varying requirements
- Fastest deadlines: 30 calendar days (Colorado, Florida; and California since SB 446). New Mexico is 45 calendar days (NMSA 57-12C-6)
- Key elements vary: definition of "personal information," notification triggers, safe harbors

PCI DSS Incident Response
- Contact your acquirer promptly on a suspected or confirmed cardholder-data compromise; the exact deadlines come from the acquirer, the card brands' programs, your merchant agreement and applicable law, not from a single universal clock
- Brand deadlines (confirm against the current rules): notify your acquirer immediately; Visa's "What To Do If Compromised" requires notice immediately and no later than three calendar days; Mastercard's Security Rules and Procedures (SPME Manual) require notifying Mastercard immediately upon becoming aware of an ADC Event or Potential ADC Event, and within 24 hours of engaging a PCI Forensic Investigator (PFI). Other brands and your merchant agreement may differ
- Engage a PCI Forensic Investigator (PFI), a QSA firm authorized by the card brands, when the brand program requires one
- Preserve all logs and evidence per PFI guidance

California Breach Notification (Civil Code 1798.82, as amended by SB 446)
- Notify affected California residents within 30 calendar days of discovery or notification of the breach (SB 446; subject to the statute's law-enforcement and scope delays)
- When notice goes to more than 500 California residents, submit a sample copy to the Attorney General within 15 calendar days of notifying consumers
- (CCPA/CPRA govern consumer privacy rights such as opt-out of sale/sharing; the breach-notice duty itself is Civil Code 1798.82)

---

### 10.4 Law Enforcement Engagement

Decision Framework:
- Ransomware: Always report to FBI via IC3; may have decryption keys or intelligence
- Financial fraud (BEC, wire transfer): Report to IC3 immediately; FBI FFKC can freeze funds
- Nation-state attribution suspected: Engage FBI Cyber Division directly
- Critical infrastructure attack: sector-specific reporting mandates may already apply; CIRCIA's cross-sector rule (72-hour incident, 24-hour ransom-payment reporting) is not yet in force (final rule pending as of late 2026)
- Child sexual abuse material discovered: electronic service providers must report to NCMEC's CyberTipline under 18 U.S.C. 2258A; preserve the material in place and contact the FBI

What LE Can Provide:
- Intelligence on attacker TTPs and infrastructure
- Decryption keys seized during takedowns
- Financial transaction tracing and fund recovery
- Legal process assistance (subpoenas, court orders) for preserving evidence at third parties
- Declassified threat intelligence briefings for critical infrastructure sectors

What to Provide LE:
- Timeline and narrative description
- Known IOCs (IP addresses, domains, file hashes, email addresses)
- Ransomware note and sample (if ransomware)
- Cryptocurrency wallet addresses (if ransomware)
- Financial transaction details (if BEC/fraud)
- All evidence in unmodified form with chain of custody

Important: Coordinate with legal counsel before sharing with LE. Attorney-client privilege considerations apply.

---

### 10.5 Evidence Preservation for Litigation (Legal Hold)

Immediate Legal Hold Actions:
1. Notify IT and relevant custodians in writing: "Do not delete or modify"
2. Identify all potentially relevant data sources: email, file shares, databases, cloud storage, endpoint data, log files
3. Implement technical holds: disable auto-delete policies in email, preserve backup snapshots
4. Collect and hash all forensic evidence; document chain of custody
5. Engage eDiscovery counsel and platform (Relativity, Everlaw, Nuix)

Evidence Preservation Periods:
- Forensic images: Minimum 7 years (litigation statute of limitations consideration)
- Log files related to incident: Do not delete during and for 3 years post-incident
- Communications during incident response: Preserve for duration of any investigation/litigation
- Chain of custody forms: Permanent retention

---

### 10.6 IR Capability Maturity Model

| Level | Description | Characteristics |
|-------|-------------|----------------|
| 1: Initial | Ad hoc, reactive | No formal IR plan; heroes respond from memory |
| 2: Developing | Basic plan exists | IR policy documented; some playbooks; manual processes |
| 3: Defined | Repeatable process | Full playbook library; SIEM/EDR deployed; regular tabletops |
| 4: Managed | Measured and controlled | MTTD/MTTR tracked; SOAR automation; purple team exercises |
| 5: Optimizing | Continuous improvement | Threat intel-driven detection; ATT&CK mapped controls; proactive hunting |

---

### 10.7 Purple Team Exercises from IR Learnings

After each significant incident, convert findings into purple team scenarios:

```
1. Identify gaps: Detection failures, coverage gaps, playbook weaknesses from PIR
2. Build attack simulation: Replicate attacker techniques in lab environment
3. Run attack simulation: Red team executes specific techniques identified in IR
4. Measure detection: Does the blue team detect each technique? How quickly?
5. Improve detections: For each missed technique, build/tune detection logic
6. Re-run simulation: Verify new detections work before declaring issue closed
7. Regression test: Run same simulation quarterly to verify detections don't degrade
```

ATT&CK-Based Validation Coverage Tracking:
```
Track percentage of ATT&CK techniques with:
- Active detection (alert fires within 10 minutes)
- Prevention (blocked automatically)
- No coverage (gap requiring remediation)

Target: >70% of techniques relevant to your threat model have active detection
```

---

*End of Incident Response Reference Library*

*Document maintained by Security Operations | Classification: Internal | Review cycle: Quarterly*
*For updates or corrections, submit to the Security Team via the internal security portal*

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Detection and response](/hubs/detection-and-response.md)
- Learning path: [Incident Response](/disciplines/incident-response.md)
- [IR Playbooks](/IR_PLAYBOOKS.md)
- [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Network Forensics Reference](/NETWORK_FORENSICS_REFERENCE.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)

<!-- related:end -->
