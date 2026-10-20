<!-- hub:start (written by scripts/build_site_nav.py from docs/site_nav.json; do not edit) -->

# Detection and response

> Collecting telemetry, writing and tuning detections, hunting, and responding to and investigating incidents.

Part of the [domain hubs](/hubs/README.md). 24 reference documents in this domain; reading time is the page's words at 230 words a minute.

## Detection, monitoring, and hunting

| Reference | What it covers | Reading time |
|---|---|---|
| [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) | Sigma, YARA, and Suricata rule writing with examples and conversion to Splunk, Elastic, and Sentinel | 12 min |
| [SIEM Reference](/SIEM_REFERENCE.md) | Splunk ES/SPL, Microsoft Sentinel/KQL, IBM QRadar/AQL, Elastic SIEM, log normalization, detection engineering, SOC operations, threat hunting | 15 min |
| [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md) | Official detection rules from Sigma, Elastic, Splunk ESCU, Microsoft Sentinel, MITRE ATT&CK mitigations, CIS Controls, and DISA STIGs | 6 min |
| [Security Data Engineering Reference](/SECURITY_DATA_ENGINEERING_REFERENCE.md) | OCSF/ECS/CIM/ASIM normalization schemas, log pipeline architecture, security data lakes, cost-driven routing, schema-on-read vs schema-on-write, telemetry quality, retention design, ATT&CK data-component mapping | 32 min |
| [SOAR Automation Reference](/SOAR_AUTOMATION_REFERENCE.md) | SOAR platforms, playbook design, Splunk SOAR/Phantom, XSOAR, Sentinel, QRadar SOAR, phishing/malware triage, threat intel automation, IR playbooks, metrics | 21 min |
| [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md) | KQL, SPL, Sigma, YARA, ATT&CK playbooks, Velociraptor, osquery, TI integration, hunt tracking | 12 min |
| [Threat Hunting Playbooks](/THREAT_HUNTING_PLAYBOOKS.md) | Hypothesis-driven hunting procedures mapped to MITRE ATT&CK with data sources, detection logic, and response actions | 4 min |
| [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) | LOLBAS/GTFOBins/LOOBins/LOLDrivers/LOLRMM/LOTS as defensive inventories, CISA/NSA joint LOTL guidance, per-platform telemetry (4688, auditd, ESF), detection patterns, WDAC/AppLocker/fapolicyd, Volt Typhoon case study | 32 min |
| [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md) | MDE/CrowdStrike/SentinelOne config, all 19 ASR rules, Sysmon event IDs, Windows audit policy, KQL hunting queries | 9 min |
| [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md) | Suricata, Zeek, Security Onion, Arkime, DNS security, nDPI, NAC, DDoS protection, NSM operations | 17 min |
| [Network Monitoring Reference](/NETWORK_MONITORING_REFERENCE.md) | Zeek logs/scripts, Suricata rules, JA3/JARM, NetFlow/SiLK, beaconing detection, DGA hunting, Security Onion | 8 min |
| [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md) | SPF/DKIM/DMARC deep dive, phishing analysis, HTML smuggling, BEC, M365 Defender config, SMTP hardening, email forensics | 12 min |
| [Deception Technology](/DECEPTION_TECHNOLOGY_REFERENCE.md) | Honeypots, honeytokens, canary tokens, deception platforms, breadcrumb strategy, and detection rules | 10 min |
| [Honeypot & Deception Reference](/HONEYPOT_DECEPTION_REFERENCE.md) | OpenCanary, Cowrie, Dionaea, T-Pot, Canarytokens, MITRE D3FEND/ATT&CK deception mapping | 27 min |
| [Vendor Prevention Policies](/VENDOR_PREVENTION_POLICIES.md) | Authoritative policy settings from Microsoft (ASR/MDE), CrowdStrike, SentinelOne, Palo Alto, Proofpoint, Zscaler, CISA, NSA, Elastic, and Splunk | 15 min |

## Incident response and forensics

| Reference | What it covers | Reading time |
|---|---|---|
| [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) | NIST/SANS IR frameworks, live response commands, Velociraptor/KAPE, ransomware playbook, BEC response, AD compromise | 25 min |
| [IR Playbooks](/IR_PLAYBOOKS.md) | Step-by-step response procedures for ransomware, BEC, data exfiltration, DDoS, cloud incidents, and more | 15 min |
| [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md) | CISA #StopRansomware program, NIST IR 8374r1, RaaS/IAB ecosystem literacy, 3-2-1 immutable backups and restore testing, OFAC payment policy, tabletops, resilience metrics | 21 min |
| [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md) | NIST SP 800-34 contingency planning, BIA and RTO/RPO/MTD, cyber-broken DR assumptions, ISO 22301, SP 800-160v2 resiliency engineering, AD forest recovery, testing tiers, resilience metrics | 24 min |
| [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md) | Order of volatility, chain of custody, disk acquisition, Windows/Linux artifacts, Volatility 3 memory forensics, and log analysis | 28 min |
| [Network Forensics Reference](/NETWORK_FORENSICS_REFERENCE.md) | Packet capture, protocol analysis, NetFlow, encrypted traffic analysis, cloud forensics, incident reconstruction | 16 min |
| [Cloud, SaaS & Mobile Forensics](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md) | CloudTrail/GuardDuty/EBS-snapshot acquisition, M365 UAL & Graph, Google Workspace logs, SaaS logs, iLEAPP/ALEAPP-class mobile workflows | 11 min |
| [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md) | Static/dynamic analysis, PE structure, process injection, YARA rules, ransomware, memory forensics, Volatility 3 | 9 min |
| [Reverse Engineering Reference](/REVERSE_ENGINEERING_REFERENCE.md) | Ghidra/IDA/Binary Ninja, dynamic analysis, anti-analysis techniques, firmware RE, malware-focused RE workflow | 32 min |

## Learning paths

- [Detection Engineering](/disciplines/detection-engineering.md)
- [Security Operations (SOC / SecOps)](/disciplines/security-operations.md)
- [SIEM & SOAR](/disciplines/siem-soar.md)
- [Threat Hunting](/disciplines/threat-hunting.md)
- [Incident Response](/disciplines/incident-response.md)
- [Digital Forensics](/disciplines/digital-forensics.md)
- [Malware Analysis](/disciplines/malware-analysis.md)
- [Reverse Engineering](/disciplines/reverse-engineering.md)
- [Active Defense & Deception](/disciplines/active-defense-deception.md)

## How-to guides

Time and difficulty are quoted in full from each guide's header table.

| Guide | Time | Difficulty |
|---|---|---|
| [Build and Deploy Your First Detection](/guides/BUILD_YOUR_FIRST_DETECTION.md) | Half a day hands-on, plus a 1-2 week audit soak | Beginner to intermediate |
| [Onboard a Log Source the Right Way](/guides/ONBOARD_A_LOG_SOURCE.md) | 4-8 hours hands-on, plus a shadow-run of at least one business cycle | Intermediate |
| [Hunt for Living-off-the-Land Activity](/guides/HUNT_FOR_LOTL_ACTIVITY.md) | 3-5 hours of hands-on work, split around a 30-day baseline window | Intermediate |
| [Build a Detection Home Lab](/guides/BUILD_A_DETECTION_HOMELAB.md) | 6-10 hours over a weekend | Beginner to intermediate |
| [Respond to a Ransomware Incident](/guides/RESPOND_TO_RANSOMWARE.md) | First 24-72 hours of the incident (steps run in parallel after Step 3) | Advanced: decisions under pressure, some irreversible |
| [Run a Ransomware Tabletop Exercise](/guides/RUN_A_RANSOMWARE_TABLETOP.md) | ~12 weeks part-time planning, one ~4-hour session, after-action closes ~8 weeks later | Intermediate: no tooling to install; facilitation and follow-through discipline are the hard parts |
| [Investigate a Phishing Report](/guides/INVESTIGATE_A_PHISHING_EMAIL.md) | 30-90 minutes per report | Intermediate |
| [Acquire and Triage a Compromised Endpoint](/guides/ACQUIRE_AND_TRIAGE_AN_ENDPOINT.md) | 4-8 hours per host for acquisition + first-pass triage; a full timeline and report can run 1-3 days | Advanced: irreversible collection decisions, evidence-integrity discipline |
| [Investigate a Cloud Account Compromise](/guides/INVESTIGATE_A_CLOUD_COMPROMISE.md) | First hour is containment; full investigation 1-5 days by scope | Advanced: cross-provider, and the evidence ages by the hour |

## See also

- [Technique detection library](/detections/TECHNIQUE_DETECTION_LIBRARY.md)
- [ATT&CK detection strategies](/detections/strategies/README.md)
- [Technique detail pages](/techniques/README.md)

<!-- hub:end -->
