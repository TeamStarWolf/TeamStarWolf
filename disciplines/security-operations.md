# Security Operations

> Running the detection, triage, investigation, and response engine of the enterprise — operating the SOC, SIEM, SOAR, and threat hunting capabilities that turn telemetry into outcomes.

## What Security Operations Engineers & Analysts Do

- Monitor SIEM dashboards and triage alerts across endpoint, network, identity, and cloud telemetry
- Investigate security incidents: scope, timeline, root cause, attacker actions
- Operate SOAR playbooks to automate repetitive triage and containment actions
- Perform proactive threat hunting using hypotheses and MITRE ATT&CK
- Manage detection content lifecycle (Sigma rules, YARA, SIEM queries) and reduce false positives
- Onboard new log sources and tune parsers and data models
- Coordinate with IR teams during major incidents; maintain incident tracking
- Produce metrics: MTTD, MTTR, detection coverage by tactic, false positive rate

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary behavior taxonomy for detection alignment |
| [MITRE D3FEND](https://d3fend.mitre.org/) | Defensive technique knowledge graph |
| [SOC-CMM](https://www.soc-cmm.com/) | SOC Capability Maturity Model |
| [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) | Computer Security Incident Handling Guide |
| [Sigma](https://sigmahq.io/) | Generic SIEM detection rule format |
| [OCSF](https://schema.ocsf.io/) | Open Cybersecurity Schema Framework (log normalization) |
| [Splunk CIM](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) | Common Information Model for Splunk |

---

## Free & Open-Source Tools

### SIEM & Log Management

| Tool | Purpose | Notes |
|---|---|---|
| [Wazuh](https://wazuh.com/) | Open-source XDR + SIEM | Agent-based; rules, decoders, compliance |
| [Elastic Security](https://www.elastic.co/security) | SIEM on ELK stack | SIEM + endpoint agent; free tier available |
| [OpenSearch Security Analytics](https://opensearch.org/platform/observability/) | SIEM on OpenSearch | AWS-maintained Elasticsearch fork |
| [Graylog](https://graylog.org/) | Log management + alerting | Streams, pipelines, alerts; open source |
| [Velociraptor](https://www.velocidex.com/) | Endpoint visibility + DFIR | Hunt across thousands of endpoints |

### Threat Hunting & Detection Engineering

| Tool | Purpose | Notes |
|---|---|---|
| [Sigma](https://sigmahq.io/) | Generic detection rules | Vendor-agnostic; converts to Splunk, QRadar, Sentinel, etc. |
| [YARA](https://virustotal.github.io/yara/) | Malware pattern matching | File and memory scanning rules |
| [Hayabusa](https://github.com/Yamatosecurity/hayabusa) | Windows event log analysis | Fast threat hunting + DFIR on EVTX |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Windows event log hunter | Sigma rule matching on EVTX |
| [Zeek](https://zeek.org/) | Network traffic analysis | Script-based protocol analysis |
| [MISP](https://www.misp-project.org/) | Threat intelligence platform | IOC sharing + correlation |
| [OpenCTI](https://www.opencti.io/) | Cyber threat intelligence | Structured CTI with ATT&CK mapping |

### SOAR & Case Management

| Tool | Purpose | Notes |
|---|---|---|
| [TheHive](https://thehive-project.org/) | Security incident response platform | Case management; SOAR integration |
| [Cortex](https://github.com/TheHive-Project/Cortex) | Observable analysis engine | Integrates with TheHive; runs analyzers |
| [Shuffle](https://shuffler.io/) | Open-source SOAR | Visual playbook builder; API integrations |
| [n8n](https://n8n.io/) | Workflow automation | General-purpose; used for SOC automation |

### Metrics & Visualization

| Tool | Purpose | Notes |
|---|---|---|
| [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | Coverage visualization | Visualize detection coverage by tactic/technique |
| [Grafana](https://grafana.com/) | SOC metrics dashboards | MTTD, MTTR, alert volume, coverage |
| [Kibana](https://www.elastic.co/kibana) | Log visualization + dashboards | ELK stack frontend |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Splunk Enterprise Security](https://www.splunk.com/en_us/products/enterprise-security.html) | Market-leading SIEM | Risk-based alerting, Notables, ES Content Library |
| [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/) | Cloud-native SIEM | Native M365/Azure integration; KQL |
| [IBM QRadar](https://www.ibm.com/products/qradar-siem) | Enterprise SIEM | On-prem and SaaS; extensive connector library |
| [Palo Alto Cortex XDR](https://www.paloaltonetworks.com/cortex/cortex-xdr) | XDR + SIEM | Stitch endpoint + network + cloud |
| [CrowdStrike Falcon Next-Gen SIEM](https://www.crowdstrike.com/products/siem/) | Cloud-native SIEM | Unified with EDR telemetry |
| [Splunk SOAR](https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html) | Enterprise SOAR | Playbooks, case management, connectors |
| [Palo Alto XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar) | Enterprise SOAR | 700+ integrations |
| [Exabeam](https://www.exabeam.com/) | UEBA + SIEM | Behavioral analytics; timeline visualization |
| [LogRhythm](https://logrhythm.com/) | SIEM + SOAR | Strong compliance reporting |

---

## SOC Maturity Model

| Level | Capability |
|---|---|
| L1 — Reactive | Alert triage; follow runbooks; escalate |
| L2 — Investigative | Incident investigation; malware triage; threat hunting |
| L3 — Proactive | Detection engineering; threat intel; red/purple team collaboration |
| L4 — Strategic | SOC metrics; program ownership; continuous improvement |

## Key SOC Metrics

| Metric | Description | Target |
|---|---|---|
| MTTD | Mean Time to Detect | < 24 hours |
| MTTR | Mean Time to Respond/Contain | < 4 hours for P1 |
| Alert FPR | False Positive Rate | < 5% per detection |
| Detection Coverage | % of ATT&CK tactics with detections | > 80% tactics covered |
| Escalation Rate | % of L1 alerts escalated to L2 | Baseline → track trend |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GIAC GSOM](https://www.giac.org/certifications/security-operations-manager-gsom/) | GIAC | SOC leadership and operations management |
| [GIAC GSOC](https://www.giac.org/certifications/security-operations-certified-gsoc/) | GIAC | SOC analyst fundamentals |
| [Splunk Core Certified Power User](https://www.splunk.com/en_us/training/certification-track/splunk-core-certified-power-user.html) | Splunk | SPL, searches, reports, dashboards |
| [Splunk Enterprise Security Certified Admin](https://www.splunk.com/en_us/training/certification-track/splunk-enterprise-security-certified-admin.html) | Splunk | ES administration and tuning |
| [Microsoft SC-200](https://learn.microsoft.com/en-us/certifications/security-operations-analyst/) | Microsoft | Security Operations Analyst (Sentinel) |
| [Blue Team Labs Online](https://blueteamlabs.online/) | BTL | Practical SOC/DFIR challenge platform |
| [BTL1](https://www.securityblue.team/courses/blue-team-labs-1) | Security Blue Team | Blue Team Level 1 |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Sigma Rule Repository](https://github.com/SigmaHQ/sigma) | Open source | 3,000+ community detection rules |
| [The DFIR Report](https://thedfirreport.com/) | Blog | Real intrusion case studies with TTPs |
| [Detection Engineering Weekly](https://www.detectionengineering.net/) | Newsletter | Community detection engineering news |
| [SOC Prime](https://socprime.com/) | Platform | Sigma rule marketplace + detection-as-code |
| [Florian Roth's Blog](https://cyb3rops.medium.com/) | Blog | YARA, Sigma, threat hunting by Sigma creator |
| [LetsDefend](https://letsdefend.io/) | Training | Hands-on SOC analyst platform |
| [Blue Team Labs Online](https://blueteamlabs.online/) | Training | Practical SOC investigations |

---

## Related Disciplines

- [Detection Engineering](detection-engineering.md) — Building and maintaining detection content
- [Incident Response](incident-response.md) — Major incident handling and containment
- [Threat Intelligence](threat-intelligence.md) — Feeding IOCs and TTPs into SIEM/SOAR
- [Digital Forensics](digital-forensics.md) — Deep investigation support
- [Enterprise Security Pipeline](../SECURITY_PIPELINE.md) — Stage 5: Visibility, Detection & Operations
