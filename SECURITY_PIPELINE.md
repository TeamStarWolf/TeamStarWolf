# Enterprise Security Pipeline

> A stage-by-stage model for building and operating enterprise security controls — from identity governance through detection and response. Each stage maps to NIST 800-53 control families, vendor tooling, and ATT&CK coverage.

---

## Pipeline Overview

```
Stage 1          Stage 2          Stage 3          Stage 4          Stage 5          Stage 6
Governance   →   Identity &   →   Endpoint &   →   Network &    →   Visibility &  →  Data &
& Risk           Access Mgmt      Workload         Boundary         Detection        Cloud
(GRC)            (IAM/PAM)        (EDR/AV)         (FW/ZT/Email)    (SIEM/SOAR)      (DSPM/CSPM)
```

Each stage builds on the previous. Gaps in Stage 2 (identity) compound into Stage 5 (detection) — attackers abuse valid credentials that detections never see as anomalous.

---

## Stage 1 — Governance, Risk & Compliance

**Goal:** Establish the policy, risk management, and compliance baseline that all other stages operate within.

### Core Controls (NIST 800-53)
| Control | Description |
|---|---|
| PL-1 | Policy and Procedures |
| RA-3 | Risk Assessment |
| CA-2 | Control Assessments |
| CA-7 | Continuous Monitoring |
| PM-9 | Risk Management Strategy |
| PM-30 | Supply Chain Risk Management |

### Vendor Tooling
| Category | Open Source | Commercial |
|---|---|---|
| GRC Platform | [OpenRMF](https://www.openrmf.io/), [OSCAL](https://pages.nist.gov/OSCAL/) | ServiceNow GRC, RSA Archer |
| Compliance Automation | [Wazuh](https://wazuh.com/) | Drata, Vanta, Thoropass |
| Risk Quantification | — | RiskLens, Safe Security |
| Policy Management | [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | OneTrust, LogicGate |

### Key Frameworks
- **NIST Cybersecurity Framework (CSF) 2.0** — Govern, Identify, Protect, Detect, Respond, Recover
- **NIST RMF (SP 800-37)** — Authorization and continuous monitoring lifecycle
- **ISO 27001** — ISMS certification
- **SOC 2** — Trust services criteria for SaaS/cloud providers

### Discipline Pages
- [Governance, Risk & Compliance](disciplines/governance-risk-compliance.md)
- [Privacy Engineering](disciplines/privacy-engineering.md)

---

## Stage 2 — Identity & Access Management

**Goal:** Ensure every user, device, and workload authenticates strongly, has only the access it needs, and that privileged access is tightly controlled.

### Core Controls (NIST 800-53)
| Control | Description |
|---|---|
| AC-2 | Account Management |
| AC-3 | Access Enforcement |
| AC-5 | Separation of Duties |
| AC-6 | Least Privilege |
| IA-2 | Identification and Authentication |
| IA-5 | Authenticator Management |
| IA-8 | Non-Organizational User Authentication |

### ATT&CK Coverage
Techniques mitigated: **T1078** (Valid Accounts), **T1110** (Brute Force), **T1556** (Modify Authentication Process), **T1621** (MFA Request Generation), **T1098** (Account Manipulation), **T1550** (Use Alternate Authentication Material), **T1558** (Steal or Forge Kerberos Tickets)

### Vendor Tooling
| Category | Tool / Vendor |
|---|---|
| Identity Provider (IdP) | [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id), [Okta](https://okta.com/) |
| Privileged Access Management | [CyberArk](https://www.cyberark.com/), [BeyondTrust](https://www.beyondtrust.com/), [HashiCorp Vault](https://www.vaultproject.io/) |
| MFA / Passwordless | [Duo](https://duo.com/), [Yubico](https://www.yubico.com/) |
| AD Security | [BloodHound Enterprise](https://bloodhoundenterprise.io/), [Semperis](https://www.semperis.com/) |
| CIEM | [Ermetic](https://ermetic.com/), [Sonrai Security](https://sonraisecurity.com/) |

### Navigator Layer
Load the [Identity & Access Stage Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage2_identity_access.json) in ATT&CK Navigator.

### Discipline Pages
- [Identity & Access Management](disciplines/identity-access-management.md)

---

## Stage 3 — Endpoint & Workload Protection

**Goal:** Prevent, detect, and respond to threats on endpoints, servers, and cloud workloads.

### Core Controls (NIST 800-53)
| Control | Description |
|---|---|
| SI-3 | Malicious Code Protection |
| SI-7 | Software, Firmware, and Information Integrity |
| CM-7 | Least Functionality |
| CM-8 | System Component Inventory |
| SC-3 | Security Function Isolation |
| SC-39 | Process Isolation |

### ATT&CK Coverage
Techniques mitigated: **T1059** (Command and Scripting Interpreter), **T1055** (Process Injection), **T1486** (Data Encrypted for Impact), **T1566** (Phishing), **T1547** (Boot/Logon Autostart), **T1543** (Create/Modify System Process), **T1053** (Scheduled Task/Job), **T1562** (Impair Defenses), **T1490** (Inhibit System Recovery)

### Vendor Tooling
| Category | Tool / Vendor |
|---|---|
| EDR / XDR | [CrowdStrike Falcon](https://www.crowdstrike.com/), [SentinelOne](https://www.sentinelone.com/), [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) |
| Open Source EDR | [Wazuh](https://wazuh.com/), [Velociraptor](https://www.velocidex.com/) |
| Application Control | [Carbon Black App Control](https://www.vmware.com/products/carbon-black-app-control.html) |
| Vulnerability Scanning | [Tenable](https://www.tenable.com/), [Qualys](https://www.qualys.com/) |

### Navigator Layer
Load the [EDR / Endpoint Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/edr_crowdstrike_sentinelone.json) in ATT&CK Navigator.

### Discipline Pages
- [Malware Analysis](disciplines/malware-analysis.md)
- [Vulnerability Management](disciplines/vulnerability-management.md)
- [DevSecOps](disciplines/devsecops.md)
- [Supply Chain Security](disciplines/supply-chain-security.md)

---

## Stage 4 — Network & Boundary

**Goal:** Control traffic flows, enforce Zero Trust network segmentation, filter threats at the perimeter, and protect email.

### Core Controls (NIST 800-53)
| Control | Description |
|---|---|
| SC-7 | Boundary Protection |
| SC-8 | Transmission Confidentiality and Integrity |
| AC-17 | Remote Access |
| AC-20 | Use of External Information Systems |
| SI-8 | Spam Protection |
| SC-5 | Denial-of-Service Protection |

### ATT&CK Coverage
Techniques mitigated: **T1021** (Remote Services), **T1133** (External Remote Services), **T1048** (Exfiltration Over Alt Protocol), **T1071** (Application Layer Protocol), **T1040** (Network Sniffing), **T1557** (Adversary-in-the-Middle), **T1090** (Proxy), **T1566** (Phishing — Email), **T1114** (Email Collection)

### Vendor Tooling
| Category | Tool / Vendor |
|---|---|
| Next-Gen Firewall | [Palo Alto Networks NGFW](https://www.paloaltonetworks.com/network-security/next-generation-firewall), [Fortinet FortiGate](https://www.fortinet.com/products/next-generation-firewall) |
| Zero Trust Network Access | [Zscaler ZIA/ZPA](https://www.zscaler.com/), [Cloudflare Access](https://www.cloudflare.com/zero-trust/products/access/) |
| Email Security | [Proofpoint](https://www.proofpoint.com/), [Mimecast](https://www.mimecast.com/) |
| DNS Security | [Cisco Umbrella](https://umbrella.cisco.com/), [Infoblox](https://www.infoblox.com/) |
| NDR | [Darktrace](https://www.darktrace.com/), [ExtraHop](https://www.extrahop.com/) |
| Open Source | [Zeek](https://zeek.org/), [Suricata](https://suricata.io/) |

### Navigator Layers
- [Network & Boundary Stage Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage4_network_boundary.json)
- [Network / ZT Vendor Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/network_zscaler_paloalto.json)
- [Email Security Vendor Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/email_proofpoint_mimecast.json)

### Discipline Pages
- [Network Security](disciplines/network-security.md)
- [Cryptography & PKI](disciplines/cryptography-pki.md)

---

## Stage 5 — Visibility, Detection & Operations

**Goal:** Aggregate logs, correlate events, detect adversary behavior, and orchestrate response across the environment.

### Core Controls (NIST 800-53)
| Control | Description |
|---|---|
| AU-2 | Event Logging |
| AU-6 | Audit Record Review, Analysis, and Reporting |
| IR-4 | Incident Handling |
| IR-5 | Incident Monitoring |
| SI-4 | System Monitoring |
| RA-5 | Vulnerability Monitoring and Scanning |

### ATT&CK Coverage
Techniques mitigated: **T1078** (Valid Accounts — anomaly detection), **T1059** (Scripting — behavioral detection), **T1003** (Credential Dumping — alert), **T1055** (Process Injection — memory detection), **T1486** (Ransomware — behavior block + response), **T1562** (Impair Defenses — integrity monitoring)

### Vendor Tooling
| Category | Tool / Vendor |
|---|---|
| SIEM | [Splunk Enterprise Security](https://www.splunk.com/en_us/products/enterprise-security.html), [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/), [Elastic Security](https://www.elastic.co/security) |
| Open Source SIEM | [Wazuh](https://wazuh.com/), [OpenSearch Security Analytics](https://opensearch.org/platform/observability/) |
| SOAR | [Splunk SOAR](https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html), [Palo Alto XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar) |
| Threat Intelligence | [MISP](https://www.misp-project.org/), [OpenCTI](https://www.opencti.io/) |
| Detection Engineering | [Sigma](https://sigmahq.io/), [YARA](https://virustotal.github.io/yara/) |
| UEBA | [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics), [Exabeam](https://www.exabeam.com/) |

### Navigator Layer
Load the [Visibility & Detection Stage Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage5_visibility_detection.json) in ATT&CK Navigator.

### Discipline Pages
- [Detection Engineering](disciplines/detection-engineering.md)
- [Incident Response](disciplines/incident-response.md)
- [Threat Intelligence](disciplines/threat-intelligence.md)
- [Security Operations](disciplines/security-operations.md)
- [Digital Forensics](disciplines/digital-forensics.md)

---

## Stage 6 — Data & Cloud Security

**Goal:** Protect data at rest, in transit, and in use across cloud environments. Enforce classification, prevent exfiltration, and maintain posture visibility.

### Core Controls (NIST 800-53)
| Control | Description |
|---|---|
| MP-2 | Media Access |
| SC-28 | Protection of Information at Rest |
| SC-8 | Transmission Confidentiality and Integrity |
| RA-5 | Vulnerability Monitoring and Scanning |
| CM-6 | Configuration Settings |
| SA-9 | External System Services |

### ATT&CK Coverage
Techniques mitigated: **T1530** (Data from Cloud Storage), **T1552** (Unsecured Credentials in Cloud), **T1580** (Cloud Infrastructure Discovery), **T1619** (Cloud Storage Object Discovery), **T1537** (Transfer Data to Cloud Account), **T1190** (Exploit Public-Facing Application)

### Vendor Tooling
| Category | Tool / Vendor |
|---|---|
| CSPM | [Wiz](https://wiz.io/), [Orca Security](https://orca.security/), [Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud) |
| DSPM | [Varonis](https://www.varonis.com/), [Normalyze](https://normalyze.ai/) |
| DLP | [Microsoft Purview](https://www.microsoft.com/en-us/security/business/information-protection/microsoft-purview-information-protection), [Forcepoint](https://www.forcepoint.com/) |
| CASB | [Netskope](https://www.netskope.com/), [Microsoft Defender for Cloud Apps](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-cloud-apps) |
| Open Source | [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite) |
| VM / Scanning | [Tenable.io](https://www.tenable.com/products/tenable-io), [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) |

### Navigator Layer
Load the [VM / CSPM Vendor Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/vuln_mgmt_tenable_qualys_wiz.json) in ATT&CK Navigator.

### Discipline Pages
- [Cloud Security](disciplines/cloud-security.md)
- [Cryptography & PKI](disciplines/cryptography-pki.md)
- [Privacy Engineering](disciplines/privacy-engineering.md)

---

## Full Stack ATT&CK Coverage

The combined coverage of all six pipeline stages across the TeamStarWolf vendor stack:

[Load Full Stack Navigator Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json)

### Known Coverage Gaps (Pre-Computed)

| Tactic | Coverage | Priority |
|---|---|---|
| Discovery | ~3% | 🔴 Critical |
| Defense Evasion | ~5% | 🔴 Critical |
| Collection | ~6% | 🔴 Critical |
| Lateral Movement | ~18% | 🟠 High |
| Command & Control | ~22% | 🟠 High |
| Credential Access | ~31% | 🟡 Medium |
| Persistence | ~38% | 🟡 Medium |
| Execution | ~44% | 🟢 Adequate |
| Initial Access | ~51% | 🟢 Adequate |
| Impact | ~55% | 🟢 Adequate |

See [Coverage Gap Analysis](scores/coverage_gaps.md) for full details and P1/P2 recommendations.

---

## Controls Mapping

This pipeline maps to NIST 800-53 R5 controls via the CTID framework. See [Controls Mapping](CONTROLS_MAPPING.md) for the full vendor → control → technique chain.

Data files:
- [`data/vendor_to_control.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/vendor_to_control.jsonl) — Vendor to NIST 800-53 control edges
- [`data/control_to_technique.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/control_to_technique.jsonl) — NIST control to ATT&CK technique edges
- [`data/vendor_to_technique.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/vendor_to_technique.jsonl) — Derived vendor to ATT&CK technique coverage

---

## Related Resources

- [Coverage Schema](COVERAGE_SCHEMA.md) — JSONL schema documentation
- [ATT&CK Navigator](navigator/index.md) — Interactive coverage visualization
- [Black Hat Arsenal Crosswalk](research/BLACK_HAT_ARSENAL_CROSSWALK.md) — Open-source tools mapped to this pipeline
