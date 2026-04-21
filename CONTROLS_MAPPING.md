# Controls Mapping: Vendor → NIST 800-53 → ATT&CK

This page provides the cross-reference chain connecting security vendors to the NIST 800-53 controls they implement, and from those controls to the ATT&CK techniques they mitigate. The bridge between NIST 800-53 and ATT&CK is provided by the [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/).

**The chain:**
```
Vendor
  → satisfies → NIST 800-53 Control
  → maps to   → ATT&CK Technique  (via CTID)
  → scored in → ATTACK-Navi heatmap
```

**Additional cloud-native control mappings from CTID:**
- [AWS Security Controls → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/)
- [Azure Security Controls → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/)
- [GCP Security Controls → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/gcp/)
- [Microsoft 365 Controls → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/)
- [CSA CCM → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/csa/)
- [KEV → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/)

For the gap scoring data model, see [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md).
For the full pipeline context, see [SECURITY_PIPELINE.md](SECURITY_PIPELINE.md).

---

## NIST 800-53 Control Families and ATT&CK Coverage

Each NIST control family mitigates a set of ATT&CK tactics and techniques. The table below shows the primary ATT&CK coverage area for each family relevant to the security pipeline.

| NIST Family | Description | Primary ATT&CK Tactics Mitigated | Pipeline Stage |
|---|---|---|---|
| **AC** | Access Control | Initial Access, Credential Access, Privilege Escalation, Lateral Movement | 2, 3 |
| **AU** | Audit & Accountability | Detection across all tactics (data source coverage) | 4, 5 |
| **CA** | Assessment & Authorization | Program-level risk across all tactics | 1, 9 |
| **CM** | Configuration Management | Defense Evasion, Persistence, Execution | 3 |
| **CP** | Contingency Planning | Impact recovery | 9 |
| **IA** | Identification & Authentication | Initial Access, Credential Access, Privilege Escalation | 2, 3 |
| **IR** | Incident Response | Response and containment across all active tactics | 6, 7, 8 |
| **MP** | Media Protection | Collection, Exfiltration | 3 |
| **PE** | Physical & Environmental Protection | Initial Access (physical), Impact | 2 |
| **PL** | Planning | Program baseline across all tactics | 1 |
| **PM** | Program Management | Governance across all tactics | 1, 9 |
| **RA** | Risk Assessment | Exposure context across all tactics | 1, 3, 5 |
| **SA** | System & Services Acquisition | Supply chain attacks, Execution | 3 |
| **SC** | System & Communications Protection | C2, Lateral Movement, Exfiltration, Defense Evasion | 2, 3, 7 |
| **SI** | System & Information Integrity | Execution, Persistence, Defense Evasion, Discovery | 3, 4, 5 |

---

## Optiv Market Family → NIST Control Family Mapping

| Optiv Market Family | Primary NIST Controls | Secondary NIST Controls | Cloud-Native CTID Mappings |
|---|---|---|---|
| **GRC** | PM, RA, CA, PL | SA-9 | — |
| **Risk & Vulnerability Management** | RA-3, RA-5, SA-11 | CM-8, SI-2 | [KEV → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/) |
| **ServiceNow Technology Partners** | IR-8, PM-3, CA-5 | PM-1, PM-14 | — |
| **Identity** | IA-2, IA-5, AC-2, AC-3 | AC-6, IA-8, IA-12 | [Azure IAM → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) · [AWS IAM → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) |
| **Zero Trust** | AC-17, AC-20, SC-7, IA-3 | AC-4, AC-24, SC-3 | [Azure → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) |
| **Application Security** | SA-11, SA-15, SI-10 | SA-3, SA-8, CM-7 | [AWS → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) |
| **Network Security** | SC-7, SC-8, SC-10, AC-17 | SC-5, SC-20, SI-4 | [AWS VPC → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) |
| **Email Security** | SC-8, SC-28, SI-3, SI-8 | SI-10, SC-26 | [M365 → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/) |
| **Cloud Security** | AC-2, AC-3, AU-2, CM-8 | SC-7, RA-5, SI-4 | [AWS](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) · [Azure](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) · [GCP](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/gcp/) · [CSA CCM](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/csa/) |
| **Data Security** | MP-2, MP-3, AC-3, AU-9 | SC-28, SI-12, AC-4 | — |
| **IoT / OT Security** | PE-3, SC-7, SI-3, CM-8 | SC-10, SI-4, AC-17 | — |
| **SecOps** | AU-2, AU-6, SI-4, IR-4 | AU-12, IR-5, IR-6 | [M365 → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/) |
| **Threat Intelligence** | RA-3, SI-5, IR-4 | PM-16, RA-10 | [KEV → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/) |
| **MSSP** | IR-4, IR-7, CA-7 | IR-6, IR-8 | — |

---

## Vendor → NIST Control → ATT&CK Coverage

### GRC / Risk Management Vendors

| Vendor | Market Family | Primary NIST Controls | ATT&CK Coverage via CTID |
|---|---|---|---|
| ServiceNow | ServiceNow Partners | IR-8, PM-3, CA-5, PM-1 | IR workflow coverage across all tactics |
| RSA Archer | GRC | PM-1, RA-3, CA-2, CA-5 | Risk context across all tactics |
| OneTrust | GRC | PM-1, PM-20, RA-3, RA-8 | Privacy-relevant technique coverage |
| MetricStream | GRC | PM-1, RA-3, CA-2 | Risk and compliance coverage |
| Tenable | Risk & VM | RA-5, CM-8, SA-11 | [Via KEV](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/): Exploitation-mapped techniques |
| Qualys | Risk & VM | RA-5, CM-8, SI-2 | [Via KEV](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/): Exploitation-mapped techniques |
| Rapid7 | Risk & VM | RA-5, SI-2, CM-7 | [Via KEV](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/): Exploitation-mapped techniques |
| Wiz | Risk & VM / Cloud | RA-5, CM-8, AC-2, AU-2 | [AWS](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) · [Azure](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) · [GCP](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/gcp/) |

### Identity & Zero Trust Vendors

| Vendor | Market Family | Primary NIST Controls | ATT&CK Coverage via CTID |
|---|---|---|---|
| Microsoft Entra ID | Identity | IA-2, IA-5, AC-2, AC-3, AC-6 | [Azure IAM → T1078, T1110, T1556, T1134, T1098](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) |
| Okta | Identity | IA-2, IA-5, AC-2, AC-3 | Initial Access (T1078), Credential Access (T1110), Persistence (T1098) |
| CyberArk | Identity (PAM) | AC-2, AC-3, AC-6, IA-4 | Privilege Escalation (T1078.003), Credential Access (T1003) |
| BeyondTrust | Identity (PAM) | AC-2, AC-6, IA-4, AC-17 | Privilege Escalation, Lateral Movement via credentials |
| Ping Identity | Identity | IA-2, IA-8, AC-2, AC-3 | Initial Access, Credential Access |
| Zscaler | Zero Trust | AC-17, SC-7, AC-20, IA-3 | C2 (T1071), Lateral Movement (T1021), Exfiltration (T1048) |
| Netskope | Zero Trust | AC-4, SC-7, AC-20, MP-2 | Exfiltration (T1048), C2 (T1071), Collection (T1213) |

### Network Security Vendors

| Vendor | Market Family | Primary NIST Controls | ATT&CK Coverage via CTID |
|---|---|---|---|
| Palo Alto Networks NGFW | Network Security | SC-7, SC-8, AC-17, SI-3 | C2 (T1071), Lateral Movement (T1021), Execution (T1059) |
| Fortinet FortiGate | Network Security | SC-7, SC-10, AC-17 | C2, Lateral Movement, Defense Evasion |
| Cisco Secure Firewall | Network Security | SC-7, SC-8, AC-4 | Network-based technique coverage |
| Corelight | Network Security | AU-2, AU-12, SI-4 | Detection coverage across C2, Lateral Movement, Exfiltration |
| Darktrace | Network Security | SI-4, AU-6, AU-12 | Behavioral detection across all network-observable tactics |
| ExtraHop Reveal(x) | Network Security | SI-4, AU-2, AU-6 | Network detection across C2, Lateral Movement |
| Vectra AI | Network Security | SI-4, AU-6, AU-12 | C2 (T1071), Lateral Movement (T1021), Privilege Escalation |

### Endpoint / SecOps Vendors

| Vendor | Market Family | Primary NIST Controls | ATT&CK Coverage via CTID |
|---|---|---|---|
| CrowdStrike Falcon | SecOps (EDR) | SI-3, SI-4, CM-7, AU-2 | Broad coverage: Initial Access through Impact; all ATT&CK tactics |
| SentinelOne | SecOps (EDR) | SI-3, SI-4, CM-7 | Broad endpoint coverage across all ATT&CK tactics |
| Microsoft Defender for Endpoint | SecOps (EDR) | SI-3, SI-4, CM-7, AU-2 | [M365 → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/) comprehensive |
| Splunk ES | SecOps (SIEM) | AU-2, AU-6, AU-12, SI-4 | Detection coverage across all tactics via correlation |
| Microsoft Sentinel | SecOps (SIEM) | AU-2, AU-6, SI-4, IR-4 | [M365 → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/) + Azure |
| Elastic Security | SecOps (SIEM) | AU-2, AU-6, SI-4 | EQL behavioral detection across all tactics |
| Exabeam | SecOps (UEBA) | AU-6, SI-4, IR-4 | Insider threat, Credential Access, Lateral Movement |
| Securonix | SecOps (UEBA) | AU-6, SI-4, IA-4 | Behavioral analytics across Credential Access, Lateral Movement |

### Cloud Security Vendors

| Vendor | Market Family | Primary NIST Controls | ATT&CK Coverage via CTID |
|---|---|---|---|
| Wiz | Cloud Security | RA-5, CM-8, AC-2, AU-2 | [AWS](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) · [Azure](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) · [GCP](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/gcp/) cloud technique coverage |
| Prisma Cloud | Cloud Security | RA-5, CM-7, AC-2, SC-7 | Full cloud ATT&CK technique coverage via CSA CCM + cloud native |
| Orca Security | Cloud Security | RA-5, CM-8, AU-2 | [CSA CCM → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/csa/) |
| Microsoft Defender for Cloud | Cloud Security | RA-5, CM-8, AU-2, AC-2 | [Azure → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) native coverage |
| AWS Security Hub | Cloud Security | AU-2, RA-5, CM-8 | [AWS → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) native coverage |

### Email Security Vendors

| Vendor | Market Family | Primary NIST Controls | ATT&CK Coverage via CTID |
|---|---|---|---|
| Proofpoint | Email Security | SI-3, SI-8, SC-8, SC-28 | Initial Access (T1566 Phishing), Execution (T1204) |
| Mimecast | Email Security | SI-3, SI-8, SC-8 | Phishing (T1566), Execution via email (T1204) |
| Microsoft Defender for O365 | Email Security | SI-3, SI-8, SC-8 | [M365 → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/) email coverage |

### Threat Intelligence Vendors

| Vendor | Market Family | Primary NIST Controls | ATT&CK Coverage via CTID |
|---|---|---|---|
| Recorded Future | Threat Intelligence | RA-3, SI-5, PM-16 | Enrichment context across all tactics; [KEV](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/) alignment |
| Mandiant Advantage | Threat Intelligence | RA-3, SI-5, IR-4 | APT technique attribution across all ATT&CK tactics |
| CrowdStrike Intelligence | Threat Intelligence | RA-3, SI-5, PM-16 | Adversary-technique mapping across all tactics |

---

## Key ATT&CK Technique → NIST Control Reference

For practitioners building coverage maps, these are the most commonly targeted ATT&CK techniques and their primary NIST 800-53 mitigating controls.

| ATT&CK Technique | Tactic | Primary NIST Controls | Vendor Categories |
|---|---|---|---|
| T1078 Valid Accounts | Initial Access / Persistence | IA-2, AC-2, AC-3 | Identity, Zero Trust |
| T1566 Phishing | Initial Access | SI-3, SI-8, SC-28 | Email Security |
| T1059 Command & Scripting | Execution | CM-7, SI-3, SI-4 | EDR/SecOps |
| T1055 Process Injection | Defense Evasion | SI-3, SI-7, CM-7 | EDR/SecOps |
| T1003 OS Credential Dumping | Credential Access | AC-6, IA-5, SI-3 | Identity, EDR |
| T1021 Remote Services | Lateral Movement | AC-17, SC-7, IA-2 | Network, Zero Trust |
| T1071 Application Layer Protocol | C2 | SC-7, SC-8, SI-4 | Network Security, Zero Trust |
| T1048 Exfiltration Over Alt Protocol | Exfiltration | SC-7, AC-4, AU-12 | Network Security, DLP |
| T1486 Data Encrypted for Impact | Impact | CP-9, CP-10, SI-3 | Backup/Recovery, EDR |
| T1190 Exploit Public-Facing Application | Initial Access | SA-11, RA-5, SI-2 | AppSec, Risk & VM |
| T1098 Account Manipulation | Persistence | AC-2, IA-4, AC-3 | Identity |
| T1110 Brute Force | Credential Access | IA-5, AC-7, AU-2 | Identity |

---

## Using CTID Data for Gap Scoring

The CTID Mappings Explorer provides downloadable STIX/JSON data for each framework mapping. To build a coverage gap score:

1. Download the NIST 800-53 → ATT&CK mapping from CTID
2. For each vendor in your stack, identify which NIST controls they satisfy
3. Join: `vendor_nist_controls` ∩ `ctid_nist_to_attck` → techniques covered by vendor
4. Union across all vendors in your stack → total technique coverage
5. Complement: `all_attck_techniques` − `covered_techniques` → **gap list**
6. Score gaps by tactic, technique criticality (EPSS/KEV), and pipeline stage

See [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md) for the full data model and scoring logic.


### Vendor to NIST 800-53 Control Mapping Reference

**Identity and Access Management**
| Vendor / Solution | NIST 800-53 Controls | Description |
|---|---|---|
| Okta / Azure AD / Ping | AC-2, AC-3, IA-2, IA-5, IA-8 | Identity providers mapping access to controls |
| CyberArk PAM | AC-2, AC-3, AC-6, IA-2, AU-9 | Privileged access management |
| BeyondTrust | AC-2, AC-6, AC-17, IA-2 | Remote access + privileged session management |
| SailPoint IIQ | AC-2, AC-5, AC-6, AU-9 | Identity governance and access reviews |
| Saviynt | AC-2, AC-3, AC-5, AC-6 | IGA and privileged access |
| Duo Security | IA-2(1), IA-2(2), IA-2(8), IA-2(12) | MFA enforcement |

**Endpoint Security**
| Vendor / Solution | NIST 800-53 Controls | Description |
|---|---|---|
| CrowdStrike Falcon | SI-3, SI-7, SI-16, AU-12, IR-4 | EDR/AV, IOA detection, threat hunting |
| Microsoft Defender for Endpoint | SI-3, SI-4, SI-7, AU-2, CM-7 | EDR + ASR rules + attack surface reduction |
| SentinelOne | SI-3, SI-4, SI-7, IR-4 | AI-powered EDR with rollback capability |
| Carbon Black | SI-3, SI-4, AU-12 | Behavioral EDR and threat hunting |
| Tanium | CM-1, CM-2, CM-6, SI-2, SI-3 | Endpoint management + vulnerability scanning |

**Network Security**
| Vendor / Solution | NIST 800-53 Controls | Description |
|---|---|---|
| Palo Alto Networks NGFW | SC-7, SC-8, SI-3, AC-17 | Next-gen firewall with app-ID and threat prevention |
| Zscaler ZIA | SC-7, SC-8, SC-28, AC-17, SI-3 | Secure web gateway + cloud firewall |
| Zscaler ZPA | AC-17, AC-3, SC-7, SC-28 | Zero Trust Network Access |
| Fortinet FortiGate | SC-7, SC-8, SI-3, AC-17 | NGFW with SD-WAN integration |
| Cisco Umbrella | SC-7, SI-3, SC-20 | DNS-layer security |
| Akamai Enterprise App Access | AC-17, SC-7, IA-8 | ZTNA platform |

**Security Operations / SIEM**
| Vendor / Solution | NIST 800-53 Controls | Description |
|---|---|---|
| Splunk Enterprise Security | AU-2, AU-3, AU-6, IR-4, IR-5, SI-4 | SIEM with UBA and SOAR |
| Microsoft Sentinel | AU-2, AU-3, AU-6, AU-12, IR-4 | Cloud-native SIEM + SOAR |
| IBM QRadar | AU-2, AU-6, IR-4, IR-5, SI-4 | SIEM with threat intelligence integration |
| Elastic SIEM | AU-2, AU-6, SI-4 | Open-source SIEM on ELK stack |
| Palo Alto Cortex XSIAM | AU-2, AU-6, IR-4, SI-4 | AI-driven SOC platform |

**Vulnerability and Compliance**
| Vendor / Solution | NIST 800-53 Controls | Description |
|---|---|---|
| Tenable.io / Nessus | RA-3, RA-5, SI-2, CA-7 | Vulnerability scanning and assessment |
| Qualys VMDR | RA-5, SI-2, CM-6, CA-7 | VM + compliance + CSPM |
| Rapid7 InsightVM | RA-5, SI-2, CM-6 | Vulnerability management with risk scoring |
| Wiz | RA-5, CM-6, AC-3, SC-7 | Cloud-native CSPM/CNAPP |
| Orca Security | RA-5, CM-6, SC-7 | Agentless cloud security posture |
| Lacework | AU-2, RA-5, CM-6, IR-4 | Cloud security + behavioral detection |

**Email Security**
| Vendor / Solution | NIST 800-53 Controls | Description |
|---|---|---|
| Proofpoint | SI-3, SC-8, SC-28, SC-7 | Advanced threat protection for email |
| Microsoft Defender for Office 365 | SI-3, SC-8, SC-28 | Native email security for M365 |
| Mimecast | SI-3, SC-8, AU-2 | Email security + archive + continuity |
| Abnormal Security | SI-3, SC-7 | AI-based email threat detection |
| Ironscales | SI-3, AT-2 | Email security + phishing training |

### ATT&CK Technique to Control Family Mapping

| ATT&CK Tactic | Example Technique | Primary 800-53 Controls |
|---|---|---|
| Initial Access | T1566 Phishing | SC-7, SC-8, AT-2, SI-3 |
| Initial Access | T1190 Exploit Public App | SI-2, RA-5, CM-6, SC-7 |
| Execution | T1059 Command-Line Interface | CM-7, SI-4, AU-12 |
| Persistence | T1053 Scheduled Task | CM-7, SI-4, AU-2 |
| Privilege Escalation | T1548 Abuse Elevation Control | AC-6, CM-6, AU-12 |
| Defense Evasion | T1562 Impair Defenses | AU-9, SI-7, SI-4 |
| Credential Access | T1003 OS Credential Dumping | IA-5, AC-6, SC-28 |
| Discovery | T1083 File and Directory Discovery | AU-12, SI-4 |
| Lateral Movement | T1021 Remote Services | AC-17, SC-7, AC-3 |
| Collection | T1560 Archive Collected Data | SC-28, AU-12 |
| Exfiltration | T1048 Exfiltration Over Alt Protocol | SC-7, AU-12, SI-4 |
| Command & Control | T1071 App Layer Protocol | SC-7, SI-4, SI-3 |
| Impact | T1486 Data Encrypted for Impact | CP-9, SC-28, SI-3 |

---
