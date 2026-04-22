# SIEM Detection Content Reference

Detection content from official repositories, maintained by the organizations that build the underlying platforms. All sources are authoritative and regularly updated by practitioners.

---

## Sigma — Universal Detection Rule Format
*Source: github.com/SigmaHQ/sigma | sigmahq.io*

### What is Sigma
- Platform-agnostic detection rule format (YAML) created by Florian Roth and Thomas Patzke
- 3,000+ community rules covering ATT&CK techniques
- Converts to: Splunk SPL, KQL, Elastic EQL, QRadar, Chronicle, Suricata, Carbon Black, and 30+ backends

### Sigma Rule Structure (from official spec)
```yaml
title: Mimikatz Command Line
id: 60bc6bb4-70ee-4dc8-a29c-f18a5f4a49c4
status: stable
description: Detects common Mimikatz command line arguments
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
author: Florian Roth
date: 2018/10/09
modified: 2023/11/09
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'DumpCreds'
            - 'invoke-mimikatz'
            - 'lsadump::sam'
            - 'sekurlsa::logonpasswords'
            - 'lsadump::dcsync'
    condition: selection
falsepositives:
    - Unlikely
level: high
```

### pySigma — Official Conversion Framework
*Source: github.com/SigmaHQ/pySigma*
```bash
pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch
# Convert Sigma to Splunk
sigma convert -t splunk -p splunk_windows rules/windows/process_creation/
# Convert to KQL
sigma convert -t microsoft365defender rules/windows/
```

### Sigma Rule Repository Categories
High-value rule directories in SigmaHQ/sigma:
- `rules/windows/process_creation/` — 800+ process execution detections
- `rules/windows/registry_event/` — Registry persistence and tampering
- `rules/windows/network_connection/` — Suspicious network connections
- `rules/windows/pipe_created/` — Named pipe detections (Cobalt Strike etc.)
- `rules/linux/auditd/` — Linux audit log detections
- `rules/cloud/aws/` — AWS CloudTrail detections
- `rules/cloud/azure/` — Azure Activity Log detections

---

## Splunk Security Content (ESCU)
*Source: github.com/splunk/security_content | splunkbase.splunk.com*
*Maintained by: Splunk Threat Research Team (STRT)*

### Content Types
- **Analytics**: SPL-based detections (1,000+)
- **Baselines**: Normal behavior establishment
- **Investigations**: Analyst workflow searches
- **Lookups**: Reference data (malicious IPs, suspicious commands, etc.)
- **Analytic Stories**: Themed collection of detections + investigations

### Installing ESCU
```bash
# Option 1: Via Splunkbase
# Install "Splunk Security Essentials" + "DA-ESS-ContentUpdate" from apps.splunk.com

# Option 2: Via CLI
splunk install app /path/to/escu.spl -auth admin:password

# Option 3: GitHub (dev/preview content)
git clone https://github.com/splunk/security_content
cd security_content
pip install -r requirements.txt
python contentctl build
```

### Key Analytic Stories (from official repository)
| Analytic Story | Detections | Description |
|---|---|---|
| Ransomware | 50+ | Detection of ransomware TTPs across the kill chain |
| Cobalt Strike | 25+ | CS beacon, malleable C2, staging detections |
| Active Directory Kerberos Attacks | 20+ | Kerberoasting, AS-REP, DCSync, Golden Ticket |
| Credential Dumping | 30+ | LSASS, SAM, NTDS, credential access |
| Living Off The Land | 40+ | LOLBin abuse, trusted process misuse |
| AWS IAM Privilege Escalation | 15+ | Cloud privesc via IAM misuse |
| Data Exfiltration | 20+ | Staging, compression, transfer detection |

### Example ESCU Detection SPL
```spl
`sysmon` EventCode=10 TargetImage="*\\lsass.exe"
  CallTrace="*dbgcore.dll*" OR CallTrace="*dbghelp.dll*" OR CallTrace="*ntdll.dll*C_07*"
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `detect_lsass_memory_dump_via_dbgcore_filter`
```

### STRT Blog and Research
- Splunk Security Blog: blogs.splunk.com/security — new detection research
- GitHub Issues/Releases: contribution process for new detections

---

## Elastic Security Detection Rules
*Source: github.com/elastic/detection-rules*
*Maintained by: Elastic Security Research team*

### Repository Structure
```
detection-rules/
├── rules/                  # Production rules (TOML format)
│   ├── windows/           # Windows-specific rules
│   ├── linux/             # Linux rules
│   ├── macos/             # macOS rules
│   ├── network/           # Network-based detections
│   └── ml/                # Machine learning jobs
├── rules_building_block/  # Building block rules (not standalone alerts)
├── hunting/               # Threat hunting queries (EQL)
└── tests/                 # Rule unit tests
```

### Installing via Kibana
```bash
# Via Detection Rules Management UI
# Stack Management > Security > Rules > Import Rules

# Via CLI (detection-rules tool)
pip install detection-rules
python -m detection_rules kibana upload-rule rules/windows/credential_access_lsass_memory_dump_handle.toml
# Or bulk import
python -m detection_rules kibana upload-rule --directory rules/windows/
```

### Rule Types Available
| Rule Type | Description | Example Use |
|---|---|---|
| query | KQL or Lucene query | Simple field matching |
| eql | Event Query Language | Sequence/correlation |
| threshold | Aggregate threshold | Brute force detection |
| machine_learning | ML anomaly job | Behavioral anomaly |
| threat_match | IOC match against feed | Threat intel correlation |
| new_terms | New value in field | First-seen user agent |
| esql | ES|QL query | Complex analytics |

### High-Confidence Production Rules (from elastic/detection-rules)
```toml
# LSASS Memory Dump Handle Access
[rule]
name = "LSASS Memory Dump Handle Access"
type = "eql"
query = '''
process where host.os.type == "windows" and event.action == "start" and
  process.name : ("procdump.exe", "procdump64.exe") and
  process.args : ("-ma", "/ma")
'''

# Suspicious PowerShell Encoded Command
[rule]
name = "Suspicious PowerShell Encoded Command"
type = "eql"
query = '''
process where host.os.type == "windows" and event.action == "start" and
  process.name : ("powershell.exe", "pwsh.exe") and
  process.args : ("-enc", "-EncodedCommand", "/enc", "/EncodedCommand")
'''
```

### Elastic SIEM Machine Learning Jobs
Built-in ML jobs for anomaly detection:
- `windows_rare_user_type10_remote_login` — Rare remote login user
- `packetbeat_dns_tunneling` — DNS tunneling via Packetbeat
- `rare_process_by_host_windows_ecs` — Rare process execution
- `v3_windows_network_connection_anomalies` — Anomalous network connections
- `v3_linux_system_user_discovery` — Linux user discovery anomaly

---

## Microsoft Sentinel Analytics Rules
*Source: github.com/Azure/Azure-Sentinel*
*Source: learn.microsoft.com/azure/sentinel*

### Content Hub Solutions
Install from Sentinel Content Hub (100+ solutions, each with rules + workbooks + playbooks):
- **Microsoft 365 Defender**: 50+ rules from M365 signals
- **Azure Active Directory**: Identity attack detections
- **Microsoft Defender for Cloud**: Cloud workload detections
- **UEBA**: User/Entity Behavior Analytics
- **MITRE ATT&CK**: Rules organized by ATT&CK technique

### GitHub Repository Structure
```
Azure-Sentinel/
├── Detections/          # Scheduled analytics rules (KQL, ARM)
│   ├── AzureActiveDirectory/
│   ├── Endpoint/
│   ├── MultipleDataSources/
│   └── ...
├── Hunting Queries/     # Proactive threat hunting (KQL)
├── Playbooks/           # SOAR automation (Logic Apps)
└── Solutions/           # Content Hub packages
```

### Deploying Rules via API
```bash
# Deploy all rules from a category
az rest --method PUT \
  --uri "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alertRules/{rule-id}?api-version=2023-02-01" \
  --body @rule.json

# List all enabled scheduled rules
az rest --method GET \
  --uri "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01" \
  | jq '.value[] | select(.kind=="Scheduled") | {name: .properties.displayName, severity: .properties.severity}'
```

### High-Value Community Rules (from Azure-Sentinel GitHub)
Key detections in the official repo:
- **Rare MFA app enrollment** — detects new app enrollment (potential MFA fatigue setup)
- **Impossible travel** — sign-in from geographically impossible locations
- **AAD user disabled then enabled** — account manipulation pattern
- **First access from new country** — UEBA-type detection
- **High volume of failed MFA** — MFA spraying/fatigue precursor

---

## MITRE ATT&CK Mitigations
*Source: attack.mitre.org/mitigations*
*Source: github.com/mitre-attack/attack-stix-data*

### ATT&CK Mitigation Objects
Each ATT&CK Mitigation (M-series) maps to specific techniques:

| Mitigation ID | Name | Key Techniques Addressed |
|---|---|---|
| M1036 | Account Use Policies | T1110 (Brute Force), T1078 (Valid Accounts) |
| M1015 | Active Directory Configuration | T1558 (Steal Kerberos Tickets), T1484 (Domain Policy Modification) |
| M1049 | Antivirus/Antimalware | T1566 (Phishing), T1204 (User Execution) |
| M1013 | Application Developer Guidance | T1190 (Exploit Public App), T1059 (Command Interpreter) |
| M1048 | Application Isolation and Sandboxing | T1059 (Scripting), T1566.001 (Spearphishing Attachment) |
| M1047 | Audit | T1078 (Valid Accounts), T1098 (Account Manipulation) |
| M1040 | Behavior Prevention on Endpoint | T1059 (Command and Scripting Interpreter) |
| M1046 | Boot Integrity | T1542 (Pre-OS Boot) |
| M1043 | Credential Access Protection | T1003 (OS Credential Dumping), T1552 (Credentials in Files) |
| M1032 | Multi-factor Authentication | T1078, T1110, T1621 (MFA Request Generation) |
| M1026 | Privileged Account Management | T1078, T1098, T1548 (Abuse Elevation Control) |
| M1030 | Network Segmentation | T1021 (Lateral Movement), T1570 (Lateral Tool Transfer) |
| M1031 | Network Intrusion Prevention | T1190, T1566, T1498 (Network DoS) |
| M1027 | Password Policies | T1110, T1078, T1552 |
| M1017 | User Training | T1566 (Phishing), T1204 (User Execution) |
| M1051 | Update Software | T1190, T1203 (Exploitation for Client Execution) |
| M1038 | Execution Prevention | T1059 (Scripting), T1204 (User Execution) |
| M1018 | User Account Management | T1078, T1136 (Create Account) |

### Downloading ATT&CK Data
```bash
# STIX 2.1 format (full ATT&CK knowledge base)
curl -O https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

# Using mitreattack-python
pip install mitreattack-python
python3 -c "
from mitreattack.stix20 import MitreAttackData
md = MitreAttackData('enterprise-attack.json')
mitigations = md.get_mitigations(remove_revoked_deprecated=True)
print(f'Total mitigations: {len(mitigations)}')
"
```

---

## CIS Controls v8 Implementation Guide
*Source: cisecurity.org/controls/v8 | github.com/CISecurity*

### CIS Controls Overview
18 Controls organized into 3 Implementation Groups (IGs):
- **IG1**: Essential cyber hygiene (small orgs, limited IT, Safeguards 1-56)
- **IG2**: IG1 + additional controls for moderate risk (mid-size, Safeguards 1-130)
- **IG3**: IG2 + full controls for high risk/regulatory (large/sensitive, all 153 Safeguards)

### Controls by Category
| # | Control | IG1 Safeguards |
|---|---|---|
| 1 | Inventory and Control of Enterprise Assets | 1.1-1.5 |
| 2 | Inventory and Control of Software Assets | 2.1-2.7 |
| 3 | Data Protection | 3.1-3.5 |
| 4 | Secure Configuration of Enterprise Assets and Software | 4.1-4.8 |
| 5 | Account Management | 5.1-5.6 |
| 6 | Access Control Management | 6.1-6.8 |
| 7 | Continuous Vulnerability Management | 7.1-7.6 |
| 8 | Audit Log Management | 8.1-8.8 |
| 9 | Email and Web Browser Protections | 9.1-9.7 |
| 10 | Malware Defenses | 10.1-10.7 |
| 11 | Data Recovery | 11.1-11.5 |
| 12 | Network Infrastructure Management | 12.1-12.8 |
| 13 | Network Monitoring and Defense | 13.1-13.11 |
| 14 | Security Awareness and Skills Training | 14.1-14.9 |
| 15 | Service Provider Management | 15.1-15.7 |
| 16 | Application Software Security | 16.1-16.14 |
| 17 | Incident Response Management | 17.1-17.9 |
| 18 | Penetration Testing | 18.1-18.5 |

### CIS Benchmarks (Official Downloads)
*Source: cisecurity.org/cis-benchmarks*
Available free (with registration) for:
- Windows Server 2022, Windows 10/11
- Ubuntu Linux 22.04, RHEL 9, CentOS
- macOS Ventura/Sonoma
- AWS Foundations, Azure Foundations, GCP Foundations
- Docker, Kubernetes
- Microsoft 365, Google Workspace
- Apache, NGINX, IIS

CIS-CAT Pro: automated benchmark scanning tool (available to CIS SecureSuite members)

---

## DISA STIGs
*Source: public.cyber.mil/stigs*
*Maintained by: Defense Information Systems Agency (DISA)*

### What Are STIGs
Security Technical Implementation Guides — mandatory for DoD, gold standard for government and regulated industries

### STIG Content Downloads
```bash
# Download STIG library (zip of XML files)
# Available at: https://public.cyber.mil/stigs/downloads/
# Key STIGs:
# - Windows Server 2022 STIG
# - Red Hat Enterprise Linux 9 STIG
# - Google Chrome STIG
# - Microsoft Office STIGs (Word, Excel, Outlook, Teams)
# - VMware vSphere 8 STIG
```

### STIG Viewer Usage
- Download STIG Viewer from public.cyber.mil
- Open STIG XML, then filter by Category (CAT I = Critical, CAT II = High, CAT III = Medium)
- Export checklist (.ckl) for tracking compliance
- InSpec/SCC SCAP tool for automated STIG scanning

### High-Priority (CAT I) STIG Requirements — Windows Server 2022
CAT I findings that are commonly failed:
- V-254239: Accounts with blank passwords must be disabled
- V-254240: Reversible password encryption must be disabled
- V-254241: Automatic logon must be disabled
- V-254256: Anonymous SID/Name translation must be disabled
- V-254257: Anonymous enumeration of SAM accounts must be restricted

---

## Google Chronicle / YARA-L Rules
*Source: cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax*

### YARA-L 2.0 Rule Format
```
rule suspicious_powershell_download {
  meta:
    author = "Google SecOps"
    description = "Detects PowerShell downloading content"
    severity = "HIGH"
    priority = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.file.full_path = /powershell\.exe$/i
    $e.principal.process.command_line = /DownloadString|DownloadFile|WebClient|Invoke-WebRequest/i

  condition:
    $e
}
```

### Chronicle Community Rules
*Source: github.com/chronicle/detection-rules*

---

## IBM QRadar Use Cases
*Source: ibm.com/docs/en/qradar-on-cloud | IBM X-Force Exchange*

### QRadar SIEM Rules — Built-in Use Cases
High-value default rules by category:
- **Authentication**: Multiple Failed Logins Followed by Success, Admin Logon Outside Business Hours
- **Network**: Port Scan Detected, Beaconing Behavior, DNS Tunneling
- **Endpoint**: Malware Detected, Potential Lateral Movement via SMB
- **Custom Rules**: via Rules Wizard or API

### IBM X-Force Exchange
*Source: exchange.xforce.ibmcloud.com*
- IP reputation feeds, malware reports, vulnerability intelligence
- Collections: curated intel sets for specific threats
- API: `curl -H "Authorization: Basic $(echo -n apikey:password | base64)" https://api.xforce.ibmcloud.com/ipr/IP`

---

## Authoritative Detection Content Sources Summary

| Source | URL | Content | License |
|---|---|---|---|
| SigmaHQ/sigma | github.com/SigmaHQ/sigma | 3,000+ multi-platform rules | DRL |
| elastic/detection-rules | github.com/elastic/detection-rules | 1,000+ EQL/KQL rules | Elastic License |
| splunk/security_content | github.com/splunk/security_content | 1,000+ Splunk detections | Apache 2.0 |
| Azure/Azure-Sentinel | github.com/Azure/Azure-Sentinel | 1,000+ Sentinel rules | MIT |
| chronicle/detection-rules | github.com/chronicle/detection-rules | YARA-L rules | Apache 2.0 |
| mitre-attack/attack-stix-data | github.com/mitre-attack/attack-stix-data | Full ATT&CK dataset | CC BY 4.0 |
| cisagov/ScubaGear | github.com/cisagov/ScubaGear | M365/Google baseline policies | Creative Commons |
| DISA STIGs | public.cyber.mil/stigs | DoD hardening requirements | Public domain |
| CIS Benchmarks | cisecurity.org/cis-benchmarks | Hardening benchmarks | CIS license |
| NSA Advisories | media.defense.gov | Technical hardening guides | Public domain |
| CISA Advisories | cisa.gov/resources-tools/resources | Threat advisories + controls | Public domain |
