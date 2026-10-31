# Security platforms

Reference pages for the vendor platforms that a security program runs on: endpoint and extended detection, vulnerability and exposure management, the vulnerability workflow and SIEM and SOAR, email and network security, firewalls and network appliances, identity and privilege, application and crowdsourced security, and backup and recovery. Each page is a product-level reference: what the platform is, how it works, what it produces, how it is deployed and integrated, and how to secure the platform itself. These describe product families as generally available in 2026; licence tier and module entitlement decide what is in force in any given environment, so verify against the live configuration.

These pages complement the concept references. For how scanners produce and classify findings see [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md); for the program that acts on them see [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

Related: [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Vendor tools](/tools/README.md), [Reference Index](/INDEX.md).

---

## Endpoint and extended detection

| Platform | Summary |
|---|---|
| [CrowdStrike Falcon](/platforms/crowdstrike-falcon.md) | Cloud-native endpoint protection, EDR, and exposure management on a single sensor |
| [Microsoft Defender for Endpoint](/platforms/microsoft-defender.md) | Microsoft endpoint EDR with Defender Vulnerability Management |
| [Tanium](/platforms/tanium.md) | Real-time endpoint query and action at scale, with patch and compliance |
| [Trend Vision One](/platforms/trend-micro.md) | Trend Micro's XDR platform, including the former Cloud One workload and cloud security |
| [SentinelOne Singularity](/platforms/sentinelone.md) | Autonomous endpoint and extended detection with on-device AI and Storyline correlation |
| [Sophos](/platforms/sophos.md) | Intercept X endpoint with deep-learning prevention and anti-ransomware, and Sophos XDR and MDR |
| [Trellix](/platforms/trellix.md) | Endpoint and XDR from the McAfee Enterprise and FireEye combination, managed through ePO |
| [Bitdefender GravityZone](/platforms/bitdefender.md) | Endpoint protection and EDR/XDR with layered prevention and risk analytics |

## Vulnerability and exposure management

| Platform | Summary |
|---|---|
| [Tenable](/platforms/tenable.md) | Exposure management on Tenable One, with Nessus, VPR, and Identity Exposure |
| [Qualys](/platforms/qualys.md) | The Qualys Cloud Platform with VMDR and TruRisk |
| [Wiz](/platforms/wiz.md) | Agentless cloud-native application protection and the Security Graph |
| [Rapid7 InsightVM](/platforms/rapid7-insightvm.md) | Vulnerability management with Real Risk scoring on the Insight platform |
| [Zafran](/platforms/zafran.md) | Threat exposure management that prioritizes by exploitability and existing control coverage, and drives mitigations |

## Vulnerability workflow, SIEM, and SOAR

| Platform | Summary |
|---|---|
| [ServiceNow Vulnerability Response](/platforms/servicenow-vr.md) | Turns scanner findings into owned, tracked remediation work mapped to the CMDB |
| [Splunk Enterprise Security](/platforms/splunk.md) | SIEM with SPL, correlation searches, risk-based alerting, and SOAR |
| [IBM QRadar](/platforms/qradar.md) | SIEM with events, flows, and offenses, with notes on the XSIAM transition |
| [Cortex XSOAR](/platforms/cortex-xsoar.md) | Security orchestration, automation, and response with playbooks |
| [Tines](/platforms/tines.md) | No-code security automation and orchestration |

## Email and network security

| Platform | Summary |
|---|---|
| [Proofpoint](/platforms/proofpoint.md) | Email security, attachment and URL sandboxing, DLP, and awareness training |
| [Zscaler](/platforms/zscaler.md) | The Zero Trust Exchange: secure web gateway and zero-trust network access |
| [Cisco Secure Access](/platforms/cisco-secure-access.md) | Cisco's security service edge with ZTNA, SWG, CASB, and DNS-layer security |
| [Forcepoint](/platforms/forcepoint.md) | Data-first security: security service edge and data loss prevention |
| [Fortinet](/platforms/fortinet.md) | The Security Fabric: FortiGate firewall, FortiNDR, and analytics |
| [Akamai](/platforms/akamai.md) | Edge platform with a web application and API firewall, bot and DDoS protection, and segmentation |
| [Netskope](/platforms/netskope.md) | Netskope One security service edge: secure web gateway, CASB, zero-trust access, and DLP |
| [Cloudflare](/platforms/cloudflare.md) | Edge platform with a WAF, DDoS protection, and the Cloudflare One zero-trust services |
| [Mimecast](/platforms/mimecast.md) | Email security and resilience with URL and attachment protection, DLP, and archiving |
| [Abnormal AI](/platforms/abnormal.md) | Behavioral-AI email security for business email compromise and account takeover |

## Firewalls and network appliances

| Platform | Summary |
|---|---|
| [Check Point](/platforms/check-point.md) | Quantum gateways with IPS virtual patching and threat prevention |
| [Citrix NetScaler](/platforms/citrix-netscaler.md) | Application delivery controller with a web application firewall and fleet CVE matching |
| [Cisco ISE](/platforms/cisco-ise.md) | Network access control with 802.1X, posture, and Change of Authorization |
| [Palo Alto Networks](/platforms/palo-alto-networks.md) | Next-generation firewalls on PAN-OS, Prisma Access SASE, and the Cortex operations family |
| [F5](/platforms/f5.md) | BIG-IP application delivery and Advanced WAF, and F5 Distributed Cloud services |

## Identity, access, and privilege

| Platform | Summary |
|---|---|
| [Microsoft Entra ID](/platforms/entra-id.md) | Cloud identity with Conditional Access, MFA, and Privileged Identity Management |
| [Cisco Duo](/platforms/cisco-duo.md) | Multi-factor authentication and device trust |
| [CyberArk](/platforms/cyberark.md) | Privileged access management, vaulting, and endpoint privilege |
| [SailPoint](/platforms/sailpoint.md) | Identity governance: provisioning, certifications, and the role model |
| [Okta](/platforms/okta.md) | Workforce and customer identity: SSO, adaptive MFA, Universal Directory, and lifecycle |
| [Ping Identity](/platforms/ping-identity.md) | Enterprise identity with PingOne, PingFederate federation, and PingAccess |
| [BeyondTrust](/platforms/beyondtrust.md) | Privileged access management: password vaulting, remote access, and endpoint privilege |
| [Delinea](/platforms/delinea.md) | Privileged access management with Secret Server and endpoint privilege |

## Application and crowdsourced security

| Platform | Summary |
|---|---|
| [Snyk](/platforms/snyk.md) | Developer-first SCA, SAST, container, and IaC security |
| [Invicti](/platforms/invicti.md) | Proof-based dynamic and interactive application security testing |
| [HackerOne](/platforms/hackerone.md) | Bug bounty, vulnerability disclosure, and pentest-as-a-service |
| [Chainguard](/platforms/chainguard.md) | Secure-by-default minimal container images and a hardened Wolfi base that cut image vulnerabilities |

## Cloud and container security

| Platform | Summary |
|---|---|
| [Prisma Cloud](/platforms/prisma-cloud.md) | Palo Alto Networks CNAPP across posture, workload, entitlements, and code security |
| [Orca Security](/platforms/orca-security.md) | Agentless CNAPP using SideScanning with a unified cloud data model |
| [Aqua Security](/platforms/aqua-security.md) | Container and cloud-native security with image assurance and runtime protection |
| [Sysdig](/platforms/sysdig.md) | Cloud-native security on the Falco project, with runtime detection and response |

## Operational technology and ICS

| Platform | Summary |
|---|---|
| [Dragos](/platforms/dragos.md) | OT and ICS threat detection, asset visibility, and vulnerability management |
| [Claroty](/platforms/claroty.md) | Cyber-physical systems protection across OT, IoT, and healthcare devices |

## Backup, recovery, and cyber resilience

The corrective control after destructive exploitation such as ransomware, where re-imaging restores the operating system but not the data. See [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md) and [Cyber Resilience and BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md).

| Platform | Summary |
|---|---|
| [Veeam](/platforms/veeam.md) | Backup and replication with immutable repositories and recovery verification |
| [Rubrik](/platforms/rubrik.md) | Backup with immutable storage and ransomware anomaly detection |
| [Cohesity](/platforms/cohesity.md) | Data management with immutable snapshots and threat detection |
| [Commvault](/platforms/commvault.md) | Backup and recovery with immutable, air-gapped copies and cyber deception |
| [Veritas NetBackup](/platforms/veritas-netbackup.md) | Enterprise backup with WORM storage and malware scanning |
| [Dell PowerProtect](/platforms/dell-powerprotect.md) | Protection storage with an air-gapped Cyber Recovery vault |
| [AWS Backup](/platforms/aws-backup.md) | AWS-native centralized backup with Vault Lock immutability |
| [Azure Backup](/platforms/azure-backup.md) | Azure-native backup with immutable vaults and multi-user authorization |
