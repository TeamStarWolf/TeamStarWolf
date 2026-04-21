# Cloud Security

Cloud security encompasses the practices, tools, and governance required to secure infrastructure, workloads, data, and identities in cloud environments — primarily AWS, Azure, and Google Cloud Platform, along with the Kubernetes and container ecosystems that run on top of them. The discipline has evolved from traditional security lifted to the cloud into something fundamentally different: infrastructure is ephemeral, identity and access management is the primary attack vector, configuration drift is constant, and the blast radius of a single overprivileged role can be an entire organization. Cloud-native architectures — serverless functions, managed Kubernetes, shared IAM hierarchies — introduce attack surfaces that have no analog in traditional on-premises security.

The shared responsibility model is the foundational concept every cloud security practitioner must internalize: the cloud provider secures the infrastructure, but the customer owns the configuration, identity management, data protection, and workload security. The vast majority of cloud security incidents are not the result of cloud provider failures — they are the result of misconfigured S3 buckets, overprivileged IAM roles, exposed secrets in environment variables, and SSRF vulnerabilities that reach cloud metadata APIs. These are customer-owned failure modes, and cloud security is the discipline of systematically finding and eliminating them.

---

## Where to Start

Earn AWS Solutions Architect Associate (or its Azure/GCP equivalent) before focusing on security. The security knowledge is useless without understanding how cloud infrastructure is actually built. Once you have that foundation, flaws.cloud is the single best entry point into cloud security practice — complete every level before spending money on any certification or course.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Shared responsibility model, cloud IAM fundamentals, S3/blob storage security, VPC/network segmentation, CloudTrail/cloud logging | [AWS Cloud Practitioner (free)](https://aws.amazon.com/training/digital/aws-cloud-practitioner-essentials/), [flaws.cloud](http://flaws.cloud), [BHIS cloud security webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) |
| Practitioner | Cloud pentesting (IAM privesc, SSRF to metadata, S3 enumeration), cloud-native logging and detection, container security, Kubernetes hardening | [flaws.cloud](http://flaws.cloud) + [flaws2.cloud](http://flaws2.cloud), [CloudGoat (Rhino Security)](https://github.com/RhinoSecurityLabs/cloudgoat), [HTB Academy Cloud path](https://academy.hackthebox.com), [Wiz Academy (free)](https://www.wiz.io/academy) |
| Advanced | Multi-cloud CSPM, cloud IR and forensics, zero trust architecture, eBPF-based runtime security, CNAPP concepts, cloud attack simulation | [SANS SEC541](https://www.sans.org/cyber-security-courses/aws-bootcamp/)/[SEC588](https://www.sans.org/cyber-security-courses/cloud-penetration-testing/), [Wiz Research blog](https://www.wiz.io/blog/tag/research), [Stratus Red Team](https://stratus-red-team.cloud), [CNCF security papers](https://github.com/cncf/tag-security) |

---

## Free Training

- [Flaws.cloud](http://flaws.cloud) and [Flaws2.cloud](http://flaws2.cloud) — The best free cloud security labs available anywhere; real AWS misconfiguration scenarios teaching S3 exposure, SSRF to metadata API, IAM privilege escalation, and Lambda exploitation; complete both before any certification exam
- [Wiz Academy](https://www.wiz.io/academy) — Free cloud security training from Wiz covering cloud architecture, misconfigurations, and CSPM concepts; practitioner-focused and kept current
- [Hack The Box Academy Cloud Path](https://academy.hackthebox.com) — Free Student tier covering AWS and Azure attack techniques with hands-on labs
- [BHIS Cloud Security Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering cloud attack techniques, cloud IR, and cloud security architecture
- [A Cloud Guru Free Tier](https://acloudguru.com) — Free introductory courses covering AWS, Azure, and GCP fundamentals; build the cloud knowledge foundation before layering on security
- [AWS Security Learning Plan](https://aws.amazon.com/training/learn-about/security/) — Free AWS-official training covering IAM, VPC security, GuardDuty, Security Hub, and cloud security best practices
- [CNCF Security Whitepapers](https://github.com/cncf/tag-security) — Free container and Kubernetes security papers from the Cloud Native Computing Foundation; authoritative cloud-native security architecture guidance
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) — Official Kubernetes security docs covering RBAC, network policies, pod security, and secrets management
- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices) — Free GCP security guidance covering IAM, VPC Service Controls, and Cloud Logging
- [Stratus Red Team Documentation](https://stratus-red-team.cloud) — Free cloud attack simulation tool documentation; teaches cloud attack techniques by explaining what each technique does and how to detect it

---

## Tools & Repositories

### Multi-Cloud & CSPM
- [aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit) — Open-source cloud security scanner covering 500+ checks across AWS, Azure, GCP, and Oracle Cloud; the leading open-source CSPM engine
- [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) — Static IaC security scanner covering Terraform, CloudFormation, Kubernetes, ARM, and Bicep; 1000+ built-in policies; standard in DevSecOps pipelines
- [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) — Multi-cloud security auditing from NCC Group covering AWS, Azure, GCP, Alibaba, and Oracle; generates detailed HTML posture reports
- [turbot/steampipe](https://github.com/turbot/steampipe) — SQL query interface for cloud APIs; query AWS/Azure/GCP resources like database tables for ad-hoc posture queries and compliance checks

### AWS-Specific
- [RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) — Vulnerable-by-design AWS environment for practicing cloud attack techniques; scenario-based labs covering IAM privilege escalation, Lambda exploitation, and more
- [RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu) — AWS exploitation framework from Rhino Security Labs; modular post-exploitation toolkit for compromised AWS environments
- [nccgroup/PMapper](https://github.com/nccgroup/PMapper) — AWS IAM privilege escalation analysis; maps all possible privilege escalation paths in an AWS account using graph analysis
- [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) — AWS security assessment and compliance auditing; 300+ checks covering CIS AWS benchmarks, GDPR, HIPAA, and PCI DSS; also supports Azure and GCP
- [DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team) — Cloud attack simulation tool for AWS, GCP, and Azure; granular attack techniques for detection validation in cloud environments

### Azure / Entra ID
- [BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) — BloodHound data collector for Azure and Entra ID; maps attack paths including role assignments, app permissions, and managed identity relationships
- [dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) — Azure AD reconnaissance and attack toolkit; the authoritative open-source toolset for Azure AD security assessment
- [hausec/PowerZure](https://github.com/hausec/PowerZure) — PowerShell framework for Azure security assessment and post-exploitation

### Containers & Kubernetes
- [aquasecurity/trivy](https://github.com/aquasecurity/trivy) — The most widely deployed open-source container vulnerability scanner; image scanning, Kubernetes misconfiguration detection, and IaC analysis in a single tool
- [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Kubernetes Benchmark compliance checker; the standard tool for Kubernetes hardening assessment
- [aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) — Active Kubernetes penetration testing; discovers vulnerabilities and misconfigurations from an attacker perspective
- [falcosecurity/falco](https://github.com/falcosecurity/falco) — Cloud-native runtime security using eBPF/kernel module; detects unexpected process execution, network connections, and file access at container and host level
- [open-policy-agent/opa](https://github.com/open-policy-agent/opa) — Policy-as-code engine; enforces security policies in Kubernetes admission control, API authorization, and IaC pipelines

### eBPF-Based Security
- [cilium/cilium](https://github.com/cilium/cilium) — eBPF-based Kubernetes networking and security; transparent encryption, network policy enforcement, and runtime visibility at the kernel level
- [cilium/tetragon](https://github.com/cilium/tetragon) — eBPF-based security observability and enforcement; syscall-level runtime security for containers with forensic capability and policy enforcement

### Secret Detection
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — Secret scanning in git repos, S3 buckets, and CI/CD pipelines; essential for finding exposed cloud credentials before attackers do
- [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) — Fast secret scanner for git repositories and pre-commit hooks

---

## Commercial & Enterprise Platforms

Cloud security has the most dynamic commercial tool market of any security discipline. These platforms define the CNAPP (Cloud-Native Application Protection Platform) category and represent the tools you will encounter in cloud security roles.

| Platform | Strength |
|---|---|
| **Wiz** | The fastest-growing cloud security platform with the highest market adoption; agentless scanning across AWS, Azure, GCP, and Kubernetes; Security Graph connects vulnerabilities, misconfigurations, secrets, identities, and network exposure into exploitable attack paths; CNAPP category leader with the broadest cloud coverage of any single platform |
| **Prisma Cloud (Palo Alto Networks)** | Full CNAPP platform covering CSPM, cloud workload protection, container security, and IaC scanning; strongest for organizations wanting a single vendor across cloud workloads; deep integration with Palo Alto's network security portfolio |
| **Orca Security** | Agentless cloud security using SideScanning technology to read cloud workload storage without agents; fast deployment and comprehensive vulnerability, misconfiguration, and secrets coverage; strong ROI for organizations that cannot deploy agents at scale |
| **Lacework** | Cloud security platform with behavioral anomaly detection for cloud workloads and containers; acquired by Fortinet; strong for detecting unusual activity patterns in AWS and GCP environments |
| **Aqua Security** | Container and cloud-native security from development through runtime; Trivy is Aqua's open-source scanner; Aqua Platform adds runtime protection, network policy enforcement, and compliance reporting |
| **Sysdig** | Container and Kubernetes runtime security and compliance built on Falco open-source; strong for organizations wanting the runtime security layer with commercial support and threat intelligence |
| **CrowdStrike Falcon Cloud Security** | Cloud workload protection and CSPM integrated with Falcon EDR; strong for organizations on the Falcon platform wanting unified cloud and endpoint coverage |
| **Microsoft Defender for Cloud** | Native Azure CSPM and workload protection; free basic tier for Azure resources; strong value for Azure-first organizations with Microsoft licensing already in place |
| **Ermetic / Tenable CIEM** | Cloud Infrastructure Entitlement Management specializing in discovering overprivileged identities and unused permissions across AWS, Azure, and GCP |
| **AWS Security Hub** | Native AWS security posture aggregation; consolidates findings from GuardDuty, Inspector, Macie, and third-party integrations into a unified compliance and posture view |

---

## NIST 800-53 Control Alignment

Cloud security maps directly to several [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) control families. Understanding which controls apply and why helps practitioners communicate cloud risk in terms that auditors and compliance programs recognize.

| Control Family | Control ID(s) | Cloud Security Application |
|---|---|---|
| Access Control (AC) | AC-2, AC-3, AC-6, AC-17 | IAM role least privilege, cross-account access policies, cloud console access restrictions, remote access via VPN/bastion |
| Audit and Accountability (AU) | AU-2, AU-3, AU-6, AU-9, AU-12 | CloudTrail / Azure Monitor / Cloud Audit Logs configuration, log integrity, SIEM ingestion of cloud logs, alerting on sensitive API calls |
| Configuration Management (CM) | CM-2, CM-6, CM-7, CM-8 | IaC security scanning (Checkov, Terraform), cloud resource inventory via CSPM, CIS benchmark enforcement, drift detection |
| Identification and Authentication (IA) | IA-2, IA-3, IA-5, IA-8 | MFA enforcement for cloud console, service account credential management, workload identity federation, cross-provider federation |
| System and Communications Protection (SC) | SC-7, SC-8, SC-12, SC-28 | VPC security groups and NACLs, encryption in transit (TLS), cloud KMS key management, encryption at rest for S3/blob/disks |
| Incident Response (IR) | IR-4, IR-5, IR-6, IR-8 | Cloud-native IR playbooks, GuardDuty/Defender for Cloud alert triage, cloud forensic evidence preservation, IR plan covering cloud workloads |
| Risk Assessment (RA) | RA-3, RA-5 | CSPM continuous risk assessment, cloud vulnerability scanning with Inspector/Defender, third-party cloud risk assessments |
| Supply Chain Risk Management (SR) | SR-3, SR-11 | Container image supply chain security, SBOMs for cloud workloads, third-party managed service provider risk |
| Program Management (PM) | PM-9, PM-30 | Cloud security program governance, shared responsibility model documentation, cloud risk in enterprise risk register |
| System and Services Acquisition (SA) | SA-10, SA-11 | Secure SDLC for cloud workloads, IaC security in CI/CD pipelines, container image signing and verification |

---

## ATT&CK Coverage

Cloud attack techniques are catalogued in the [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/) covering AWS, Azure, GCP, Office 365, and SaaS platforms. Understanding these techniques explains why each cloud security control exists.

| Technique | ID | How Cloud Security Addresses It |
|---|---|---|
| Cloud Infrastructure Discovery | [T1580](https://attack.mitre.org/techniques/T1580/) | CSPM continuous inventory; restrict ListBuckets/DescribeInstances via SCPs; monitor for reconnaissance API calls in CloudTrail |
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | WAF in front of public cloud workloads; container image vulnerability scanning; runtime workload protection to detect exploitation |
| Valid Accounts: Cloud Accounts | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | MFA enforcement, anomalous login detection via GuardDuty/Defender, just-in-time privileged access, short-lived credentials via STS |
| Steal Application Access Token | [T1528](https://attack.mitre.org/techniques/T1528/) | Token expiry enforcement, SSRF protection to block metadata API abuse, workload identity federation replacing long-lived keys |
| Unsecured Credentials: Cloud Instance Metadata API | [T1552.005](https://attack.mitre.org/techniques/T1552/005/) | IMDSv2 enforcement (AWS), SSRF-blocking WAF rules, network controls restricting metadata API access from container workloads |
| Modify Cloud Compute Infrastructure | [T1578](https://attack.mitre.org/techniques/T1578/) | CloudTrail alerting on compute modification events, SCPs restricting region/service usage, change management integration |
| Exfiltration to Cloud Storage | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | S3/blob DLP controls, bucket policies blocking public access, network egress monitoring for large S3 transfers |
| Resource Hijacking | [T1496](https://attack.mitre.org/techniques/T1496/) | Cost anomaly detection, GuardDuty CryptoCurrency findings, budget alerts for unexpected compute/GPU spin-up |
| Account Manipulation: Additional Cloud Credentials | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | CloudTrail/Entra ID alerting on new access key creation or role assignment changes; PAM coverage of cloud console access |
| Data from Cloud Storage | [T1530](https://attack.mitre.org/techniques/T1530/) | S3 Block Public Access enforcement, Macie sensitive data discovery, bucket ACL auditing via CSPM, access logging on all storage |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Hacking the Cloud | Nick Frichette | Practical cloud attack techniques and methodology covering AWS and Azure attack paths; the best technical offensive cloud reference |
| Kubernetes Security | Liz Rice & Michael Hausenblas | The definitive Kubernetes security reference; RBAC, network policy, pod security, runtime security, and supply chain security |
| Cloud Security and Privacy | Mather, Kumaraswamy, Latif | Foundational cloud security architecture covering governance, risk, and technical controls across service models |
| Zero Trust Networks | Gilman & Barth | Zero trust architecture principles for cloud networking; essential for understanding modern cloud network security design |

---

## Certifications

- **CCSP** (Certified Cloud Security Professional — ISC2) — The most widely recognized vendor-neutral cloud security certification; covers cloud architecture, data security, platform security, and compliance; valued in governance and architecture roles
- **AWS Certified Security — Specialty** — The premier AWS security certification; covers IAM, encryption, logging, incident response, and infrastructure protection; the most respected cloud vendor certification in the market
- **AZ-500** (Microsoft Azure Security Engineer Associate) — Azure security controls, Entra ID, network security, and security operations; required for Azure security roles
- **CKS** (Certified Kubernetes Security Specialist — CNCF) — Advanced Kubernetes security certification covering cluster hardening, supply chain security, and runtime security; requires CKA as prerequisite; highly respected in cloud-native environments
- **KCSA** (Kubernetes and Cloud Native Security Associate — CNCF) — Entry-level cloud-native security certification covering Kubernetes security fundamentals and supply chain security
- **Google Professional Cloud Security Engineer** — GCP security covering IAM, encryption, and compliance; valuable for Google Cloud-focused practitioners

---

## Channels

- [Wiz](https://www.youtube.com/@WizIO) — Cloud security research, attack path demonstrations, and cloud misconfiguration walkthroughs from the CNAPP category leader
- [Cloud Security Podcast](https://www.youtube.com/@CloudSecurityPodcast) — Weekly discussions of cloud security news, architecture decisions, and practitioner perspectives
- [AWS Security](https://www.youtube.com/@AWSEventsChannel) — re:Inforce and re:Invent security talks covering AWS security services and architecture
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Cloud attack techniques and cloud IR from the practitioner perspective
- [CNCF](https://www.youtube.com/@cncf) — KubeCon cloud-native security talks and CNCF security project updates

---

## Who to Follow

- [@wiz_io](https://x.com/wiz_io) — Cloud security research and CNAPP platform updates from the market leader
- [@DirkjanM](https://x.com/DirkjanM) — Dirk-jan Mollema; Azure/Entra ID attack research; ROADtools author; the most prolific public Azure offensive researcher
- [@kmcquade3](https://x.com/kmcquade3) — Kinnaird McQuade; cloud security, AWS IAM privilege escalation, and cloudsplaining
- [@SpenGietz](https://x.com/SpenGietz) — AWS pentesting, Pacu framework, and cloud attack techniques from Rhino Security Labs
- [@christophetd](https://x.com/christophetd) — CloudGoat and Stratus Red Team author; cloud attack simulation methodology
- [@lizrice](https://x.com/lizrice) — Liz Rice; Cilium/eBPF and Kubernetes security; Container Security book author
- [@kelseyhightower](https://x.com/kelseyhightower) — Cloud-native infrastructure and Kubernetes; foundational thinking on cloud-native architecture
- [@toniblyx](https://x.com/toniblyx) — Toni de la Fuente; Prowler author and AWS security assessment methodology
- [@PrismaCloud](https://x.com/PrismaCloud) — Cloud security research and CNAPP news from Palo Alto Prisma Cloud team

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Cloud technique clusters in the ATT&CK Enterprise matrix; visualization of detection and compliance coverage for cloud-specific TTPs; pivot from cloud attack techniques to relevant threat groups
- [Flaws.cloud](http://flaws.cloud) — The single best starting point for hands-on cloud security learning; complete every level before any certification
- [Wiz Research Blog](https://www.wiz.io/blog/tag/research) — The most prolific publisher of cloud vulnerability research; ChaosDB, OMIGOD, and BrokenSesame were all Wiz Research discoveries
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/) — Adversary behavior framework covering AWS, Azure, GCP, Office 365, and SaaS attack techniques
- [CIS Cloud Benchmarks](https://www.cisecurity.org/cis-benchmarks) — Free hardening baselines for AWS, Azure, GCP, and Kubernetes; the compliance standard most cloud security programs anchor to
- [AWS Customer Security Incidents](https://github.com/ramimac/aws-customer-security-incidents) — Curated public record of real AWS security incidents; learning from actual breaches is the best way to understand real cloud attack patterns
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf) — Authoritative cloud-native security architecture reference from the CNCF Security Technical Advisory Group

---

---

## Cloud Attack Techniques (AWS)

### IAM Attacks

- Privilege escalation via policy attachment: `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, `iam:PassRole` + Lambda/EC2 abuse
- Role assumption chain: `sts:AssumeRole` to hop across accounts
- Key exposure: Leaked access keys in GitHub (`truffleHog`, `gitleaks` for detection), pastebin monitoring
- Credential exfiltration from EC2: IMDSv1 SSRF (`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name`)

### Compute and Storage

- EC2 snapshot exfiltration: Share snapshot with attacker account → restore in attacker VPC
- S3 misconfiguration: Public buckets, overly permissive bucket policies, ACL `public-read`
- Lambda abuse: Overprivileged execution role, environment variable secrets, zip poisoning
- ECS/EKS: Container escape to host, IMDS access from pod, overprivileged service accounts

### Detection and Defense (AWS)

- CloudTrail: Enable in all regions, log to S3 with Object Lock, alert on `ConsoleLogin` from unknown IP, `StopLogging`, `DeleteTrail`
- GuardDuty: Enable in all accounts/regions, findings for crypto mining, credential exfiltration, port scanning from EC2
- AWS Config: Continuous compliance checking, config rules for S3 public access, root MFA, CloudTrail enabled
- Security Hub: Aggregates GuardDuty + Config + Inspector + Macie findings
- AWS IAM Access Analyzer: Identify externally accessible resources (cross-account trust, public S3)

---

## Cloud Attack Techniques (Azure)

### Entra ID / Azure AD Attacks

- Password spray: `o365spray --spray -U users.txt -P passwords.txt --domain target.com`
- Legacy authentication: IMAP/POP3/SMTP bypass MFA — block with Conditional Access
- Consent phishing: OAuth app requests read access to email/files, user grants it
- Service principal abuse: Over-privileged managed identities, client secret exfiltration
- PRT (Primary Refresh Token) theft: Pass-the-PRT for SSO bypass

### Azure Resource Manager

- VM extensions: Abuse CustomScriptExtension to run code on VMs
- Runbook abuse: Automation accounts with contributor+ rights
- Key Vault: List/read secrets if access policies misconfigured

### Detection and Defense (Azure)

- Microsoft Defender for Cloud: Secure score, attack path analysis, workload protections
- Entra ID sign-in logs: Alert on impossible travel, legacy auth, MFA failures
- Conditional Access: Require compliant device + MFA for all users, block legacy auth
- PIM (Privileged Identity Management): Just-in-time privileged access, approval workflows

---

## Cloud Attack Techniques (GCP)

- Service account key abuse: Downloaded JSON keys persist indefinitely
- Workload Identity Federation: Misconfigured allows any external identity to assume GCP role
- GCS bucket misconfiguration: `allUsers` or `allAuthenticatedUsers` ACLs
- Cloud Functions: Overprivileged service accounts, env var secrets

---

## Common Cloud Misconfigurations (All Platforms)

| Misconfiguration | Platform | Severity | Remediation |
|---|---|---|---|
| Public S3/GCS/Azure Blob | All | High | Enable public access blocks, review bucket ACLs |
| Root/Owner account used for daily ops | All | Critical | Create IAM users/service accounts with least privilege |
| No MFA on privileged accounts | All | Critical | Enforce MFA via policy/conditional access |
| Overpermissive IAM roles | All | High | Implement least privilege, use access analyzer |
| CloudTrail/audit logging disabled | All | High | Enable in all regions with tamper-proof storage |
| IMDSv1 enabled | AWS | High | Enforce IMDSv2 with `http-tokens: required` |
| Public AMI/snapshot sharing | AWS | Medium | Review snapshot permissions, encrypt EBS |
| Legacy authentication enabled | Azure | High | Block via Conditional Access policy |

---

## Cloud Security Tooling

| Tool | Type | Use Case |
|---|---|---|
| ScoutSuite | OSS | Multi-cloud security auditing (AWS/Azure/GCP) |
| Prowler | OSS | AWS/Azure/GCP CIS benchmark assessment (3,000+ checks) |
| Pacu | OSS | AWS exploitation framework (post-compromise) |
| CloudMapper | OSS | AWS network visualization and attack surface analysis |
| ROADtools | OSS | Azure AD enumeration and dumping |
| AzureHound | OSS | BloodHound data collector for Azure |
| Stratus Red Team | OSS | Cloud TTPs simulator (Atomic Red Team for cloud) |
| Cartography | OSS | Graph-based cloud asset relationships |
| Cloudsploit | OSS | Cloud misconfiguration scanning |

---

## Related Disciplines

- [identity-access-management.md](identity-access-management.md) — Cloud security and IAM are inseparable: misconfigured IAM roles and overprivileged identities are the leading root cause of cloud breaches; CIEM, entitlement analysis, and cloud-specific OAuth patterns are shared territory
- [detection-engineering.md](detection-engineering.md) — Cloud attack detection requires purpose-built rules for CloudTrail, Azure Monitor, and GCP Audit Logs; cloud-native SIEM integrations and detection content for ATT&CK cloud techniques are built by detection engineers
- [devsecops.md](devsecops.md) — IaC security scanning, container image signing, Kubernetes admission control, and supply chain security live at the intersection of cloud security and DevSecOps; shift-left cloud security is largely a DevSecOps responsibility
- [threat-intelligence.md](threat-intelligence.md) — Cloud-targeted threat actors require CTI-informed defensive posture; threat intelligence feeds directly into which cloud misconfigurations to prioritize and which attack paths to harden
- [incident-response.md](incident-response.md) — Cloud IR requires cloud-specific forensic techniques: CloudTrail forensics, S3 access log analysis, container forensics, and workload memory acquisition in ephemeral environments differ significantly from traditional IR
- [governance-risk-compliance.md](governance-risk-compliance.md) — Cloud compliance programs (FedRAMP, SOC 2, ISO 27001 in cloud environments) require CSPM evidence, IaC policy-as-code, and cloud-specific control implementation guidance
