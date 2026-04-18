# Cloud Security

Cloud security encompasses the practices, tools, and governance required to secure infrastructure, workloads, data, and identities in cloud environments — primarily AWS, Azure, and Google Cloud Platform, along with the Kubernetes and container ecosystems that run on top of them. The discipline has evolved from traditional security lifted to the cloud into something fundamentally different: infrastructure is ephemeral, identity and access management is the primary attack vector, configuration drift is constant, and the blast radius of a single overprivileged role can be an entire organization. Cloud-native architectures — serverless functions, managed Kubernetes, shared IAM hierarchies — introduce attack surfaces that have no analog in traditional on-premises security.

The shared responsibility model is the foundational concept every cloud security practitioner must internalize: the cloud provider secures the infrastructure, but the customer owns the configuration, identity management, data protection, and workload security. The vast majority of cloud security incidents are not the result of cloud provider failures — they are the result of misconfigured S3 buckets, overprivileged IAM roles, exposed secrets in environment variables, and SSRF vulnerabilities that reach cloud metadata APIs. These are customer-owned failure modes, and cloud security is the discipline of systematically finding and eliminating them.

---

## Where to Start

Earn AWS Solutions Architect Associate (or its Azure/GCP equivalent) before focusing on security. The security knowledge is useless without understanding how cloud infrastructure is actually built. Once you have that foundation, flaws.cloud is the single best entry point into cloud security practice — complete every level before spending money on any certification or course.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Shared responsibility model, cloud IAM fundamentals, S3/blob storage security, VPC/network segmentation, CloudTrail/cloud logging | AWS Cloud Practitioner (free training), flaws.cloud lab (free), BHIS cloud security webcasts |
| Practitioner | Cloud pentesting (IAM privesc, SSRF to metadata, S3 enumeration), cloud-native logging and detection, container security, Kubernetes hardening | flaws.cloud + flaws2.cloud, CloudGoat (Rhino Security), HTB Academy Cloud path, Wiz Academy (free) |
| Advanced | Multi-cloud CSPM, cloud IR and forensics, zero trust architecture, eBPF-based runtime security, CNAPP concepts, cloud attack simulation | SANS SEC541/SEC588, Wiz Research blog, Stratus Red Team, CNCF security papers |

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
