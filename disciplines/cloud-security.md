# Cloud Security

Securing cloud infrastructure, workloads, containers, and identities across AWS, Azure, GCP, and Kubernetes environments.

---

## Where to Start

Cloud security requires understanding both how cloud platforms work and how they are attacked. Start with a single provider — AWS is the most common, Azure is dominant in enterprise — and learn the identity model first: IAM permissions, roles, and trust relationships are the most exploited attack surface in cloud environments. Then layer in infrastructure assessment with tools like Prowler. Kubernetes security builds on container fundamentals; understand how pods, namespaces, and RBAC interact before you can defend them effectively. Use Hack The Box, TryHackMe, or flaws.cloud to practice against real misconfigured cloud environments.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Cloud IAM models, shared responsibility, basic misconfiguration patterns | AWS free tier labs, TryHackMe cloud paths, CISA free training |
| Practitioner | Prowler/ScoutSuite assessments, Kubernetes security, IaC scanning, Trivy | HTB Academy cloud path, BHIS webcasts, flaws.cloud |
| Advanced | Cloud attack paths (Pacu, ROADtools), eBPF runtime security, policy-as-code | CCSP, AWS Security Specialty, AZ-500, CKS |

---

## Free Training

- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts on cloud attack techniques, AWS/Azure misconfigurations, and Kubernetes security
- [BHIS YouTube](https://www.youtube.com/@BlackHillsInformationSecurity) — Cloud security attack walkthroughs, container security, and DevSecOps content
- [TCM Security YouTube](https://www.youtube.com/@TCMSecurityAcademy) — Cloud security and AWS pentesting content
- [Hack The Box Academy](https://academy.hackthebox.com) — Free Student tier; cloud security and container security modules
- [TryHackMe](https://tryhackme.com) — Cloud security learning paths for AWS and Azure
- [flaws.cloud](http://flaws.cloud) — Free AWS misconfiguration challenge course by Scott Piper; learn by exploiting real misconfigs
- [flaws2.cloud](http://flaws2.cloud) — Follow-on challenge with both attacker and defender perspectives
- [Kubernetes the Hard Way](https://github.com/kelseyhightower/kubernetes-the-hard-way) — Free guide to understanding Kubernetes from the ground up; essential context for securing it
- [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) — Includes cloud security, IaC, and identity management topics
- [AWS Security Documentation](https://docs.aws.amazon.com/security/) — Free; the most authoritative source for AWS security controls and best practices

---

## Tools & Repositories

### Multi-Cloud Assessment
- [prowler](https://github.com/prowler-cloud/prowler) — Cloud security posture assessment across AWS, Azure, and GCP
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — Multi-cloud security auditing tool
- [cloudmapper](https://github.com/duo-labs/cloudmapper) — AWS environment analysis and network visualization
- [checkov](https://github.com/bridgecrewio/checkov) — IaC security scanning for Terraform, CloudFormation, and CDK
- [terrascan](https://github.com/tenable/terrascan) — IaC compliance and security scanning

### AWS
- [pacu](https://github.com/RhinoSecurityLabs/pacu) — AWS exploitation framework for red team operations
- [cloudsploit](https://github.com/aquasecurity/cloudsploit) — AWS, Azure, GCP, and Oracle cloud security scanning
- [aws-inventory](https://github.com/nccgroup/aws-inventory) — Enumerate AWS resources across a large number of services

### Azure & Entra ID
- [AADInternals](https://github.com/Gerenios/AADInternals) — PowerShell toolkit for Azure AD/Entra ID offensive and defensive operations
- [ROADtools](https://github.com/dirkjanm/ROADtools) — Azure AD recon, token abuse, and attack framework
- [AzureADAssessment](https://github.com/AzureAD/AzureADAssessment) — Microsoft Azure AD tenant security assessment
- [AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) — Entra ID attack scenarios paired with detection guidance
- [MicroBurst](https://github.com/NetSPI/MicroBurst) — Azure security assessment PowerShell scripts
- [untitledgoosetool](https://github.com/cisagov/untitledgoosetool) — CISA Azure/M365 incident response toolkit

### Containers & Kubernetes
- [kube-bench](https://github.com/aquasecurity/kube-bench) — Kubernetes CIS Benchmark checks
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) — Kubernetes penetration testing tool
- [trivy](https://github.com/aquasecurity/trivy) — Container, IaC, and cloud vulnerability scanner
- [tracee](https://github.com/aquasecurity/tracee) — Linux runtime security and forensics with eBPF
- [falco](https://github.com/falcosecurity/falco) — Runtime container security threat detection
- [badPods](https://github.com/BishopFox/badPods) — Kubernetes pod abuse scenarios and privilege escalation techniques
- [badrobot](https://github.com/controlplaneio/badrobot) — Kubernetes Operator security auditing
- [ThreatMapper](https://github.com/deepfence/ThreatMapper) — Runtime threat detection across cloud workloads
- [kube-linter](https://github.com/stackrox/kube-linter) — Static analysis for Kubernetes manifests
- [dive](https://github.com/wagoodman/dive) — Inspect Docker image layers for leaked secrets and bloat

### eBPF Security
- [tetragon](https://github.com/cilium/tetragon) — eBPF-based security observability and runtime enforcement
- [cilium](https://github.com/cilium/cilium) — eBPF-based networking, observability, and security
- [KubeArmor](https://github.com/kubearmor/KubeArmor) — Runtime security enforcement for Kubernetes with eBPF

### Policy as Code
- [opa](https://github.com/open-policy-agent/opa) — Open Policy Agent for unified policy enforcement
- [gatekeeper](https://github.com/open-policy-agent/gatekeeper) — Kubernetes admission control with OPA
- [kyverno](https://github.com/kyverno/kyverno) — Kubernetes-native policy engine

### DevSecOps & IaC
- [tfsec](https://github.com/aquasecurity/tfsec) — Terraform security analysis
- [hadolint](https://github.com/hadolint/hadolint) — Dockerfile linter and security checker
- [ggshield](https://github.com/GitGuardian/ggshield) — Secret detection in code and CI/CD pipelines
- [snyk](https://github.com/snyk/cli) — Developer-first vulnerability scanning
- [pre-commit-hooks](https://github.com/pre-commit/pre-commit-hooks) — Git hooks for catching secrets and misconfigs before commit

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Hacking Kubernetes | Rice & Hausenblas | Attack and defense for Kubernetes; the definitive container security book |
| Kubernetes Security and Observability | Liz Rice | Container and K8s security from the author of container security fundamentals |
| CCSP Official Study Guide | Chapple & Seidl | Broad cloud security foundations covering architecture, compliance, and operations |
| Hacking the Cloud (online) | Various | [hackingthe.cloud](https://hackingthe.cloud) — Free, continuously updated with real attack techniques and mitigations |
| AWS Security Handbook | Marzia Kjell | Practical AWS security from misconfiguration to exploitation |

---

## Certifications

- **CCSP** (Certified Cloud Security Professional) — Broad cloud security architecture and governance; the leading vendor-neutral cloud security certification
- **AWS Security Specialty** — AWS-specific security services, detection, and response; the practitioner benchmark for AWS environments
- **Azure Security Engineer (AZ-500)** — Azure security controls and Entra ID management
- **KCSA** (Kubernetes and Cloud Native Security Associate) — Kubernetes security fundamentals; the entry-level cloud native security certification
- **CKS** (Certified Kubernetes Security Specialist) — Advanced Kubernetes cluster hardening; requires passing CKA first

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Cloud attack techniques, AWS/Azure misconfigurations, and cloud-specific adversary simulation
- [fwd:cloudsec](https://www.youtube.com/@fwdcloudsec) — Cloud security conference recordings from the leading practitioner event
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Cloud pentesting and AWS security content
- [SANS Cloud Security](https://www.youtube.com/@SansInstitute) — Cloud security architecture and operations content
- [KubeCon](https://www.youtube.com/@cncf) — CNCF conference recordings including Kubernetes security sessions

---

## Who to Follow

- [@SpenGietz](https://x.com/SpenGietz) — Spencer Gietzen; Rhino Security Labs cloud research
- [@_dirkjan](https://x.com/_dirkjan) — Dirk-jan Mollema; Azure/Entra ID attack research, ROADtools
- [@christophetd](https://x.com/christophetd) — Cloud security research and attack path analysis
- [@kmcquade3](https://x.com/kmcquade3) — Kinnaird McQuade; AWS IAM and cloud policy security
- [@LizRice](https://x.com/lizrice) — Liz Rice; container security and eBPF; Aqua Security
- [@IanColdwater](https://x.com/IanColdwater) — Kubernetes security and container hardening
- [@NigelDouglas10](https://x.com/NigelDouglas10) — Cloud native security and runtime security
- [@sysdig](https://x.com/sysdig) — Container and cloud runtime security research
- [@falcosecurity](https://x.com/falcosecurity) — Falco runtime security project

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Map cloud attack techniques to ATT&CK; correlate with CVE and KEV data; visualize detection gaps across cloud-focused technique clusters
- [Hacking the Cloud](https://hackingthe.cloud) — Free, community-maintained reference for cloud attack techniques with mitigations
- [flaws.cloud](http://flaws.cloud) — Free AWS misconfiguration challenge; learn to find the same issues assessors find
- [CloudSecDocs](https://cloudsecdocs.com) — Free community cloud security reference
- [CISA Cloud Security Resources](https://www.cisa.gov/topics/cyber-threats-and-advisories/cloud-security) — Federal cloud security guidance and best practices
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/) — Free; the AWS security architecture reference
- [NSA Cloud Security Guidance](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2987379/) — NSA guidance on cloud security principles and misconfiguration risks
