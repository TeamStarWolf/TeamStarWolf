# Cloud Security

Securing cloud infrastructure, workloads, containers, and identities across AWS, Azure, GCP, and Kubernetes environments.

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
| Hacking the Cloud (online) | Various | [hackingthe.cloud](https://hackingthe.cloud) — Free, updated constantly with real attack techniques |
| AWS Security Handbook | Marzia Kjell | Practical AWS security from misconfiguration to exploitation |

## Certifications

- **CCSP** (Certified Cloud Security Professional) — Broad cloud security architecture and governance
- **AWS Security Specialty** — AWS-specific security services, detection, and response
- **Azure Security Engineer (AZ-500)** — Azure security controls and identity management
- **KCSA** (Kubernetes and Cloud Native Security Associate) — Kubernetes security fundamentals
- **CKS** (Certified Kubernetes Security Specialist) — Advanced Kubernetes cluster hardening

## Channels

- [fwd:cloudsec](https://www.youtube.com/@fwdcloudsec) — Cloud security conference recordings
- [Cloud Security Podcast](https://www.youtube.com/@CloudSecurityPodcast) — Practitioner interviews across AWS, Azure, and GCP
- [Day Cyberwox](https://www.youtube.com/@DayCyberwox) — AWS, Azure, GCP security walkthroughs
- [A Cloud Guru](https://www.youtube.com/@acloudguru) — Cloud certification preparation including security specialty paths
- [HashiCorp](https://www.youtube.com/@HashiCorp) — Vault, Boundary, and infrastructure security tooling

## Who to Follow

- [@scott_piper](https://x.com/scott_piper) — Summit Route; AWS security research and misconfig tracking
- [@ToniBlyx](https://x.com/ToniBlyx) — Toni de la Fuente; Prowler creator and AWS security expertise
- [@Frichette_n](https://x.com/Frichette_n) — Nick Frichette; AWS offensive security and credential abuse research
- [@shehackspurple](https://x.com/shehackspurple) — Tanya Janca; DevSecOps, AppSec, and cloud security
- [@clintgibler](https://x.com/clintgibler) — Clint Gibler; tl;dr sec newsletter covering cloud and AppSec
- [@RobertMLee](https://x.com/RobertMLee) — Robert M. Lee; Dragos ICS/OT and cloud-adjacent infrastructure security

## Key Resources

- [HackingThe.Cloud](https://hackingthe.cloud) — Cloud attack techniques, misconfigurations, and exploitation methods
- [CloudSecDocs](https://cloudsecdocs.com) — Cloud security documentation and reference
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html) — AWS prescriptive security guidance
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — Hardening benchmarks for AWS, Azure, GCP, and Kubernetes
- [CNCF Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf) — Cloud native security model

---

*Part of the [TeamStarWolf](https://github.com/TeamStarWolf) community resource library.*
