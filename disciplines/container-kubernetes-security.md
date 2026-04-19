# Container & Kubernetes Security

Container and Kubernetes security encompasses the practices, tools, and controls required to secure containerized workloads throughout their full lifecycle — from image build through registry storage, deployment, and runtime execution. The discipline has matured rapidly alongside the adoption of Kubernetes as the dominant container orchestration platform, and it now covers a distinct and deep attack surface: vulnerable base images, misconfigured orchestration layers, container runtime escapes, insecure pod configurations, secrets embedded in manifests, and supply chain risks in public container registries.

The fundamental challenge of container security is that containers share a kernel with the host. An improperly configured container running as root with unnecessary Linux capabilities is not an isolated workload — it is a privilege escalation path to the underlying node and, from there, to the rest of the cluster. Kubernetes amplifies this: a single misconfigured RBAC binding, an exposed API server, or an unencrypted etcd store can compromise an entire production environment. Container and Kubernetes security is the discipline of systematically reducing this attack surface at every layer of the stack.

---

## Where to Start

Begin with the fundamentals of how containers actually work — namespaces, cgroups, and the Linux capabilities model — before studying Kubernetes security. Understanding why `--privileged` containers are dangerous, what `CAP_NET_ADMIN` actually grants, and how the container runtime mediates host access makes every other Kubernetes security concept more concrete. The CKA certification provides the necessary Kubernetes operations foundation before pursuing the CKS.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Container fundamentals (namespaces, cgroups, capabilities), image scanning basics, Dockerfile best practices, Kubernetes architecture and RBAC basics, pod security standards | Docker security documentation, kube-bench CIS benchmark runs, Trivy image scanning quickstart, CNCF Kubernetes Security Whitepaper |
| Practitioner | Kubernetes RBAC hardening, network policies, admission controllers (OPA Gatekeeper, Kyverno), image signing with Cosign, Falco runtime detection, secrets management with Vault | KubeCon security talks (free on YouTube), NSA/CISA Kubernetes Hardening Guide, CKA certification, killer.sh CKS practice environment |
| Advanced | eBPF-based runtime security (Tetragon), service mesh mTLS (Istio), SLSA for container builds, container escape research, multi-tenant cluster hardening, supply chain attestation | CKS certification, CNCF Security Technical Advisory Group papers, Liz Rice "Container Security" (O'Reilly), eBPF Summit talks |

---

## Free Training

- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) — The authoritative US government hardening reference for Kubernetes; covers pod security, network policies, authentication, logging, and threat detection; free and kept current; the first document to read before hardening any cluster
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf) — Comprehensive cloud-native security architecture guidance from the CNCF Security Technical Advisory Group; covers the full lifecycle from development through runtime; authoritative and vendor-neutral
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — Free hardening baseline covering API server, etcd, kubelet, scheduler, and worker node configuration; the compliance standard most enterprise Kubernetes programs anchor to; run kube-bench to audit against it
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) — Official Kubernetes security docs covering RBAC, network policies, pod security standards, secrets encryption, and admission control; required reading for the CKS exam
- [KubeCon Security Talks (CNCF YouTube)](https://www.youtube.com/@cncf) — Free recordings from every KubeCon conference covering container escape research, supply chain security, eBPF security, and Kubernetes hardening; the highest-signal free content in the discipline
- [Falco Documentation and Labs](https://falco.org/docs/) — Free getting-started labs for deploying Falco, writing detection rules, and integrating with SIEM; the best way to understand container runtime threat detection hands-on
- [Aqua Cloud Native Academy](https://www.aquasec.com/cloud-native-academy/) — Free cloud-native security learning content covering container security, Kubernetes hardening, and supply chain security; practitioner-level and consistently updated
- [Killer.sh CKS Preview](https://killer.sh) — Free preview scenarios for the CKS exam environment; the most realistic preparation available for the Certified Kubernetes Security Specialist exam

---

## Tools & Repositories

### Image Scanning
- [aquasecurity/trivy](https://github.com/aquasecurity/trivy) — The most widely deployed open-source container vulnerability scanner; image scanning, Kubernetes misconfiguration detection, SBOM generation, and secrets detection in a single tool; the de facto standard for CI/CD pipeline scanning
- [anchore/grype](https://github.com/anchore/grype) — Fast vulnerability scanner for container images and filesystems using the Anchore vulnerability database; pairs with Syft for SBOM-based scanning workflows
- [quay/clair](https://github.com/quay/clair) — Open-source container vulnerability analysis from Red Hat; designed for integration with container registries to scan images at push time
- [docker/scout-cli](https://github.com/docker/scout-cli) — Docker's official image analysis CLI; vulnerability scanning, base image recommendations, and supply chain policy checks integrated into Docker Desktop and Docker Hub

### Runtime Security
- [falcosecurity/falco](https://github.com/falcosecurity/falco) — The CNCF standard for container and Kubernetes runtime security; uses eBPF or kernel module to detect unexpected process execution, network connections, file access, and syscall anomalies at container and host level; the most deployed open-source runtime security tool
- [cilium/tetragon](https://github.com/cilium/tetragon) — eBPF-based security observability and enforcement from the Cilium project; syscall-level runtime security with policy enforcement and forensic-grade event capture; lower overhead than Falco for high-throughput workloads
- [google/gvisor](https://github.com/google/gvisor) — Application kernel written in Go that provides a sandboxed container runtime; intercepts container syscalls with a user-space kernel to reduce the host kernel attack surface
- [kata-containers/kata-containers](https://github.com/kata-containers/kata-containers) — Lightweight virtual machines that behave like containers; hardware virtualization boundary between container workloads and the host kernel; the strongest container isolation available

### Policy Enforcement & Admission Control
- [open-policy-agent/gatekeeper](https://github.com/open-policy-agent/gatekeeper) — Kubernetes admission controller using OPA (Open Policy Agent) for policy-as-code enforcement; blocks non-compliant workloads at admission time; the most widely deployed Kubernetes policy engine
- [kyverno/kyverno](https://github.com/kyverno/kyverno) — Kubernetes-native policy engine using YAML-based policies without requiring Rego; validates, mutates, and generates resources at admission time; lower learning curve than OPA Gatekeeper
- [kubewarden/kubewarden-controller](https://github.com/kubewarden/kubewarden-controller) — WebAssembly-based Kubernetes admission controller; policies compiled to Wasm modules for performance and language flexibility

### Image Signing & Supply Chain
- [sigstore/cosign](https://github.com/sigstore/cosign) — The Sigstore tool for signing and verifying container images and other OCI artifacts; keyless OIDC-based signing using Fulcio and Rekor; the emerging standard for container image integrity
- [notaryproject/notation](https://github.com/notaryproject/notation) — Notary v2 CLI for signing and verifying OCI artifacts; CNCF project with broad registry and toolchain support; alternative to Cosign for enterprise signing workflows

### Networking
- [cilium/cilium](https://github.com/cilium/cilium) — eBPF-based Kubernetes networking and security; transparent encryption, network policy enforcement at the kernel level, and deep visibility into pod-to-pod traffic; the most capable open-source CNI for security-conscious deployments
- [projectcalico/calico](https://github.com/projectcalico/calico) — The most widely deployed Kubernetes CNI for NetworkPolicy enforcement; global network policies, egress controls, and Kubernetes NetworkPolicy compatibility
- [istio/istio](https://github.com/istio/istio) — The most deployed service mesh; mutual TLS between all pods, L7 traffic policy, and authorization policies; eliminates unencrypted east-west traffic in Kubernetes clusters

### Secrets Management
- [hashicorp/vault](https://github.com/hashicorp/vault) — The standard open-source secrets management platform; dynamic secrets, PKI, Kubernetes auth integration, and encryption as a service; removes the need to store static secrets in Kubernetes Secrets objects
- [external-secrets/external-secrets](https://github.com/external-secrets/external-secrets) — Kubernetes operator that syncs secrets from external providers (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) into Kubernetes Secrets; decouples secrets from cluster state
- [bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) — Encrypts Kubernetes Secrets for safe storage in version control; the SealedSecret CRD is decrypted only by the in-cluster controller; practical GitOps-compatible secrets solution

### Kubernetes Security Assessment
- [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Kubernetes Benchmark compliance checker; audits API server, etcd, kubelet, and scheduler configuration against CIS controls; the standard tool for Kubernetes hardening assessment
- [aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) — Active Kubernetes penetration testing; discovers vulnerabilities and misconfigurations from an attacker perspective including API server exposure and RBAC weaknesses
- [cyberark/KubiScan](https://github.com/cyberark/KubiScan) — Scans Kubernetes clusters for risky RBAC permissions and overprivileged roles; identifies which service accounts can escalate privileges or access sensitive resources
- [Shopify/kubeaudit](https://github.com/Shopify/kubeaudit) — Audits Kubernetes clusters and manifests against security best practices; checks for privileged containers, missing network policies, and insecure capabilities
- [corneliusweig/rakkess](https://github.com/corneliusweig/rakkess) — Displays the RBAC access matrix for Kubernetes resources; shows exactly which permissions every subject has across all API groups; essential for RBAC audit
- [alcideio/rbac-tool](https://github.com/alcideio/rbac-tool) — RBAC visualization and policy generation for Kubernetes; generates network policies and summarizes permissions across subjects and resources

---

## Commercial & Enterprise Platforms

| Platform | Strength |
|---|---|
| **Prisma Cloud (Palo Alto Networks)** | Full CNAPP coverage from image scanning through runtime; Kubernetes admission control, CI/CD pipeline scanning, and compliance reporting; deepest container security feature set among legacy security vendors |
| **Wiz** | Agentless container and Kubernetes security with Security Graph connecting image vulnerabilities, Kubernetes misconfigs, network exposure, and identity risk into exploitable attack paths; fastest deployment with broadest cloud provider coverage |
| **Aqua Security** | The container-native security specialist; Aqua Platform adds enterprise runtime protection, network policy enforcement, image assurance policies, and compliance reporting built on the Trivy open-source engine |
| **Sysdig Secure** | Container and Kubernetes runtime security and compliance built on Falco; commercial threat intelligence, managed Falco rules, and compliance dashboards; the commercial offering for organizations wanting enterprise Falco support |
| **Lacework** | Behavioral anomaly detection for container workloads; unsupervised ML identifies deviations from normal container behavior without requiring rule authoring; acquired by Fortinet |
| **Snyk Container** | Developer-first container image scanning with base image recommendations and auto-remediation PRs; strong IDE and CI/CD integration for shift-left container security |
| **NeuVector (SUSE)** | Open-source and enterprise container security platform with zero-trust network segmentation, deep packet inspection, and runtime vulnerability patching; the most capable open-core option for on-premises deployments |

---

## NIST 800-53 Control Alignment

| Control | ID | Container & Kubernetes Relevance |
|---|---|---|
| Least Functionality | CM-7 | Non-root containers, read-only root filesystems, dropped Linux capabilities, and minimal base images directly implement least functionality for container workloads |
| Configuration Settings | CM-6 | Pod Security Standards (restricted/baseline/privileged), admission controller policies, and Kubernetes API server hardening settings operationalize configuration management |
| Security Function Isolation | SC-3 | Namespace isolation, gVisor and Kata Containers sandboxing, and seccomp/AppArmor profiles provide security function isolation between container workloads |
| Process Isolation | SC-39 | Linux namespaces (PID, mount, network, user) provide process isolation between containers; gVisor adds a second isolation boundary via a user-space kernel |
| Access Enforcement | AC-3 | Kubernetes RBAC enforces access control for API server operations; NetworkPolicy enforces network access control; OPA Gatekeeper enforces admission-time policy |
| Malware Protection | SI-3 | Falco and Tetragon runtime detection identify malicious process execution, unexpected network connections, and file system tampering in container workloads |
| Vulnerability Scanning | RA-5 | Trivy, Grype, and Clair scan container images for known CVEs at build time and registry push time; continuous scanning catches new CVEs in deployed images |
| Developer Configuration Management | SA-10 | Image signing with Cosign and Notary v2, SLSA build provenance, and immutable container registries implement supply chain integrity controls |

---

## ATT&CK Coverage

| Technique | ID | Container Security Control |
|---|---|---|
| Deploy Container | T1610 | Admission controllers (OPA Gatekeeper, Kyverno) enforce image allowlists, registry policies, and deployment constraints; only signed and scanned images from approved registries reach production |
| Escape to Host | T1611 | Pod Security Standards (restricted profile), seccomp profiles, AppArmor, dropped capabilities, non-root enforcement, and gVisor/Kata sandboxing reduce container escape risk |
| Container and Resource Discovery | T1613 | RBAC least privilege limits which service accounts can enumerate pods, services, and config maps; NetworkPolicy restricts lateral movement for recon within the cluster |
| Credentials in Container | T1552.007 | Secrets management (Vault, External Secrets Operator) eliminates static credentials in environment variables and Kubernetes Secrets; image scanning detects hardcoded secrets in layers |
| Disable Security Tools | T1562.001 | Falco and Tetragon runtime detection alert on attempts to kill monitoring agents or modify audit configurations; immutable container filesystems prevent tampering |
| Resource Hijacking | T1496 | Runtime anomaly detection identifies cryptomining workloads via unexpected CPU spikes, network connections to mining pools, and execution of known mining binaries |
| Modify Cloud Compute Infrastructure | T1578 | RBAC controls restrict which identities can modify cluster infrastructure; admission controllers prevent deployment of privileged workloads that could affect node configuration |
| Exploit Public-Facing Application | T1190 | Image vulnerability scanning prevents deployment of images with known exploitable CVEs; Kubernetes API server hardening (authentication, authorization, audit logging) protects the control plane |

---

## Certifications

- **CKS** (Certified Kubernetes Security Specialist — CNCF) — The premier Kubernetes security certification; covers cluster hardening, system hardening, minimizing microservice vulnerabilities, supply chain security, monitoring, and runtime security; requires CKA as prerequisite; the most respected credential for Kubernetes security practitioners
- **CKA** (Certified Kubernetes Administrator — CNCF) — The required prerequisite for CKS; validates deep Kubernetes operations knowledge including networking, storage, scheduling, and troubleshooting; foundational for any Kubernetes security role
- **CKAD** (Certified Kubernetes Application Developer — CNCF) — Validates container and Kubernetes application development skills; useful context for security practitioners who need to understand what developers are deploying and why
- **AWS Certified Security — Specialty** — Covers EKS security including IAM roles for service accounts, ECR image scanning, and EKS cluster hardening; the relevant vendor certification for AWS-hosted Kubernetes workloads
- **OSCP** (Offensive Security Certified Professional) — Container escape and Kubernetes privilege escalation techniques appear in modern OSCP exam environments; offensive knowledge directly informs defensive container security controls

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) | Free guide | Authoritative US government Kubernetes hardening reference |
| [CNCF Security Whitepaper v2](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf) | Free paper | Cloud-native security architecture lifecycle reference |
| [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) | Free benchmark | Hardening baseline; run with kube-bench for CIS compliance |
| [Container Security (Liz Rice, O'Reilly)](https://www.oreilly.com/library/view/container-security/9781492056690/) | Book | The definitive container security reference; namespaces, capabilities, seccomp, and runtime security |
| [Kubernetes Security Best Practices (Liz Rice)](https://www.oreilly.com/library/view/kubernetes-security/9781492039075/) | Book | RBAC, network policies, admission control, and secrets management |
| [KubeCon Security Talks](https://www.youtube.com/@cncf) | Free video | Annual KubeCon talks covering container escapes, supply chain, and eBPF security |
| [Killer.sh CKS Practice](https://killer.sh) | Lab environment | The most realistic CKS exam simulator; scenario-based Kubernetes security labs |
| [Falco Documentation](https://falco.org/docs/) | Reference | CNCF runtime security engine; rule writing and deployment guides |

---

## Related Disciplines

- [Cloud Security](cloud-security.md) — Container and Kubernetes security is a specialization within the broader cloud security discipline; EKS, GKE, and AKS add cloud IAM and managed control plane attack surfaces
- [DevSecOps](devsecops.md) — Image scanning, admission control, and signing belong in CI/CD pipelines; container security is inseparable from DevSecOps pipeline design
- [Supply Chain Security](supply-chain-security.md) — Container image signing, SLSA build provenance, and registry security are core supply chain security concerns
- [Network Security](network-security.md) — Kubernetes NetworkPolicy and service mesh mTLS are the network security layer for containerized workloads
- [Vulnerability Management](vulnerability-management.md) — Container image CVE scanning and base image remediation are a primary vulnerability management workflow in container-heavy environments
