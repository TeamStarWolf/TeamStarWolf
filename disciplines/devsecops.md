# DevSecOps

DevSecOps is the practice of integrating security controls, testing, and culture directly into the software development lifecycle and CI/CD pipeline — shifting security left so vulnerabilities are found and fixed at the point of code creation rather than after deployment. Where traditional security was a gate at release time, DevSecOps embeds security into every sprint: developers run static analysis on every commit, pipelines block deployments with critical dependency CVEs, and infrastructure-as-code is scanned before it is provisioned. The discipline matters because modern software ships continuously — weekly or daily releases mean there is no longer time for a separate security review cycle. It is practiced by security engineers embedded in product teams, platform engineers building secure golden paths, and AppSec teams automating controls at scale. Understanding DevSecOps offensively is equally critical: attackers now target CI/CD pipelines, dependency ecosystems, and container registries as primary attack vectors, making pipeline security as important as application security.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Learn the secure SDLC concept, set up a GitHub Actions workflow, and run Semgrep on a personal project. Understand OWASP Top 10 for developers and what SAST vs DAST means. | [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/) |
| Intermediate | Integrate SAST (Semgrep or CodeQL), SCA (Trivy or Grype), and secrets detection (gitleaks) into a CI/CD pipeline. Understand dependency confusion attacks and container image signing. | [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) |
| Advanced | Implement SLSA Level 3 provenance, generate and validate SBOMs, harden CI/CD runners against pipeline poisoning, and build policy-as-code with OPA/Gatekeeper for Kubernetes admission control. | [SLSA Framework Specification](https://slsa.dev/spec/v1.0/) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| OWASP DevSecOps Guideline | https://owasp.org/www-project-devsecops-guideline/ | Comprehensive reference for embedding security in SDLC phases |
| GitHub Actions Security Hardening | https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions | Securing CI/CD pipelines, permissions, secrets management |
| Google SRE Book | https://sre.google/sre-book/table-of-contents/ | Reliability and security engineering at scale |
| SLSA Framework | https://slsa.dev/ | Supply chain security levels, provenance, and build integrity |
| Semgrep Learn | https://semgrep.dev/learn | Writing SAST rules, understanding pattern matching for security |
| Secure Code Warrior | https://www.securecodewarrior.com/ | Developer-focused secure coding training by language |
| CISA Secure by Design | https://www.cisa.gov/securebydesign | Federal guidance on shifting security left in product development |

---

## Tools & Repositories

### Static Application Security Testing (SAST)

| Tool | Language Support | Repository |
|---|---|---|
| Semgrep | 30+ languages; rule-based pattern matching | https://github.com/semgrep/semgrep |
| CodeQL | Deep semantic analysis; GitHub Actions native | https://github.com/github/codeql |
| SonarQube Community | Java, Python, JS, C#, and more | https://github.com/SonarSource/sonarqube |
| Bandit | Python-specific SAST | https://github.com/PyCQA/bandit |
| Bearer | Privacy-focused SAST detecting sensitive data flows | https://github.com/Bearer/bearer |

### Dynamic Application Security Testing (DAST)

| Tool | Purpose | Repository |
|---|---|---|
| OWASP ZAP | Automated web scanner with CI/CD integration | https://github.com/zaproxy/zaproxy |
| Nikto | Web server misconfiguration and vulnerability scanner | https://github.com/sullo/nikto |
| nuclei | Template-based scanner with CI/CD mode | https://github.com/projectdiscovery/nuclei |

### Software Composition Analysis (SCA)

| Tool | Purpose | Repository |
|---|---|---|
| OWASP Dependency-Check | Identifies CVEs in project dependencies | https://github.com/jeremylong/DependencyCheck |
| Trivy | Multi-target scanner: containers, filesystems, IaC, SBOMs | https://github.com/aquasecurity/trivy |
| Grype | Fast vulnerability scanner for container images and filesystems | https://github.com/anchore/grype |
| Syft | SBOM generation for containers and filesystems (CycloneDX, SPDX) | https://github.com/anchore/syft |

### Secrets Detection

| Tool | Purpose | Repository |
|---|---|---|
| gitleaks | Detect secrets and credentials in git history and staged changes | https://github.com/gitleaks/gitleaks |
| truffleHog | Deep git history scan for high-entropy and regex-matched secrets | https://github.com/trufflesecurity/trufflehog |
| detect-secrets | Yelp's auditing framework for preventing secrets in code | https://github.com/Yelp/detect-secrets |

### Infrastructure-as-Code (IaC) Scanning

| Tool | Purpose | Repository |
|---|---|---|
| Checkov | Terraform, CloudFormation, Kubernetes, ARM, Bicep policy scanning | https://github.com/bridgecrewio/checkov |
| tfsec | Terraform-focused static analysis security scanner | https://github.com/aquasecurity/tfsec |
| KICS | Multi-platform IaC security scanning (Terraform, Docker, k8s) | https://github.com/Checkmarx/kics |
| Prowler | AWS, Azure, GCP cloud security posture and compliance checks | https://github.com/prowler-cloud/prowler |
| terrascan | Policy-as-code for IaC security and compliance | https://github.com/tenable/terrascan |

### Container Security

| Tool | Purpose | Repository |
|---|---|---|
| Trivy | Container image vulnerability and misconfiguration scanning | https://github.com/aquasecurity/trivy |
| Grype | Fast image vulnerability scanner with SBOM input support | https://github.com/anchore/grype |
| Hadolint | Dockerfile linter enforcing best practices | https://github.com/hadolint/hadolint |
| Dockle | Container image linter for CIS benchmark compliance | https://github.com/goodwithtech/dockle |

---

## Commercial Platforms

| Platform | Description |
|---|---|
| Snyk | Developer-first SCA, SAST, container, and IaC scanning with IDE and CI integrations |
| Checkmarx One | Enterprise SAST, DAST, and SCA platform with a unified developer security portal |
| Veracode | Cloud-based SAST, DAST, and SCA with compliance reporting (SOC 2, PCI, FedRAMP) |
| SonarQube (Enterprise/Cloud) | Code quality and security platform with branch analysis and quality gates |
| JFrog Xray | Binary-level SCA and vulnerability scanning integrated with JFrog Artifactory |
| Prisma Cloud (Palo Alto) | Full-lifecycle cloud and container security including CI/CD pipeline scanning |
| GitHub Advanced Security | CodeQL SAST, secret scanning, and Dependabot natively integrated into GitHub |
| Renovate / Dependabot | Automated dependency update pull requests (Renovate is OSS; Dependabot is GitHub-native) |

---

## CI/CD Security: Offensive & Defensive Perspectives

| Attack Vector | Offensive Technique | Defensive Control |
|---|---|---|
| Pipeline Poisoning | Inject malicious steps via pull request changes to `.github/workflows` or poisoned Actions | Require code review for workflow changes; pin Actions to commit SHAs not tags |
| Dependency Confusion | Publish a public package with the same name as an internal private package | Private package registries with scope pinning; SCA scanning on all installs |
| Secrets in Env Vars | Extract CI/CD secrets via compromised step or malicious Action | Use short-lived OIDC tokens instead of static secrets; mask secrets in logs |
| Compromised Build Dependency | Typosquatted or hijacked transitive dependency injects malicious code | Lock file enforcement, hash pinning, SBOM generation and comparison |
| Malicious GitHub Action | Reference a third-party Action that exfiltrates GITHUB_TOKEN or env vars | Pin all Actions to verified commit SHAs; audit Action permissions |
| Excessive Pipeline Permissions | GITHUB_TOKEN with write permissions used to modify repository contents | Apply principle of least privilege; use `permissions: read-all` as default |
| Container Registry Poisoning | Push a malicious image tag to a shared registry used by downstream services | Image signing with Sigstore/cosign; admission control enforcing verified signatures |

---

## SBOM: Software Bill of Materials

An SBOM is a formal, machine-readable inventory of all software components, their versions, and their licenses. It is foundational to supply chain security:

- **CycloneDX** — OWASP-hosted standard; widely supported by tooling (syft, Trivy, Snyk)
- **SPDX** — Linux Foundation standard; used by CISA and US federal requirements
- **Generation**: `syft image:latest -o cyclonedx-json > sbom.json`
- **Vulnerability Matching**: Feed SBOM to Grype — `grype sbom:sbom.json`
- **Attestation**: Sign SBOMs with cosign and store in OCI registries as attestations

---

## SLSA Framework Levels

| Level | Requirements | Protection Against |
|---|---|---|
| SLSA 1 | Build process documented; provenance available | Accidental errors in build |
| SLSA 2 | Build service used; signed provenance | Tampering after source code committed |
| SLSA 3 | Hardened build; isolated builds per project | Compromise of build service |
| SLSA 4 (Legacy) / Build L3 | Two-party review; hermetic, reproducible builds | Insider threats in the build process |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| SA-11 | System and Services Acquisition | Automated SAST and DAST in CI/CD pipelines implements developer security testing |
| SA-15 | Development Process Standards | DevSecOps formalizes secure development standards across the SDLC |
| SI-7 | Software, Firmware, and Information Integrity | SBOM, code signing, and hash pinning enforce software integrity |
| CM-3 | Configuration Change Control | Pipeline gates enforce change approval and security validation before deployment |
| CM-7 | Least Functionality | IaC scanning and container hardening reduce unnecessary functionality |
| SR-3 | Supply Chain Controls and Processes | SCA, SBOM, and dependency scanning implement supply chain risk management |
| SR-4 | Provenance | SLSA provenance and SBOM attestations establish software supply chain provenance |
| CA-2 | Control Assessments | Automated pipeline security gates serve as continuous control assessments |
| RA-5 | Vulnerability Monitoring and Scanning | SCA tools continuously scan for new CVEs in deployed dependencies |
| CM-2 | Baseline Configuration | IaC scanning enforces security baselines for infrastructure configurations |

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Initial Access | SCA and SBOM tooling detects compromised or malicious dependencies |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | SLSA provenance and pipeline hardening prevent build-time compromise |
| T1059 | Command and Scripting Interpreter | Execution | Malicious CI/CD pipeline steps executing arbitrary commands |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access | Secrets detection (gitleaks, truffleHog) prevents credentials in source |
| T1078 | Valid Accounts | Defense Evasion | Compromised service accounts and deploy tokens used to access pipelines |
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access | Developer-targeted phishing to compromise CI/CD access credentials |
| T1190 | Exploit Public-Facing Application | Initial Access | DAST and SAST detect exploitable vulnerabilities before production deployment |
| T1036 | Masquerading | Defense Evasion | Typosquatted packages masquerading as legitimate dependencies |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| CSSLP (Certified Secure Software Lifecycle Professional) | (ISC)2 | Secure software development across the full SDLC |
| DevSecOps Foundation | DevOps Institute | DevSecOps principles, culture, and tooling integration |
| SC-200 (Microsoft Security Operations Analyst) | Microsoft | Security operations including Azure DevOps and Sentinel |
| AWS Security Specialty | Amazon Web Services | AWS security including CI/CD, IAM, and supply chain controls |
| Certified DevSecOps Professional (CDP) | Practical DevSecOps | Hands-on pipeline security, SAST, DAST, and container security |
| CKS (Certified Kubernetes Security Specialist) | CNCF / Linux Foundation | Kubernetes security including admission control and supply chain |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/) | Free guide | Comprehensive reference for embedding security into each SDLC phase |
| [SLSA Specification](https://slsa.dev/spec/v1.0/) | Free spec | Supply chain levels for software artifacts; build provenance framework |
| [Google SRE Book](https://sre.google/sre-book/table-of-contents/) | Free book | Reliability and security at scale; foundational for platform engineers |
| [Semgrep Docs and Rules](https://semgrep.dev/docs/) | Free | Writing custom SAST rules; understanding code pattern matching |
| [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) | Free | Official guide to securing GitHub Actions pipelines |
| [Practical DevSecOps Courses](https://www.practical-devsecops.com/) | Paid | Hands-on SAST, DAST, SCA, and pipeline security labs |
| [Kubernetes Security Best Practices (CNCF)](https://kubernetes.io/docs/concepts/security/) | Free | Container and orchestration security hardening |
| [Securing DevOps — Julien Vehent](https://www.manning.com/books/securing-devops) | Book | Practical DevSecOps from a Mozilla security engineer |
| [The Phoenix Project](https://www.amazon.com/Phoenix-Project-DevOps-Helping-Business/dp/1942788290) | Book | Foundational DevOps culture narrative; context for DevSecOps integration |

---

## Related Disciplines

- [Application Security](application-security.md)
- [Cloud Security](cloud-security.md)
- [Vulnerability Management](vulnerability-management.md)
- [Container Security](container-security.md)
- [Bug Bounty](bug-bounty.md)
- [Security Operations](security-operations.md)
- [Offensive Security](offensive-security.md)
