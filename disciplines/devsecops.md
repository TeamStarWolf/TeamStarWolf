# DevSecOps

> Integrating security practices throughout the software development lifecycle — shifting left to catch vulnerabilities earlier, cheaper, and automatically.

## What DevSecOps Engineers Do

- Embed security scanning into CI/CD pipelines (SAST, DAST, SCA, IaC scanning)
- Define and enforce secure-by-default container and infrastructure configurations
- Conduct threat modeling for new features and architecture changes
- Triage and track vulnerability findings from automated tooling
- Build and maintain security guardrails (policy-as-code, pre-commit hooks, branch protections)
- Collaborate with developers to fix findings and improve secure coding practices
- Manage secrets scanning and enforce secrets management standards

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/) | End-to-end DevSecOps pipeline reference |
| [SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) | Software supply chain integrity framework |
| [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final) | Secure Software Development Framework |
| [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide) | Hardening guide for CI/CD systems |
| [OpenSSF Scorecard](https://securityscorecards.dev/) | Automated security health metrics for open source |

---

## Free & Open-Source Tools

### SAST (Static Analysis)

| Tool | Language Support | Notes |
|---|---|---|
| [Semgrep](https://semgrep.dev/) | 30+ languages | Fast, rule-based; community rules + custom |
| [CodeQL](https://codeql.github.com/) | C/C++, C#, Java, JS, Python, Go, Ruby | GitHub-native; deep semantic analysis |
| [Bandit](https://bandit.readthedocs.io/) | Python | Lightweight Python-specific SAST |
| [Gosec](https://github.com/securego/gosec) | Go | Go security checker |
| [Brakeman](https://brakemanscanner.org/) | Ruby on Rails | Rails-specific SAST |
| [Flawfinder](https://dwheeler.com/flawfinder/) | C/C++ | Quick C/C++ risk scanner |

### SCA (Software Composition Analysis)

| Tool | Purpose | Notes |
|---|---|---|
| [Trivy](https://trivy.dev/) | Container + filesystem + IaC scanning | All-in-one; CVEs, misconfigs, secrets |
| [Grype](https://github.com/anchore/grype) | Vulnerability scanner for container images | Pairs with Syft for SBOMs |
| [Syft](https://github.com/anchore/syft) | SBOM generation | CycloneDX + SPDX output |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | SCA for Java, .NET, JS, Python | NVD-based CVE matching |
| [osv-scanner](https://github.com/google/osv-scanner) | OSV database vulnerability scanner | Google-maintained; multi-ecosystem |

### IaC Scanning

| Tool | Purpose | Notes |
|---|---|---|
| [Checkov](https://www.checkov.io/) | Terraform, CloudFormation, K8s, Helm | 2,000+ built-in checks |
| [KICS](https://kics.io/) | Multi-IaC scanner | Keeping Infrastructure as Code Secure |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Terraform security scanner | Fast, opinionated Terraform checks |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS Kubernetes Benchmark | Cluster hardening verification |
| [Conftest](https://www.conftest.dev/) | Policy testing for config files | OPA/Rego-based policy engine |

### Secrets Detection

| Tool | Purpose | Notes |
|---|---|---|
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Pre-commit secrets detection | Yelp-maintained; plugin-based |
| [gitleaks](https://gitleaks.io/) | Git history secrets scanner | Scans commits + working tree |
| [truffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets scanning with entropy | Scans git, S3, GitHub, Slack |

### Pipeline Security

| Tool | Purpose | Notes |
|---|---|---|
| [in-toto](https://in-toto.io/) | Software supply chain attestation | Cryptographic pipeline verification |
| [Cosign](https://docs.sigstore.dev/cosign/overview/) | Container image signing | Sigstore ecosystem |
| [OSSF Allstar](https://github.com/ossf/allstar) | GitHub security policy enforcement | Continuous policy checks |
| [Falco](https://falco.org/) | Runtime security for containers | CNCF; detects anomalous behavior |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Snyk](https://snyk.io/) | SAST + SCA + IaC + container | Developer-friendly; IDE integrations |
| [Checkmarx](https://checkmarx.com/) | Enterprise SAST/SCA/DAST | CxOne unified platform |
| [Veracode](https://www.veracode.com/) | SAST + DAST + SCA | Pipeline-first; compliance reporting |
| [SonarQube](https://www.sonarsource.com/products/sonarqube/) | Code quality + security | Community edition free; widely adopted |
| [Lacework](https://lacework.com/) | Cloud-native security platform | Behavioral anomaly detection |
| [Prisma Cloud (Palo Alto)](https://www.paloaltonetworks.com/prisma/cloud) | CNAPP; code-to-cloud | Shift-left IaC + runtime |
| [Wiz](https://wiz.io/) | CNAPP with code security | Context-aware risk prioritization |
| [GitHub Advanced Security](https://github.com/features/security) | CodeQL SAST + secret scanning | Native to GitHub |

---

## CI/CD Pipeline Integration

```yaml
# Example: Semgrep in GitHub Actions
name: Semgrep SAST
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/ci
            p/secrets
```

```yaml
# Example: Trivy container scan
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:latest'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
```

---

## ATT&CK Coverage

DevSecOps tooling primarily addresses the **initial access** and **execution** phases by preventing vulnerable code from reaching production and detecting misconfigurations attackers could exploit.

Key techniques addressed:
- **T1190** — Exploit Public-Facing Application (via SCA/SAST catching CVEs)
- **T1195** — Supply Chain Compromise (via SBOM, Cosign, in-toto)
- **T1552** — Unsecured Credentials (via secrets scanning)
- **T1059** — Command and Scripting Interpreter (via SAST catching injection flaws)
- **T1068** — Exploitation for Privilege Escalation (via dependency vulnerability scanning)

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [CSSLP](https://www.isc2.org/Certifications/CSSLP) | ISC² | Certified Secure Software Lifecycle Professional |
| [GWEB](https://www.giac.org/certifications/web-application-defender-gweb/) | GIAC | Web application security testing |
| [GCSA](https://www.giac.org/certifications/cloud-security-automation-gcsa/) | GIAC | Cloud Security Automation (DevSecOps-focused) |
| [AWS Security Specialty](https://aws.amazon.com/certification/certified-security-specialty/) | AWS | Cloud security including CI/CD pipelines |
| [CKS](https://www.cncf.io/certification/cks/) | CNCF | Certified Kubernetes Security Specialist |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [DevSecOps.org](https://www.devsecops.org/) | Community | Manifesto, guides, community |
| [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) | Reference | Top CI/CD attack vectors |
| [Semgrep Academy](https://academy.semgrep.dev/) | Free course | Writing custom Semgrep rules |
| [Snyk Learn](https://learn.snyk.io/) | Free course | Vulnerability learning paths |
| [OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/) | Reference | Badge program for open source projects |
| [Practical DevSecOps](https://www.practical-devsecops.com/) | Paid course | Hands-on pipeline security labs |

---

## Related Disciplines

- [Supply Chain Security](supply-chain-security.md) — SBOM standards, signing, and provenance
- [Cloud Security](cloud-security.md) — CSPM, cloud misconfigurations
- [Security Architecture](security-architecture.md) — Threat modeling and secure design
- [Vulnerability Management](vulnerability-management.md) — Triage and remediation workflows
