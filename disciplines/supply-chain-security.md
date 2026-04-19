# Supply Chain Security

> Protecting the integrity of software and hardware as it flows from developers and vendors into production — preventing compromised dependencies, tampered builds, and malicious packages from reaching your environment.

## What Supply Chain Security Engineers Do

- Build and maintain SBOM (Software Bill of Materials) generation and consumption pipelines
- Implement artifact signing and verification (containers, packages, binaries)
- Enforce dependency pinning, allowlisting, and vulnerability gating in CI/CD
- Evaluate third-party software and vendor security posture
- Monitor for dependency confusion, typosquatting, and malicious package attacks
- Implement SLSA framework controls to achieve build integrity guarantees
- Operate internal package mirrors and artifact registries with security controls
- Respond to supply chain incidents (SolarWinds-style, XZ Utils, Log4Shell-style)

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) | Build integrity framework (Levels 0–3) |
| [in-toto](https://in-toto.io/) | Cryptographic supply chain attestation framework |
| [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final) | Secure Software Development Framework |
| [CISA Software Bill of Materials](https://www.cisa.gov/sbom) | SBOM guidance and standards |
| [OpenSSF Security Baseline](https://baseline.openssf.org/) | Security baseline for open source projects |
| [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide) | Hardening CI/CD systems |
| [NIST SP 800-161r1](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final) | C-SCRM (Cyber Supply Chain Risk Management) |

---

## Free & Open-Source Tools

### SBOM Generation

| Tool | Purpose | Notes |
|---|---|---|
| [Syft](https://github.com/anchore/syft) | SBOM generator for containers + filesystems | CycloneDX + SPDX output; Anchore |
| [cdxgen](https://github.com/CycloneDX/cdxgen) | CycloneDX SBOM generator | Multi-language; deep dependency analysis |
| [Tern](https://github.com/tern-tools/tern) | Container layer SBOM inspection | Dockerfile + image analysis |
| [Microsoft SBOM Tool](https://github.com/microsoft/sbom-tool) | SPDX SBOM generator | Multi-ecosystem; Azure DevOps integration |
| [SPDX Tools](https://github.com/spdx/spdx-tools) | SPDX format tooling | Reference implementation |

### Vulnerability Scanning

| Tool | Purpose | Notes |
|---|---|---|
| [Grype](https://github.com/anchore/grype) | Vulnerability scanner from SBOM or image | Works with Syft SBOMs |
| [Trivy](https://trivy.dev/) | All-in-one: CVE + secrets + misconfigs | Widely adopted; fast |
| [osv-scanner](https://github.com/google/osv-scanner) | OSV database scanner | Google; multi-ecosystem |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | NVD-based SCA | Java, .NET, Python, Ruby, Node |
| [Safety](https://pypi.org/project/safety/) | Python dependency CVE checker | PyPI ecosystem |
| [npm audit](https://docs.npmjs.com/cli/v9/commands/npm-audit) | Node.js dependency audit | Built-in npm tool |

### Artifact Signing & Verification

| Tool | Purpose | Notes |
|---|---|---|
| [Cosign](https://docs.sigstore.dev/cosign/overview/) | Container image + artifact signing | Sigstore; keyless OIDC signing |
| [Rekor](https://docs.sigstore.dev/rekor/overview/) | Immutable transparency log | Sigstore; append-only attestation ledger |
| [Fulcio](https://docs.sigstore.dev/fulcio/overview/) | Short-lived certificate CA | Sigstore; OIDC-based identity |
| [in-toto](https://in-toto.io/) | Supply chain attestation | Cryptographic pipeline step verification |
| [The Update Framework (TUF)](https://theupdateframework.io/) | Secure software update system | Used by PyPI, Docker, Conda |
| [sigstore-python](https://github.com/sigstore/sigstore-python) | Python Sigstore client | Sign + verify Python packages |

### Repository & Registry Security

| Tool | Purpose | Notes |
|---|---|---|
| [Renovate](https://www.mend.io/renovate/) | Automated dependency updates | Open source; PR-based updates |
| [Dependabot](https://github.com/dependabot) | GitHub-native dependency updates | Automatic PRs for CVE fixes |
| [pip-audit](https://pypi.org/project/pip-audit/) | Python package audit | PyPI Advisory Database |
| [Socket Security](https://socket.dev/) | Malicious package detection | Behavioral analysis of npm/PyPI/Go packages |
| [Wolfi OS](https://wolfi.dev/) | Distroless-style secure base images | Chainguard; minimal CVE footprint |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Chainguard](https://chainguard.dev/) | Secure container images + SBOM | Minimal, hardened images; Wolfi-based |
| [Snyk](https://snyk.io/) | SCA + container + IaC scanning | Developer-first; rich IDE integrations |
| [JFrog Xray](https://jfrog.com/xray/) | Universal artifact scanning | Deep recursive scanning; JFrog platform |
| [Sonatype Nexus Lifecycle](https://www.sonatype.com/products/open-source-security-management) | Component intelligence | Policy enforcement; OSS Index |
| [Mend (WhiteSource)](https://www.mend.io/) | SCA + malicious package detection | Remediation automation |
| [Anchore Enterprise](https://anchore.com/) | Container supply chain security | Policy-based gate in CI/CD |
| [Black Duck (Synopsys)](https://www.synopsys.com/software-integrity/software-composition-analysis-tools/black-duck-sca.html) | SCA + license compliance | Enterprise; proprietary component DB |

---

## Attack Taxonomy

### Known Supply Chain Attack Patterns

| Attack Type | Example | Mitigation |
|---|---|---|
| Dependency Confusion | [Alex Birsan 2021](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) | Private registry namespacing, scope pinning |
| Typosquatting | `colourama` vs `colorama` | Allowlisting, package hash pinning |
| Compromised maintainer | `xz-utils` backdoor (CVE-2024-3094) | Reproduce builds, signed releases |
| Build system compromise | SolarWinds SUNBURST | SLSA Level 3+, hermetic builds |
| Malicious CI config | GitHub Actions pwn requests | Pin Actions to commit SHA, not tag |
| Trojanized update | CCleaner 2017 | Binary signing + CT logs |

### ATT&CK Coverage

Supply chain security directly addresses:
- **T1195** — Supply Chain Compromise (SBOMs, signing, provenance)
- **T1195.001** — Compromise Software Dependencies (SCA, hash pinning)
- **T1195.002** — Compromise Software Supply Chain (SLSA, in-toto)
- **T1195.003** — Compromise Hardware Supply Chain (hardware attestation)
- **T1554** — Compromise Host Software Binary (binary signing verification)
- **T1199** — Trusted Relationship (vendor security assessment)

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [CSSLP](https://www.isc2.org/Certifications/CSSLP) | ISC² | Secure Software Lifecycle including supply chain |
| [GCSA](https://www.giac.org/certifications/cloud-security-automation-gcsa/) | GIAC | Cloud Security Automation |
| [CIS Controls CCSA](https://www.cisecurity.org/) | CIS | Supply chain controls assessment |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Sigstore Documentation](https://docs.sigstore.dev/) | Reference | Keyless signing ecosystem |
| [SLSA Framework](https://slsa.dev/spec/v1.0/) | Framework | SLSA levels and requirements |
| [OpenSSF Guides](https://openssf.org/resources/guides/) | Free guides | Supply chain best practices |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Feed | KEV catalog for prioritization |
| [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) | Reference | Pipeline attack surface |
| [Securing the Software Supply Chain (CISA)](https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-guide-developers) | Guide | CISA/NSA joint guide |

---

## Related Disciplines

- [DevSecOps](devsecops.md) — Pipeline security, SAST/SCA integration
- [Cryptography & PKI](cryptography-pki.md) — Artifact signing, key management
- [Cloud Security](cloud-security.md) — Registry security, container hardening
- [Vulnerability Management](vulnerability-management.md) — CVE triage from SBOM findings
