# Supply Chain Security

Supply chain security is the practice of protecting the integrity of software and hardware as it flows from developers, vendors, and open-source maintainers into production environments. Every dependency a project pulls, every build system that compiles code, every container image used as a base, and every third-party vendor with privileged access represents a supply chain risk. Adversaries have learned that attacking one well-positioned supplier can compromise thousands of downstream organizations simultaneously — making supply chain attacks one of the highest-leverage offensive techniques available. Supply chain security practitioners include DevSecOps engineers, software engineers, platform security teams, procurement and vendor risk teams, and incident responders. The field sits at the intersection of software development, cryptographic integrity, and risk management.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Understand what an SBOM is, how dependencies create transitive risk, and how Dependabot or Renovate automatically opens PRs for vulnerable packages. | [OpenSSF: Securing Your Software Supply Chain](https://openssf.org/resources/guides/) |
| Intermediate | Generate an SBOM for a project using syft, scan it with Grype, sign a container image with cosign, and understand SLSA levels 1-3. | [SLSA Framework](https://slsa.dev/spec/v1.0/) |
| Advanced | Implement a full SLSA Level 3 build pipeline with hermetic builds, provenance attestation, in-toto metadata, and policy enforcement at deployment via Kyverno or OPA. | [in-toto Framework](https://in-toto.io/) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| SLSA Framework | https://slsa.dev/ | Build integrity levels, requirements, and tooling |
| OpenSSF Guides | https://openssf.org/resources/guides/ | Supply chain best practices for open source projects |
| Sigstore Documentation | https://docs.sigstore.dev/ | Keyless signing, cosign, Rekor, Fulcio |
| CISA Supply Chain Resources | https://www.cisa.gov/sbom | SBOM guidance, formats, and policy |
| OWASP CI/CD Top 10 | https://owasp.org/www-project-top-10-ci-cd-security-risks/ | Pipeline attack surface and mitigations |
| Google OSV | https://osv.dev/ | Open source vulnerability database |
| Chainguard Academy | https://edu.chainguard.dev/ | Sigstore, SLSA, and software supply chain security |

---

## Key Incidents and Threat Context

Understanding real-world supply chain attacks shapes defensive priorities:

| Incident | Year | Attack Vector | Impact |
|---|---|---|---|
| SolarWinds SUNBURST | 2020 | Build system compromise; DLL injection into Orion updates | 18,000+ organizations including US government agencies |
| XZ Utils backdoor (CVE-2024-3094) | 2024 | Compromised maintainer; malicious commits over months | Targeted sshd on systemd-linked systems; caught pre-widespread deployment |
| 3CX Supply Chain Attack | 2023 | Compromised upstream dependency (Trading Technologies) via a trojanized installer | Malware delivered to 3CX customers through legitimate software update |
| Codecov bash uploader compromise | 2021 | CI environment credentials stolen; uploader script modified | Thousands of CI pipelines exfiltrated secrets |
| event-stream npm compromise | 2018 | Malicious maintainer added backdoor targeting Copay Bitcoin wallet | Targeted financial application via transitive npm dependency |
| PyPI malicious packages (ongoing) | 2022+ | Typosquatting and dependency confusion packages | Credential theft, reverse shells deployed to developer machines |

**Key lesson**: Sophisticated adversaries target the weakest link in the software delivery chain — often a less-scrutinized open source maintainer, a CI/CD credential, or a transitive dependency — rather than attacking the hardened target directly.

---

## Software Supply Chain Threats

| Threat | Description | Mitigation |
|---|---|---|
| Dependency Confusion | Publishing a higher-versioned public package matching a private package name | Private registry namespacing, scoped packages, registry priority config |
| Typosquatting | Publishing packages with names nearly identical to popular packages | Package allowlisting, hash pinning, Dependabot alerts |
| Malicious Package Injection | Injecting malware into a legitimate package after maintainer compromise | Signed releases, reproducible builds, SLSA provenance |
| Compromised Build System | Attacker modifies build environment to inject malicious code into output artifacts | SLSA Level 3+, hermetic builds, isolated build environments |
| Poisoned CI/CD Pipeline | Malicious workflow injection via pull requests targeting CI token permissions | Pin Actions to commit SHA, least-privilege CI tokens, branch protection |
| Transitive Dependency Risk | Vulnerability or malicious code in a deep transitive dependency | SBOM generation, recursive SCA scanning, lock files |
| Insider / Compromised Maintainer | Malicious or coerced open source maintainer injects backdoor | Multi-party review, reproducible builds, behavioral analysis of packages |

---

## SBOM: Software Bill of Materials

An SBOM is a machine-readable inventory of all software components in an application or container — analogous to an ingredient list for software. SBOMs enable vulnerability correlation (match components against CVE databases), license compliance, and incident response (instantly identify which products contain a vulnerable library).

**SBOM formats**:
- **CycloneDX** — OWASP standard; JSON/XML; rich vulnerability and license metadata; widely tooled
- **SPDX** — Linux Foundation standard; designed for license compliance; also supports security use cases

**Generation tools**:
- **syft** — Fast SBOM generator for containers and filesystems; outputs CycloneDX and SPDX
- **cdxgen** — CycloneDX generator with deep multi-language dependency analysis
- **Microsoft SBOM Tool** — SPDX generator; Azure DevOps integration

**Vulnerability correlation**:
- Generate SBOM at build time, store alongside artifact
- Scan SBOM against OSV, NVD, or GitHub Advisory Database using Grype or Trivy
- Alert when new CVEs are published matching SBOM components (continuous monitoring)

---

## Artifact Signing and Provenance

Signing and provenance attestation creates a cryptographic chain of custody from source code to deployed artifact:

**Sigstore ecosystem**:
- **cosign** — Signs container images and arbitrary files; supports keyless signing via OIDC identity
- **Fulcio** — Short-lived certificate CA that issues certificates bound to OIDC identity (GitHub Actions, Google, Microsoft)
- **Rekor** — Immutable, append-only transparency log that records all signatures; enables audit and discovery

**Keyless signing flow** (GitHub Actions example):
1. Build step triggers cosign sign in CI
2. cosign requests short-lived certificate from Fulcio using GitHub OIDC token
3. Signature and certificate recorded in Rekor transparency log
4. Verifier confirms: certificate was issued to the expected workflow; signature is valid; entry exists in Rekor

**in-toto framework**:
- Defines a supply chain layout (policy) specifying what steps must run and who must sign them
- Each step generates a link metadata file (signed attestation of inputs and outputs)
- Final product verification confirms the entire pipeline ran as expected

**SLSA (Supply chain Levels for Software Artifacts)**:
- Level 0: No guarantees
- Level 1: Build process documented; provenance generated (but unsigned)
- Level 2: Hosted build platform; provenance signed by build service
- Level 3: Hardened build platform; provenance verified; builds isolated from each other
- Level 4 (legacy spec, now merged into L3): Two-party review; hermetic, reproducible builds

---

## Dependency Security

| Tool | Ecosystem | What It Does | Link |
|---|---|---|---|
| Dependabot | Multi-ecosystem | Automated PRs for CVE fixes in GitHub repos | https://github.com/dependabot |
| Renovate | Multi-ecosystem | Open source dep updates with flexible scheduling | https://github.com/renovatebot/renovate |
| Snyk | npm, PyPI, Maven, Go, .NET | SCA + container + IaC scanning; developer-first | https://snyk.io/ |
| OWASP Dependency-Check | Java, .NET, Python, Ruby, Node | NVD-based SCA scanning | https://owasp.org/www-project-dependency-check/ |
| Grype | Multi-ecosystem | Vulnerability scanner operating on SBOM or image | https://github.com/anchore/grype |
| Trivy | Multi-ecosystem | All-in-one: CVE + secrets + misconfigs in one scan | https://trivy.dev/ |
| Socket Security | npm, PyPI, Go | Behavioral analysis detecting malicious packages | https://socket.dev/ |
| pip-audit | Python | Audit Python packages against PyPI Advisory Database | https://pypi.org/project/pip-audit/ |

---

## Build System Security

Securing the build system prevents SolarWinds-style attacks where the output artifact is trojanized:

**Hermetic builds**: The build environment is fully isolated — no network access, no access to secrets or the host file system beyond explicitly declared inputs. Output depends only on declared inputs.

**Reproducible builds**: Given the same source code and build environment, the build produces bit-for-bit identical output. Enables independent verification by multiple parties.

**SLSA build requirements (Level 3)**:
- Hosted build platform (GitHub Actions, Google Cloud Build, etc.)
- Build definition and source are version controlled
- Build is isolated; cannot access other builds or credentials beyond scope
- Provenance is generated by the build platform, not the build script

**Pinning GitHub Actions to commit SHA** (critical hygiene):
```yaml
# Insecure: tag can be moved by attacker
- uses: actions/checkout@v4

# Secure: commit SHA is immutable
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

---

## Container Supply Chain Security

| Control | Description | Tools |
|---|---|---|
| Base image selection | Use minimal, maintained base images — prefer distroless or scratch | Chainguard Images, Google distroless |
| Distroless images | Remove shell, package managers, and unnecessary binaries from final image | gcr.io/distroless, cgr.dev/chainguard |
| Signed images | Sign all container images and verify signatures at deployment | cosign, Notation |
| Image scanning in CI | Scan for CVEs and misconfigurations before pushing to registry | Trivy, Grype, Snyk Container |
| Registry policies | Enforce signed images, block known vulnerable base tags | OPA/Gatekeeper, Kyverno, Harbor |
| Provenance attestation | Attach build provenance metadata to images in registry | cosign attest, SLSA GitHub generator |

---

## Hardware Supply Chain Security

Hardware supply chain risks involve counterfeit components, firmware implants, and interdiction during shipping:

- **Counterfeit components**: Fake chips or modules substituted into the supply chain; may malfunction under stress or contain surveillance capability
- **Firmware implants**: Malicious firmware installed at the factory, during transit, or by a compromised vendor update process
- **SCRM (Supply Chain Risk Management)**: NIST SP 800-161r1 provides a comprehensive framework for identifying, assessing, and mitigating hardware supply chain risks
- **Trusted suppliers**: Maintain approved supplier lists, require certificates of conformance, and verify provenance for critical hardware

---

## Offensive Angle: Supply Chain Attack Techniques

Understanding attack construction is essential for building effective defenses:

**Dependency confusion attack construction**:
1. Enumerate internal package names via OSINT (job postings, GitHub leaks, error messages)
2. Publish a public package with the same name at a higher version number on PyPI/npm
3. Package managers that check public registries first will download the malicious package
4. Payload executes in the CI/CD environment or on developer machines

**Typosquatting PyPI/npm**:
- Register packages with common typos of popular packages (e.g., `requets`, `colourama`, `setuptool`)
- Inject credential stealers, reverse shells, or cryptominers into the package code
- Legitimate developers install the package when mistyping the real package name

**Build system pivot via CI token theft**:
1. Gain write access to a repository via a compromised contributor account or PR injection
2. Craft a malicious workflow that exfiltrates `GITHUB_TOKEN` or cloud provider credentials
3. Use stolen credentials to push malicious code to the main branch or tamper with release artifacts

**SolarWinds-style DLL injection**:
1. Compromise the build environment (not source code) — insert malicious build step
2. Build system injects malicious code into compiled binaries post-compilation
3. Signed artifacts pass code signing checks because the signing step runs after injection
4. Mitigated by: build provenance, reproducible builds, monitoring build environment access

---

## Tools & Repositories

| Tool | Purpose | Link |
|---|---|---|
| syft | SBOM generation for containers and filesystems | https://github.com/anchore/syft |
| cdxgen | CycloneDX SBOM generator (multi-language) | https://github.com/CycloneDX/cdxgen |
| cosign | Container image and artifact signing (Sigstore) | https://github.com/sigstore/cosign |
| Rekor | Immutable transparency log for supply chain attestations | https://github.com/sigstore/rekor |
| in-toto | Cryptographic supply chain attestation framework | https://github.com/in-toto/in-toto |
| Grype | Vulnerability scanner from SBOM or container image | https://github.com/anchore/grype |
| Trivy | All-in-one CVE, secrets, and misconfiguration scanner | https://github.com/aquasecurity/trivy |
| Renovate | Automated dependency update PRs | https://github.com/renovatebot/renovate |
| Socket Security | Behavioral analysis of npm/PyPI/Go packages | https://socket.dev/ |
| SLSA GitHub Generator | Generates SLSA provenance for GitHub Actions builds | https://github.com/slsa-framework/slsa-github-generator |
| osv-scanner | Multi-ecosystem vulnerability scanner using OSV DB | https://github.com/google/osv-scanner |
| The Update Framework (TUF) | Secure software update system (used by PyPI, Docker) | https://theupdateframework.io/ |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Chainguard](https://chainguard.dev/) | Secure container images + SBOM | Minimal, hardened Wolfi-based images; zero CVE at build |
| [Snyk](https://snyk.io/) | SCA + container + IaC scanning | Developer-first; rich IDE integrations |
| [JFrog Xray](https://jfrog.com/xray/) | Universal artifact scanning | Deep recursive scanning; JFrog platform integration |
| [Sonatype Nexus Lifecycle](https://www.sonatype.com/products/open-source-security-management) | Component intelligence | Policy enforcement; OSS Index |
| [Mend (WhiteSource)](https://www.mend.io/) | SCA + malicious package detection | Remediation automation |
| [Anchore Enterprise](https://anchore.com/) | Container supply chain security | Policy-based gate in CI/CD |
| [Black Duck (Synopsys)](https://www.synopsys.com/software-integrity/software-composition-analysis-tools/black-duck-sca.html) | SCA + license compliance | Enterprise; proprietary component DB |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| SR-1 | Supply Chain Risk Management Policy | Requires organizations to establish and maintain C-SCRM program |
| SR-3 | Supply Chain Controls and Processes | Defines controls for managing supply chain risks throughout the lifecycle |
| SR-4 | Provenance | Requires tracking and documentation of system component provenance |
| SR-5 | Acquisition Strategies and Supply Chain Risk | Risk-based acquisition requirements for high-impact systems |
| SR-9 | Tamper Resistance and Detection | Controls for detecting and responding to hardware/software tampering |
| SR-11 | Component Authenticity | Verification of component authenticity before use |
| SA-12 | Supply Chain Protection | Predecessor control family to SR; broad supply chain security requirements |
| SA-3 | System Development Life Cycle | Integrating supply chain security into the SDLC |
| CM-7 | Least Functionality | Limiting software to approved components reduces supply chain attack surface |
| SI-7 | Software, Firmware, and Information Integrity | Hash verification, integrity checking, and signing validation |
| SA-15 | Development Process, Standards, and Tools | Secure development environment requirements — relevant to build system integrity |
| SA-9 | External System Services | Security requirements for third-party software and service providers |

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| T1195 | Supply Chain Compromise | Initial Access | Parent technique — all supply chain attack vectors |
| T1195.001 | Compromise Software Dependencies | Initial Access | Malicious packages, dependency confusion, typosquatting |
| T1195.002 | Compromise Software Supply Chain | Initial Access | Build system compromise (SolarWinds-style), poisoned CI |
| T1195.003 | Compromise Hardware Supply Chain | Initial Access | Counterfeit hardware, firmware implants |
| T1554 | Compromise Host Software Binary | Persistence | Trojanizing installed software binaries post-deployment |
| T1072 | Software Deployment Tools | Execution | Abusing update mechanisms to distribute malicious payloads |
| T1059 | Command and Scripting Interpreter | Execution | Malicious package install scripts (setup.py, postinstall) executing payloads |
| T1078.001 | Default Accounts | Defense Evasion | CI/CD service accounts with default or excessive permissions |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [CSSLP (Certified Secure Software Lifecycle Professional)](https://www.isc2.org/Certifications/CSSLP) | ISC2 | Secure software lifecycle including supply chain integrity |
| [SSCP (Systems Security Certified Practitioner)](https://www.isc2.org/Certifications/SSCP) | ISC2 | Broad security including software and supply chain controls |
| [CISSP](https://www.isc2.org/Certifications/CISSP) | ISC2 | Enterprise security architecture including supply chain risk |
| [GCSA (GIAC Cloud Security Automation)](https://www.giac.org/certifications/cloud-security-automation-gcsa/) | GIAC | Cloud security automation and pipeline security |
| [AWS Security Specialty](https://aws.amazon.com/certification/certified-security-specialty/) | AWS | Cloud-native supply chain controls in AWS environments |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [NIST SP 800-161r1](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final) | Standard | Comprehensive C-SCRM (Cyber Supply Chain Risk Management) framework |
| [SLSA Specification](https://slsa.dev/spec/v1.0/) | Framework | Build integrity levels and requirements — essential reading |
| [OpenSSF Guides](https://openssf.org/resources/guides/) | Free guides | Supply chain best practices for open source projects |
| [Sigstore Documentation](https://docs.sigstore.dev/) | Reference | Keyless signing ecosystem — cosign, Rekor, Fulcio |
| [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) | Reference | Pipeline attack surface — poisoned pipeline injection, credential theft |
| [Securing the Software Supply Chain (CISA/NSA)](https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-guide-developers) | Guide | CISA/NSA joint guidance for developers, suppliers, and customers |
| [Dependency Confusion: Alex Birsan (2021)](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) | Research | Original research paper demonstrating the dependency confusion attack |
| [The Update Framework (TUF)](https://theupdateframework.io/) | Framework | Securing software update systems — used by PyPI, Docker, Conda |

---

## Related Disciplines

- [DevSecOps](devsecops.md) — Pipeline security, SAST/SCA integration, and shift-left supply chain controls
- [Cryptography & PKI](cryptography-pki.md) — Artifact signing, key management, and certificate transparency
- [Cloud Security](cloud-security.md) — Registry security, container hardening, and cloud build platform controls
- [Vulnerability Management](vulnerability-management.md) — CVE triage from SBOM findings and dependency scanner output
- [Offensive Security](offensive-security.md) — Understanding attack construction (dependency confusion, CI token theft) to build better defenses
- [Governance, Risk & Compliance](governance-risk-compliance.md) — NIST SP 800-161, EO 14028, and contractual SBOM requirements
