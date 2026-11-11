<!-- hub:start (written by scripts/build_site_nav.py from docs/site_nav.json; do not edit) -->

# Application and supply chain security

> Secure coding, web, API, and browser security, threat modeling, DevSecOps, the software supply chain, and secrets.

Part of the [domain hubs](/hubs/README.md). 10 reference documents in this domain; reading time is the page's words at 230 words a minute.

## References

| Reference | What it covers | Reading time |
|---|---|---|
| [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) | OWASP Top 10 (2021), input validation, cryptography in code, SAST/DAST, and quick guides for Python, JavaScript, TypeScript, Java, Kotlin, C#, Go, Rust, C, C++, PHP, Ruby, Swift, and PowerShell | 13 min |
| [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) | OWASP Top 10, SQL injection, XSS, authentication attacks, SSRF/XXE, API security, WAF bypass, secure coding, bug bounty methodology | 16 min |
| [API Security Reference](/API_SECURITY_REFERENCE.md) | OWASP API Top 10, REST and GraphQL attack techniques, JWT attacks, SSRF, BOLA/BFLA, and API security testing methodology | 25 min |
| [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md) | SOP, CORS attacks, CSP bypass, security headers, CSRF, clickjacking, cookie security, extension analysis, prototype pollution | 11 min |
| [Threat Modeling Reference](/THREAT_MODELING_REFERENCE.md) | STRIDE, PASTA, LINDDUN, attack trees, MITRE ATT&CK integration, DFDs, pytm, cloud microservices threat modeling | 26 min |
| [DevSecOps Reference](/DEVSECOPS_REFERENCE.md) | SAST/DAST/SCA tools, GitHub Actions security, Semgrep/CodeQL/Trivy/Snyk, secrets detection, IaC scanning, pipeline security gates | 19 min |
| [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) | SBOM (CycloneDX/SPDX), Sigstore/cosign, SLSA framework, dependency security, CI/CD pipeline hardening, malicious package detection, OSS risk management | 26 min |
| [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md) | HashiCorp Vault, CyberArk Conjur, secret detection (gitleaks/ggshield/TruffleHog), cloud-native secrets, PKI/SSH, CI/CD OIDC | 17 min |
| [Application Security Testing](/APPSEC_TESTING_REFERENCE.md) | SAST, DAST, IAST, SCA, SBOM, and secrets scanning: what each finds and misses, where each fits in the SDLC and CI/CD, how to choose and combine them, and where application findings are consolidated | 6 min |
| [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md) | npm/yarn/pnpm, pip/Poetry/uv/conda, cargo, Go modules, Maven/Gradle, NuGet, RubyGems, Composer, and OS managers: manifests, lockfiles, registries, and supply-chain risks (dependency confusion, typosquatting, malicious and install-script packages) with mitigations | 4 min |

## Learning paths

- [Application Security](/disciplines/application-security.md)
- [DevSecOps](/disciplines/devsecops.md)
- [Supply Chain Security](/disciplines/supply-chain-security.md)
- [Threat Modeling](/disciplines/threat-modeling.md)

## How-to guides

Time and difficulty are quoted in full from each guide's header table.

| Guide | Time | Difficulty |
|---|---|---|
| [Threat Model an Application](/guides/THREAT_MODEL_AN_APPLICATION.md) | 3-4 hours (first pass, one application) | Intermediate |

## Platforms and developer reference

| Page | What it covers |
|---|---|
| [Programming Languages](/languages/README.md) | In-depth pages for programming and scripting languages: design, type system, toolchain, a syntax tour, common pitfalls, and secure coding |
| [Programming Paradigms](/paradigms/README.md) | The ways programs are organized, one paradigm per page, with runnable examples, trade-offs, the languages that use it, and its secure-coding failure modes |
| [Software Frameworks](/frameworks/README.md) | In-depth pages for backend, frontend, full-stack, and mobile application frameworks: architecture, request flow, and framework-specific security |
| [Data Formats and Regular Expressions](/formats/README.md) | Reference pages for markup, data, and configuration formats and for regular expressions: syntax, tooling that parses and validates them, and format-specific security pitfalls |
| [Databases](/databases/README.md) | Reference pages for database engines: relational, analytical, NoSQL, search, graph, and time-series stores, with each one's data model, query surface, and security |
| [Git Command Reference](/commands/git.md) | Version control: branching, merging, rebasing, history, and secret hygiene |
| [Snyk](/platforms/snyk.md) | Developer-first SCA, SAST, container, and IaC security |
| [Invicti](/platforms/invicti.md) | Proof-based dynamic and interactive application security testing |
| [Chainguard](/platforms/chainguard.md) | Secure-by-default minimal container images and a hardened Wolfi base that cut image vulnerabilities |

## See also

- [Web application pentesting](/WEB_APPLICATION_PENTESTING.md)
- [CAPEC attack patterns](/mitre/capec/README.md)
- [Log4Shell: a case study](/case-studies/LOG4SHELL.md)
- [Ghostcat (CVE-2020-1938): a lab case study](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [Node.js CVE-2026-111497 (Brotli): a lab case study](/case-studies/NODEJS_CVE_2026_111497.md)
- [Magento and Adobe Commerce (CVE-2026-48356): a lab case study](/case-studies/MAGENTO_CVE_2026_48356.md)
- [PHP 8.4.27 (CVE-2026-109618 and CVE-2026-109619): a lab case study](/case-studies/PHP_8_4_27_CVES.md)
- [Nextcloud Collabora Built-in CODE Server (CVE-2026-110447): a lab case study](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md)
- [npm supply-chain attacks: a case study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)
- [Hugging Face supply chain: a case study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md)

<!-- hub:end -->
