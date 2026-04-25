# Supply Chain Security Reference

> Comprehensive reference covering real-world software supply chain attacks, detection methods, SBOM generation, SLSA framework, Sigstore ecosystem, and CI/CD pipeline hardening.
>
> Mapped to: NIST SP 800-161r1 (C-SCRM) | EO 14028 | ATT&CK T1195 (Supply Chain Compromise) | T1554 (Compromise Software Supply Chain)

---

## Notable Supply Chain Attacks

### SolarWinds SUNBURST (2020)

- **Attack vector**: Trojanized SolarWinds Orion software update — malicious DLL injected into `SolarWinds.Orion.Core.BusinessLayer.dll` during the build process
- **Mechanism**: SUNBURST backdoor lay dormant for 12–14 days post-installation, then validated the hostname against an internal blocklist (filtering out AV vendors and security researchers). If clear, it beaconed to `avsvmcloud[.]com` using subdomain-encoded victim fingerprints for C2 communication
- **Impact**: 18,000+ organizations received the trojanized Orion update; ~100 were actively exploited including US Treasury, CISA, DHS, and Microsoft
- **Detection lessons**:
  - **Golden SAML forgery** — attackers forged SAML tokens to bypass MFA entirely
  - Lateral movement used legitimate credentials, blending with normal admin activity
  - Anomalous outbound DNS/HTTPS from Orion service process (`SolarWinds.BusinessLayerHost.exe`) to external domains
- **Mitigations derived**:
  - Network segmentation: monitoring systems should NOT have unrestricted internet access
  - Behavioral baselines for update traffic; alert on new external domains contacted by software processes
  - Privileged Access Workstations (PAWs) for IT management to limit blast radius
  - Build environment isolation and integrity verification (hash comparison of build outputs)

---

### XZ Utils Backdoor (CVE-2024-3094)

- **Timeline**: 2-year slow social engineering campaign against Lasse Collin (XZ maintainer) by a persona called "Jia Tan", beginning in 2021. Gradual trust-building through legitimate contributions before gaining commit access
- **Mechanism**: Malicious build script injected into XZ Utils 5.6.0 and 5.6.1. The backdoor modified `liblzma.so` and, on systemd-linked systems where OpenSSH called `liblzma`, used an **IFUNC resolver hijack** to intercept `RSA_public_decrypt()` — allowing the attacker to authenticate to any affected SSH daemon with a hardcoded private key, bypassing all normal authentication
- **Affected distributions**: Debian Sid, Fedora 40/41 (pre-release), Kali Linux (briefly), openSUSE Tumbleweed
- **Discovery**: Andres Freund (Microsoft/PostgreSQL) noticed an anomalous ~500ms SSH login slowdown on Debian Sid and traced it to the tampered `liblzma.so`
- **Key lessons**:
  - **Maintainer burnout** is an attack surface — understaffed OSS projects are targets for social engineering
  - **Slow-burn social engineering**: building trust over years before weaponizing access
  - **Build artifact != source code**: the malicious payload was in the autoconf/M4 build macros, not visible in the raw C source
  - **Automated binary diff monitoring** is needed to detect unexpected changes between release tarballs and source checkout builds
  - The attack targeted the *binary distribution chain*, not the source repo directly

---

### 3CX Desktop App Trojanization (2023)

- **Supply chain within a supply chain**: Lazarus Group (North Korea) first compromised **Trading Technologies' X_TRADER** application. A 3CX employee downloaded the trojanized X_TRADER, infecting their developer workstation. Attackers then pivoted into the 3CX build environment, signing a trojanized version of the 3CX Electron app with 3CX's own legitimate certificate
- **Mechanism**: Malicious `d3dcompiler_47.dll` sideloaded by the 3CX app; shellcode was decrypted from **ICO files hosted on GitHub**, then fetched and executed in-memory for C2 communication
- **Detection**: CrowdStrike MARS telemetry identified unexpected child processes spawning from the 3CX application, triggering the investigation
- **Lessons**: Verify build environment integrity; monitor developer workstations as entry points; signed binaries are not proof of legitimacy

---

### Codecov Bash Uploader Compromise (2021)

- **CI/CD pipeline attack**: An attacker with access to Codecov's GCS bucket replaced the legitimate `codecov.io/bash` uploader script with a malicious version that exfiltrated all environment variables (including `CODECOV_TOKEN`, AWS credentials, GitHub tokens) to an attacker-controlled server
- **Impact**: Any CI pipeline using `curl https://codecov.io/bash | bash` was affected — git credentials and secrets from thousands of repositories were exfiltrated. Affected organizations included Twilio, HashiCorp, and Rapid7
- **Lesson**: Never use `curl | bash` patterns in CI pipelines without checksum verification; pin to a specific commit SHA with verified hash

---

### npm / PyPI Typosquatting and Malicious Packages

Ongoing campaigns targeting developers via confusingly named packages:

| Campaign | Package | Year | Method |
|---|---|---|---|
| `crossenv` | Impersonated `cross-env` | 2017 | 43 malicious packages, post-install data theft |
| `event-stream` | Maintainer transfer attack | 2018 | Targeted bitcoin wallet via `flatmap-stream` dependency |
| `ctx` / `PHPass` | PyPI credential theft | 2022 | Harvested env vars including AWS keys |
| `lodash` impersonators | Dozens per year | Ongoing | Typosquatting at scale |
| `colorama`, `requests` impersonators | Hundreds of variants | Ongoing | Credential/crypto theft |

**Detection approaches**:

```bash
# pip-audit — scan for known vulnerabilities in installed packages
pip-audit -r requirements.txt

# Inspect a PyPI package before installing
curl https://pypi.org/pypi/PACKAGE/json | jq '.info | {name, author, home_page, requires_python, version}'

# npm audit
npm audit --json

# Socket.dev — supply chain risk scoring for npm/PyPI packages
# https://socket.dev — flags suspicious behaviors (network access, obfuscation, install scripts)

# deps.dev — Open Source Insights dependency graph analysis
# https://deps.dev
```

---

### Dependency Confusion Attacks

Alex Birsan's 2021 research demonstrated that build systems will prefer a **higher-versioned public registry package** over an internal private package with the same name.

**Attack flow**:

```
1. Attacker discovers internal package name (e.g., "mycompany-utils") via:
   - Accidentally public package.json / requirements.txt in GitHub repos
   - Job postings mentioning internal tooling names
   - Error messages from npm/pip referencing private packages

2. Attacker uploads "mycompany-utils" @ version 9999.0.0 to public npm/PyPI

3. Build systems configured to check public registries first fetch the malicious package
```

**Defenses**:

```bash
# npm: use scoped packages for all internal packages
@mycompany/internal-lib

# .npmrc: lock to internal registry
registry=https://registry.internal.company.com
@mycompany:registry=https://registry.internal.company.com

# pip.conf: explicit index URL
[global]
index-url = https://internal.company.com/simple/
extra-index-url = https://pypi.org/simple/
# Note: extra-index-url still vulnerable — use index-url only, or allowlist

# Yarn
# .yarnrc.yml: use resolutions and private registry
```

---

## Software Bill of Materials (SBOM)

### What is an SBOM

A **Software Bill of Materials** is a machine-readable inventory of all components in a software artifact — including direct dependencies, transitive dependencies, licenses, and version information.

**Executive Order 14028** (May 2021) mandates SBOM for software sold to the US federal government. The **NTIA minimum elements** are:

| Element | Description |
|---|---|
| Supplier Name | Entity that distributes the component |
| Component Name | Name used by the supplier |
| Version of the Component | Identifier as used by the supplier |
| Other Unique Identifiers | PURL, CPE, or other identifier |
| Dependency Relationship | Relationship to the containing product |
| Author of SBOM Data | Who created the SBOM record |
| Timestamp | When the SBOM entry was created |

---

### SBOM Formats

**SPDX 2.3 (Linux Foundation / ISO 5962)**:

```json
{
  "SPDXID": "SPDXRef-DOCUMENT",
  "spdxVersion": "SPDX-2.3",
  "creationInfo": {
    "created": "2024-01-15T12:00:00Z",
    "creators": ["Tool: syft-0.105.1"]
  },
  "name": "my-application",
  "packages": [
    {
      "SPDXID": "SPDXRef-requests",
      "name": "requests",
      "versionInfo": "2.31.0",
      "downloadLocation": "https://pypi.org/project/requests/",
      "filesAnalyzed": false,
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:pypi/requests@2.31.0"
        }
      ]
    }
  ]
}
```

**CycloneDX 1.5 (OWASP)**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata>
    <timestamp>2024-01-15T12:00:00Z</timestamp>
    <tools><tool><name>syft</name><version>0.105.1</version></tool></tools>
    <component type="application">
      <name>my-app</name>
      <version>1.0.0</version>
    </component>
  </metadata>
  <components>
    <component type="library">
      <name>requests</name>
      <version>2.31.0</version>
      <purl>pkg:pypi/requests@2.31.0</purl>
      <licenses><license><id>Apache-2.0</id></license></licenses>
    </component>
  </components>
</bom>
```

---

### Generating SBOMs

```bash
# Syft — universal SBOM generator (container images, dirs, archives)
syft image nginx:latest -o spdx-json > nginx-sbom.spdx.json
syft dir:./myapp -o cyclonedx-json > myapp-sbom.cyclonedx.json
syft image python:3.11 -o table        # Human-readable table output
syft image alpine:3.19 -o spdx-json --file alpine-sbom.json

# Docker Scout (built into Docker Desktop / Docker Hub)
docker scout sbom nginx:latest
docker scout sbom --format spdx nginx:latest > nginx.spdx.json

# Python projects: cyclonedx-bom
pip install cyclonedx-bom
cyclonedx-bom -r requirements.txt -o cyclonedx.xml
cyclonedx-py poetry -o sbom.json     # Poetry projects

# Java: CycloneDX Maven plugin
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
# Output: target/bom.xml and target/bom.json

# JavaScript/Node: CycloneDX npm plugin
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
npx @cyclonedx/cyclonedx-npm --output-format XML --output-file sbom.xml

# Go: cyclonedx-gomod
cyclonedx-gomod app -output sbom.json

# GitHub: dependency graph + SBOM export
gh api repos/OWNER/REPO/dependency-graph/sbom | jq .sbom > repo-sbom.spdx.json
```

---

### SBOM Vulnerability Scanning

```bash
# Grype — Anchore's vulnerability scanner against SBOM files
grype sbom:./nginx-sbom.spdx.json
grype sbom:./myapp-sbom.cyclonedx.json --fail-on critical
grype image nginx:latest                 # Direct image scan
grype sbom:./sbom.json -o json | jq '.matches[] | select(.vulnerability.severity=="Critical")'

# OSV-Scanner — Google's scanner using the OSV vulnerability database
osv-scanner --sbom=./sbom.spdx.json
osv-scanner --lockfile=requirements.txt  # Direct lockfile scanning
osv-scanner --recursive ./               # Scan entire project tree

# Trivy — all-in-one scanner (image + SBOM + IaC + secret)
trivy image nginx:latest
trivy sbom ./sbom.spdx.json
trivy fs ./myapp --format cyclonedx > sbom.json  # Generate + scan

# Dependency-Track — full SBOM lifecycle management platform
# - Upload SBOM via REST API or web UI
# - Continuous monitoring against NVD, GitHub Advisory, OSV, Sonatype OSS
# - Webhook alerts on new CVEs affecting your SBOM components
curl -X "POST" "http://dtrack.internal/api/v1/bom" \
  -H 'X-Api-Key: your-api-key' \
  -H 'Content-Type: multipart/form-data' \
  -F "autoCreate=true" \
  -F "projectName=myapp" \
  -F "projectVersion=1.0.0" \
  -F "bom=@./sbom.cyclonedx.json"
```

---

## SLSA Framework (Supply chain Levels for Software Artifacts)

*Source: [slsa.dev](https://slsa.dev) | OpenSSF*

SLSA is a security framework providing a checklist of standards and controls to prevent tampering, improve integrity, and secure packages and infrastructure in your projects, businesses, or enterprises.

### SLSA Levels (v1.0)

| Level | Build Requirements | Benefit |
|---|---|---|
| **SLSA Build L1** | Documented build process; provenance generated | Basic provenance — consumers know how artifact was built |
| **SLSA Build L2** | Hosted build platform generates provenance; signed provenance | Provenance is harder to falsify; audit trail |
| **SLSA Build L3** | Hardened, isolated build platform; non-falsifiable provenance | Strong tamper resistance; build environment integrity |

*Previous SLSA 4 requirements (two-party review, hermetic/reproducible builds) are now tracked separately under the Source track.*

### SLSA Provenance Attestation (in-toto format)

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "my-app-v1.0.0.tar.gz",
      "digest": {"sha256": "abc123def456..."}
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/actions/runner"
    },
    "buildType": "https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/generic/README.md",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/myorg/myrepo@refs/heads/main",
        "digest": {"sha1": "abc123..."},
        "entryPoint": ".github/workflows/release.yml"
      }
    },
    "metadata": {
      "buildInvocationId": "https://github.com/myorg/myrepo/actions/runs/123",
      "completeness": {"parameters": true, "environment": true, "materials": true},
      "reproducible": false
    },
    "materials": [
      {
        "uri": "git+https://github.com/myorg/myrepo",
        "digest": {"sha1": "abc123..."}
      }
    ]
  }
}
```

### GitHub Actions SLSA Provenance Generator

```yaml
# .github/workflows/release.yml
name: Release with SLSA Provenance

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4 pinned

      - name: Build artifact
        run: |
          make release
          echo "hashes=$(sha256sum ./dist/*.tar.gz | base64 -w0)" >> "$GITHUB_OUTPUT"

  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.10.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true
```

### Verifying SLSA Provenance

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.4.1

# Verify an artifact with its provenance attestation
slsa-verifier verify-artifact my-app-v1.0.0.tar.gz \
  --provenance-path my-app-v1.0.0.tar.gz.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.0.0
```

---

## Sigstore Ecosystem

*Source: [sigstore.dev](https://sigstore.dev) | [github.com/sigstore](https://github.com/sigstore)*

Sigstore provides free, open-source infrastructure for code signing and transparency — eliminating the need for developers to manage long-lived private keys.

### Components

| Component | Role |
|---|---|
| **Cosign** | Container image and arbitrary artifact signing/verification |
| **Fulcio** | OIDC-based certificate authority — issues short-lived certificates tied to OIDC identity (no long-lived private keys) |
| **Rekor** | Immutable transparency log for signed artifacts (like Certificate Transparency, but for software artifacts) |
| **Gitsign** | Sign git commits using your OIDC identity instead of a GPG key |
| **Policy Controller** | Kubernetes admission controller enforcing image signature policies |

---

### Keyless Signing (GitHub Actions — Recommended)

```yaml
jobs:
  sign-and-push:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # Required for OIDC token
      packages: write

    steps:
      - name: Install Cosign
        uses: sigstore/cosign-installer@9614fae9e5c5ead4b9f48dcce21ec0e0d8f4a4cd  # v3.3.0

      - name: Build and push container
        id: build
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Sign artifact with cosign (keyless)
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Verify signature
        run: |
          cosign verify \
            --certificate-identity "https://github.com/${{ github.workflow_ref }}" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            ghcr.io/${{ github.repository }}:${{ github.sha }}
```

---

### Traditional Key-Based Signing

```bash
# Generate key pair (stores encrypted private key locally)
cosign generate-key-pair
# Output: cosign.key (private, encrypted) + cosign.pub (public)

# Sign a container image
cosign sign --key cosign.key docker.io/myorg/myapp:v1.0

# Verify container image signature
cosign verify --key cosign.pub docker.io/myorg/myapp:v1.0

# Sign arbitrary artifact (binary, SBOM, provenance)
cosign sign-blob --key cosign.key myapp-v1.0.tar.gz > myapp-v1.0.tar.gz.sig

# Verify artifact signature
cosign verify-blob \
  --key cosign.pub \
  --signature myapp-v1.0.tar.gz.sig \
  myapp-v1.0.tar.gz

# Attach SBOM to container image in OCI registry
cosign attach sbom --sbom sbom.spdx.json ghcr.io/myorg/myapp:v1.0

# Download and verify attached SBOM
cosign download sbom ghcr.io/myorg/myapp:v1.0
```

---

### Rekor Transparency Log

```bash
# Search Rekor for entries related to a specific artifact
rekor-cli search --sha $(sha256sum myapp.tar.gz | awk '{print $1}')

# Retrieve a specific Rekor log entry
rekor-cli get --uuid <entry-uuid>

# Verify an artifact is in the Rekor log
cosign verify-blob \
  --key cosign.pub \
  --signature artifact.sig \
  --bundle rekor-bundle.json \  # Rekor inclusion proof
  artifact.bin
```

---

### Gitsign — Sign Git Commits with OIDC

```bash
# Install gitsign
go install github.com/sigstore/gitsign@latest

# Configure git to use gitsign
git config --global commit.gpgsign true
git config --global gpg.x509.program gitsign
git config --global gpg.format x509

# Commits now signed with your OIDC identity (browser flow)
git commit -m "feat: signed commit"

# Verify commit signature
git log --show-signature -1

# Batch verify all commits
gitsign verify --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com
```

---

## CI/CD Pipeline Security

### GitHub Actions Hardening

```yaml
# BAD: tag-based pinning — tags are mutable and can be moved
- uses: actions/checkout@v4

# GOOD: pin to full commit SHA — immutable
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

# Minimal permissions — principle of least privilege
permissions:
  contents: read       # Only what's absolutely needed
  packages: write      # Add only what the job requires
  id-token: write      # Only if using OIDC

# OIDC-based cloud authentication (no long-lived secrets)
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/github-actions-deployer
    aws-region: us-east-1

# Restrict workflow triggers
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# Protect against script injection via environment variable
- name: Process PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "Processing: $PR_TITLE"   # Safe: variable not interpolated into shell
    # NEVER: run: echo "Processing: ${{ github.event.pull_request.title }}"
```

**Tools for GitHub Actions hardening**:

```bash
# actionlint — static analysis for GitHub Actions workflows
actionlint .github/workflows/*.yml

# zizmor — security-focused GitHub Actions scanner
pip install zizmor
zizmor .github/workflows/

# OpenSSF Scorecard — check repo security posture
scorecard --repo github.com/myorg/myrepo
```

---

### Dependency Pinning

```bash
# npm: install exact versions + commit lockfile
npm install --save-exact
# package.json: "requests": "2.31.0" not "^2.31.0"

# Python: hash-pinning with pip-tools
pip install pip-tools
pip-compile --generate-hashes requirements.in
# Generates requirements.txt with entries like:
# requests==2.31.0 \
#     --hash=sha256:58cd2187423839ac5e15a56dd6b57... \
#     --hash=sha256:942c5a758f98d790eaed1a29cb6efe...

# Install with hash verification
pip install --require-hashes -r requirements.txt

# Docker: pin base images to digest (tags are mutable)
# BAD
FROM python:3.11-slim

# GOOD — tag + digest
FROM python:3.11.7-slim@sha256:e5a0f55d9c0f3f2a9e9c5b...

# Use docker pull to get current digest
docker pull python:3.11-slim
docker inspect python:3.11-slim | jq '.[0].RepoDigests'
```

---

### Secret Scanning in CI

```bash
# trufflehog — scan for verified leaked secrets in git history
trufflehog git https://github.com/org/repo --only-verified --fail

# Scan local repo
trufflehog git file://. --only-verified

# Scan a specific commit range
trufflehog git file://. --since-commit abc123 --branch main --fail

# detect-secrets — pre-commit hook approach
pip install detect-secrets
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline  # Review and mark false positives
```

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.70.3
    hooks:
      - id: trufflehog
        name: TruffleHog
        entry: trufflehog git file://. --only-verified --fail
        language: system
        pass_filenames: false
```

---

### Software Composition Analysis (SCA) in CI

```yaml
# GitHub Actions: Dependency Review (blocks PRs adding vulnerable deps)
- name: Dependency Review
  uses: actions/dependency-review-action@0fa40c55be84c9ff8b1d54e0e6f3ff5d2de0f3f  # v4
  with:
    fail-on-severity: high
    deny-licenses: GPL-2.0, AGPL-3.0

# Snyk in CI
- name: Snyk vulnerability scan
  uses: snyk/actions/python@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: --severity-threshold=high

# OWASP Dependency-Check
- name: OWASP Dependency Check
  uses: dependency-check/Dependency-Check_Action@main
  with:
    project: 'MyApp'
    path: '.'
    format: 'HTML'
    args: --failOnCVSS 7
```

---

## Supply Chain Security Tools Reference

| Tool | Purpose | Source |
|---|---|---|
| **Syft** | SBOM generation for container images, dirs, archives | [github.com/anchore/syft](https://github.com/anchore/syft) |
| **Grype** | SBOM and image vulnerability scanning | [github.com/anchore/grype](https://github.com/anchore/grype) |
| **OSV-Scanner** | Vulnerability scan via Google OSV database | [github.com/google/osv-scanner](https://github.com/google/osv-scanner) |
| **Trivy** | All-in-one scanner: images, SBOM, IaC, secrets | [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| **Cosign** | Container and artifact signing/verification | [github.com/sigstore/cosign](https://github.com/sigstore/cosign) |
| **Rekor** | Immutable software artifact transparency log | [github.com/sigstore/rekor](https://github.com/sigstore/rekor) |
| **Gitsign** | Sign git commits with OIDC identity | [github.com/sigstore/gitsign](https://github.com/sigstore/gitsign) |
| **Dependency-Track** | SBOM lifecycle management and continuous monitoring | [dependencytrack.org](https://dependencytrack.org) |
| **Socket.dev** | npm/PyPI supply chain risk scoring | [socket.dev](https://socket.dev) |
| **deps.dev** | Open source dependency graph and advisory data | [deps.dev](https://deps.dev) |
| **SLSA GitHub Generator** | SLSA L3 provenance generation in GitHub Actions | [github.com/slsa-framework/slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) |
| **slsa-verifier** | Verify SLSA provenance attestations | [github.com/slsa-framework/slsa-verifier](https://github.com/slsa-framework/slsa-verifier) |
| **OpenSSF Scorecard** | Security health score for open source projects | [github.com/ossf/scorecard](https://github.com/ossf/scorecard) |
| **trufflehog** | Secret scanning in git history and files | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| **detect-secrets** | Pre-commit secret detection with baseline management | [github.com/Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) |
| **actionlint** | Static analysis for GitHub Actions workflows | [github.com/rhysd/actionlint](https://github.com/rhysd/actionlint) |
| **zizmor** | Security-focused GitHub Actions workflow scanner | [github.com/woodruffw/zizmor](https://github.com/woodruffw/zizmor) |
| **pip-audit** | Audit Python packages for known vulnerabilities | [github.com/pypa/pip-audit](https://github.com/pypa/pip-audit) |
| **cyclonedx-bom** | Generate CycloneDX SBOMs from Python projects | [github.com/CycloneDX/cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python) |
| **in-toto** | Supply chain integrity framework and attestation | [in-toto.io](https://in-toto.io) |

---

## Regulatory and Framework Mapping

| Regulation / Framework | Relevant Requirements |
|---|---|
| **NIST SP 800-161r1** (C-SCRM) | Risk assessment of ICT suppliers; SCRM plan; supplier screening; monitoring controls |
| **Executive Order 14028** (2021) | SBOM for federal software; secure software development practices; SSDF compliance |
| **NIST SSDF (SP 800-218)** | PW.4 (reusable software); PO.5 (secure build environments); RV.1 (vulnerability identification) |
| **ATT&CK T1195** | Supply Chain Compromise — software supply chain sub-technique T1195.002 |
| **ATT&CK T1554** | Compromise Software Supply Chain (used in SolarWinds, XZ Utils) |
| **CIS Control 16** | Application Software Security — includes secure SDLC and dependency management |
| **ISO/IEC 27001:2022** | A.8.30 (outsourced development); A.5.19 (supplier relationships) |
| **SOC 2 CC9.2** | Vendor and business partner risk assessments including software supply chain |

---

## Quick Reference: Supply Chain Attack Taxonomy

```
Software Supply Chain Attack Vectors
├── Build System Compromise
│   ├── SolarWinds — trojanized build output
│   ├── XZ Utils — malicious build macros in autoconf
│   └── 3CX — compromised signing environment
├── Dependency Confusion
│   └── Public registry name squatting on internal package names
├── Typosquatting / Malicious Packages
│   ├── npm: crossenv, event-stream, lodash variants
│   └── PyPI: ctx, PHPass, requests/colorama impersonators
├── CI/CD Pipeline Compromise
│   ├── Codecov — tampered uploader script
│   └── Malicious GitHub Actions (curl|bash, mutable tags)
├── Maintainer Account Takeover
│   └── Social engineering (XZ Utils), credential theft
└── Update Mechanism Abuse
    └── SolarWinds Orion auto-update delivery mechanism
```

---

## See Also

- [Container Security](CONTAINER_SECURITY_REFERENCE.md) — Docker hardening, Kubernetes security, and related SBOM/SLSA content
- [Secure Coding Reference](SECURE_CODING_REFERENCE.md) — SAST/DAST tools and secure SDLC practices
- [Enterprise Security Pipeline](SECURITY_PIPELINE.md) — End-to-end security lifecycle
- [Frameworks Reference](FRAMEWORKS.md) — NIST, ISO 27001, SOC 2, and other frameworks in detail
