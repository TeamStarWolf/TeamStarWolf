# DevSecOps Reference Library

> A professional, comprehensive reference for integrating security into every phase of the software development lifecycle. Maintained for practitioners, architects, and security champions.

---

## Table of Contents

1. [DevSecOps Fundamentals](#1-devsecops-fundamentals)
2. [SAST & Code Analysis](#2-sast--code-analysis)
3. [SCA & Dependency Security](#3-sca--dependency-security)
4. [Secrets Detection & Management in CI/CD](#4-secrets-detection--management-in-cicd)
5. [CI/CD Pipeline Security](#5-cicd-pipeline-security)
6. [Container & IaC Security](#6-container--iac-security)
7. [DAST & API Testing in Pipelines](#7-dast--api-testing-in-pipelines)
8. [Infrastructure as Code Security Practices](#8-infrastructure-as-code-security-practices)
9. [Software Supply Chain in DevSecOps](#9-software-supply-chain-in-devsecops)
10. [Observability, Compliance & Culture](#10-observability-compliance--culture)

---

## 1. DevSecOps Fundamentals

### Shift-Left Security Philosophy

Shift-left security is the practice of integrating security activities as early in the SDLC as possible — moving security "left" on the timeline toward design and coding phases rather than relegating it to a post-development gate.

**NIST Cost Curve for Defect Remediation:**

| Phase Defect Discovered | Relative Cost to Fix |
|------------------------|----------------------|
| Requirements / Design  | 1x                   |
| Coding                 | 6x                   |
| Integration Testing    | 15x                  |
| System Testing         | 30x                  |
| Production             | 100x                 |

The IBM Systems Sciences Institute study and subsequent NIST research reinforce this exponential cost curve. A vulnerability caught by a pre-commit hook costs minutes of developer time; the same vulnerability reaching production can require incident response, forensics, customer notification, legal fees, and reputational damage worth orders of magnitude more.

**Core Shift-Left Practices:**
- Threat modeling during sprint planning and design reviews
- Security unit tests alongside functional unit tests
- Pre-commit hooks for secrets scanning and linting
- IDE plugins (Snyk, SonarLint, Semgrep VSCode extension) providing real-time feedback
- Mandatory security training before developers commit to production codebases
- Security acceptance criteria in user stories (Definition of Done includes security)
- Developer-accessible security dashboards (not just security team dashboards)

---

### DevSecOps Maturity Models

#### BSIMM v14 (Building Security In Maturity Model)

BSIMM is a data-driven model built from observing real software security initiatives at over 130 firms. It describes what organizations actually do, not just what they should do.

**4 Domains:**
1. **Governance** — strategy, metrics, compliance, and executive engagement
2. **Intelligence** — attack models, security features and design, standards and requirements
3. **SSDL Touchpoints** — architecture analysis, code review, security testing
4. **Deployment** — penetration testing, software environment, configuration and vulnerability management

**12 Practices (3 per domain):**

| Domain | Practice |
|--------|----------|
| Governance | Strategy & Metrics (SM), Compliance & Policy (CP), Training (T) |
| Intelligence | Attack Models (AM), Security Features & Design (SFD), Standards & Requirements (SR) |
| SSDL Touchpoints | Architecture Analysis (AA), Code Review (CR), Security Testing (ST) |
| Deployment | Penetration Testing (PT), Software Environment (SE), Configuration Mgmt & Vulnerability Mgmt (CMVM) |

Each practice contains activities scored by prevalence. BSIMM scores help organizations benchmark against their industry vertical (FinSrv, ISV, Healthcare, IoT).

#### OWASP SAMM 2.0 (Software Assurance Maturity Model)

SAMM provides a measurable, actionable framework for building and improving software security programs.

**5 Business Functions:**
1. **Governance** — organizational management, policy, and education
2. **Design** — threat assessment, security requirements, security architecture
3. **Implementation** — secure build, secure deployment, defect management
4. **Verification** — architecture assessment, requirements-driven testing, security testing
5. **Operations** — incident management, environment management, operational management

**15 Security Practices** (3 per function), each with **Maturity Levels 0-3:**
- Level 0: Practice not performed
- Level 1: Initial understanding and ad hoc performance
- Level 2: Increased efficiency and/or effectiveness of the practice
- Level 3: Comprehensive mastery at scale

SAMM assessments produce a scorecard that feeds roadmap planning. The SAMM Toolbox (Excel) and SAMMwise web application automate scoring.

---

### Security Gates vs. Guardrails

| Aspect | Security Gate (Blocking) | Security Guardrail (Advisory) |
|--------|--------------------------|-------------------------------|
| Behavior | Fails the pipeline / blocks merge | Warns but allows continuation |
| Use case | Critical/High findings, policy violations | Medium/Low findings, style issues |
| Risk | Can slow velocity if miscalibrated | May be ignored if not tracked |
| Best for | CVSS Critical + confirmed vulns, secret exposure | New findings under triage, informational |

**Recommended approach:** Start with guardrails to build data, tune false positive rates, then progressively promote categories to gates as confidence grows. Gate on: any secret in code, any CRITICAL CVSS in direct dependencies, any known-exploited CVE (CISA KEV list).

---

### Threat Modeling in SDLC

#### STRIDE Methodology

STRIDE is a per-component threat enumeration methodology developed at Microsoft.

| Threat | Violates | Example |
|--------|----------|---------|
| **S**poofing | Authentication | Attacker impersonates a user or service |
| **T**ampering | Integrity | Attacker modifies data in transit or at rest |
| **R**epudiation | Non-repudiation | User denies performing an action with no audit trail |
| **I**nformation Disclosure | Confidentiality | Verbose error messages expose stack traces |
| **D**enial of Service | Availability | Unauthenticated endpoint triggers expensive computation |
| **E**levation of Privilege | Authorization | User accesses admin functionality via IDOR |

**STRIDE Process:**
1. Draw a Data Flow Diagram (DFD) with trust boundaries
2. Enumerate STRIDE threats per component and data flow
3. Rate each threat (DREAD or CVSS-like scoring)
4. Define mitigations and assign to owners
5. Validate mitigations in code review and testing

#### PASTA (Process for Attack Simulation and Threat Analysis) — 7 Stages

1. **Define Objectives** — business impact analysis, regulatory scope
2. **Define Technical Scope** — system components, APIs, data stores
3. **Application Decomposition** — DFDs, trust boundaries, entry/exit points
4. **Threat Analysis** — threat intelligence, threat actor profiling
5. **Vulnerability & Weakness Analysis** — existing scan results, CVE mapping
6. **Attack Modeling** — attack trees, kill chain mapping
7. **Risk & Impact Analysis** — risk rating, residual risk acceptance

#### Risk Rating Matrix

| Likelihood vs Impact | Low | Medium | High | Critical |
|---------------------|-----|--------|------|----------|
| Very Likely         | Medium | High | Critical | Critical |
| Likely              | Low | Medium | High | Critical |
| Unlikely            | Low | Low | Medium | High |
| Very Unlikely       | Info | Low | Low | Medium |

---

### Developer Security Training Programs

| Platform | Format | Strengths |
|----------|--------|-----------|
| **OWASP WebGoat** | Self-hosted vulnerable app | Free, hands-on, covers OWASP Top 10 |
| **Secure Code Warrior** | Role-based gamified training | Language-specific, tournament mode, LMS integration |
| **HackEdu** | Secure coding challenges | Language-aware, real code snippets |
| **SANS SEC522** | Instructor-led course | Deep web app security, 5-day intensive |
| **OWASP SKF** | Self-hosted + labs | Security Knowledge Framework with code examples |

**Training Cadence Recommendation:**
- Onboarding: 8-hour foundational secure coding course
- Annual: 4-hour refresher with current threat landscape
- Role-specific: AppSec champions get 40+ hours/year
- Just-in-time: Contextual training triggered by SAST findings (Secure Code Warrior integration)

---

### Security Champions Program Design

**Selection Criteria:** Volunteer (not assigned), respected developer peer, technical competence, security curiosity, communication skills.

**Training Curriculum (Recommended 40-hour path):**
- OWASP Top 10 Web + API in depth (8h)
- Threat modeling facilitation (4h)
- SAST/DAST tool operation (4h)
- Secure code review techniques (8h)
- Cryptography fundamentals (4h)
- Incident response basics (4h)
- Cloud security fundamentals (4h)
- AppSec architecture patterns (4h)

**Champion Responsibilities:** Facilitate sprint threat models, triage SAST findings, advocate for security in backlog grooming, lead security retrospectives, represent team in security guild.

**Recognition:** Dedicated conference budget ($2K+/year), security certification sponsorship, visible credit in security reports, career ladder acknowledgment.

---

### Measuring DevSecOps Maturity — KPIs

| KPI | Formula | Target |
|-----|---------|--------|
| SAST scan coverage | Repos with SAST / Total repos x 100 | >= 95% |
| Mean Time to Remediate (Critical) | Avg(patch_date - discovery_date) for CVSS >= 9.0 | <= 24 hours |
| Mean Time to Remediate (High) | Avg for CVSS 7.0-8.9 | <= 7 days |
| Vulnerability escape rate | Vulns found in prod / Total vulns found x 100 | <= 5% |
| Security training completion | Devs completed training / Total devs x 100 | >= 90% |
| False positive rate | FP SAST findings / Total SAST findings x 100 | <= 20% |
| Security gate bypass rate | Pipeline overrides / Total gate failures x 100 | <= 2% |

---
## 2. SAST & Code Analysis

### SAST Tool Comparison

Static Application Security Testing analyzes source code, bytecode, or binary without executing the program to find security defects.

| Tool | Languages | Deployment | Strength |
|------|-----------|------------|----------|
| Semgrep | 30+ | Cloud + self-hosted | Fast, custom rules, OSS community rules |
| SonarQube | 29 | Self-hosted / SonarCloud | Quality + security combined, branch analysis |
| CodeQL | 10 | GitHub-native / self-hosted | Deep semantic analysis, complex queries |
| Checkmarx SAST | 35+ | Cloud + on-prem | Enterprise workflow, SDLC integration |
| Veracode Static | 20+ | SaaS | Policy-based, compliance reporting |

---

### Semgrep

**Basic scan:**
```bash
semgrep --config p/security-audit --config p/owasp-top-ten ./src
semgrep --config p/python ./src --json > semgrep-results.json
```

**Custom rule syntax (YAML):**
```yaml
rules:
  - id: hardcoded-secret-env-bypass
    patterns:
      - pattern: os.environ["SECRET"] = "..."
    message: "Hardcoded secret assigned to environment variable"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-798

  - id: sql-injection-format-string
    patterns:
      - pattern: cursor.execute($QUERY % ...)
      - pattern-not: cursor.execute($QUERY % ($SAFE, ...))
    message: "Potential SQL injection via string formatting"
    languages: [python]
    severity: ERROR
```

**Taint tracking rule:**
```yaml
rules:
  - id: flask-taint-sqli
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: cursor.execute(...)
    message: "User-controlled input flows into SQL query"
    languages: [python]
    severity: ERROR
```

Community rulesets: `p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/kotlin`, `p/react`, `p/django`. Browse at semgrep.dev/r.

---

### SonarQube

**sonar-project.properties:**
```properties
sonar.projectKey=my-org_my-project
sonar.organization=my-org
sonar.sources=src
sonar.tests=tests
sonar.python.coverage.reportPaths=coverage.xml
sonar.exclusions=**/node_modules/**,**/vendor/**
sonar.coverage.exclusions=**/*test*/**
```

**Quality Gate configuration (SonarQube API):**
```bash
# Create custom quality gate
curl -X POST "https://sonar.example.com/api/qualitygates/create"   -u admin:password -d "name=DevSecOps-Gate"

# Add condition: block on any new blocker/critical security issue
curl -X POST "https://sonar.example.com/api/qualitygates/create_condition"   -u admin:password   -d "gateId=3&metric=new_security_rating&op=GT&error=1"
```

**Security Hotspots vs Vulnerabilities:**
- **Vulnerability**: Confirmed security issue requiring immediate action
- **Security Hotspot**: Suspicious code requiring human review to determine if exploitable
- Hotspots use a review workflow (To Review > Acknowledged/Fixed/Safe) distinct from the vulnerability fix workflow

Branch analysis (Developer Edition+): Analyzes feature branches independently; PR decoration posts findings as comments; new code period tracks delta.

---

### CodeQL

**Database creation and analysis:**
```bash
# Create database for Python project
codeql database create my-db --language=python --source-root=.

# Analyze with security queries
codeql analyze my-db python-security-and-quality.qls   --format=sarif-latest --output=results.sarif

# Run specific query pack
codeql analyze my-db   codeql/python-queries:Security/CWE-089/SqlInjection.ql   --format=sarif-latest --output=sqli.sarif
```

**Custom QL query:**
```ql
import python
import semmle.python.security.dataflow.SqlInjection

from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection from $@", source.getNode(), "user-controlled input"
```

**GitHub Advanced Security code scanning setup (.github/workflows/codeql.yml):**
```yaml
name: CodeQL Analysis
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python, javascript
          queries: security-and-quality
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:python"
          output: results/
          upload: true
```

---

### GitHub Advanced Security Features

**Secret Scanning:**
- Auto-enabled for all public repos and GHAS-licensed private repos
- Partner program: 100+ token types with provider-side revocation on detection
- Custom patterns: regex-based patterns with up to 10 test strings
- Push protection: blocks pushes containing detected secrets

**Custom secret pattern:**
```json
{
  "name": "Internal API Token",
  "secret_type": "internal_api_token",
  "pattern": "INT-[A-Z0-9]{32}",
  "test_string": "INT-ABCDEFGH12345678IJKLMNOP90QRST"
}
```

**Dependency review action:**
```yaml
- uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: high
    deny-licenses: GPL-2.0, AGPL-3.0
    comment-summary-in-pr: always
```

---

### GitLab SAST Integration

```yaml
# .gitlab-ci.yml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml

variables:
  SAST_EXCLUDED_PATHS: "spec, test, tests, tmp"
  SAST_SEVERITY_LEVEL: "medium"

sast:
  stage: test
  variables:
    SEARCH_MAX_DEPTH: 10
```

GitLab runs language-specific analyzers: Bandit (Python), ESLint (JS), SpotBugs (Java/Scala/Groovy), Semgrep (multi), Flawfinder (C/C++).

---

### SARIF Format for Interoperability

SARIF (Static Analysis Results Interchange Format) is the OASIS standard for sharing static analysis results across tools and platforms.

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "MyScanner",
        "rules": [{"id": "SQL001", "name": "SqlInjection"}]
      }
    },
    "results": [{
      "ruleId": "SQL001",
      "level": "error",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "src/db.py"},
          "region": {"startLine": 42}
        }
      }]
    }]
  }]
}
```

SARIF is consumed by GitHub (code scanning alerts), Azure DevOps, and SARIF viewers.

---

### False Positive Management Workflow

1. **Triage queue**: All new findings enter a triage queue (not directly assigned as bugs)
2. **Classifier review**: Security champion reviews within SLA (Critical: same day; High: 3 days)
3. **Disposition options**: Confirmed -> Jira ticket with severity SLA; False Positive -> suppress with justification comment; Accepted Risk -> risk register entry with owner sign-off
4. **Suppression syntax:**
```python
result = cursor.execute(query)  # nosemgrep: sql-injection-format-string
# Justification: query is a compile-time constant, never user-controlled
```
5. **Suppression audit**: Monthly review of all suppressions; automated check that suppression comments include justification

**Incremental scanning for PRs:** Scan only changed files and their transitive imports to reduce scan time. Full scan runs nightly on main. Both results feed the same dashboard.

---
## 3. SCA & Dependency Security

### SCA Tool Ecosystem

Software Composition Analysis identifies known vulnerabilities, license issues, and supply chain risks in open-source dependencies — both direct and transitive.

#### Snyk Open Source

```bash
# Scan project dependencies
snyk test --severity-threshold=high --json > snyk-results.json

# Monitor project (uploads to Snyk dashboard for ongoing monitoring)
snyk monitor --project-name=my-service --org=my-org

# Auto-fix vulnerabilities (creates PR)
snyk fix

# License compliance check
snyk test --license

# Container image SCA
snyk container test myimage:latest --file=Dockerfile
```

**Snyk in GitHub Actions:**
```yaml
- uses: snyk/actions/python@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: --severity-threshold=high --sarif-file-output=snyk.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: snyk.sarif
```

#### OWASP Dependency-Check

```bash
# Standalone scan (downloads NVD data on first run, ~20 min)
dependency-check.sh \
  --project "MyProject" \
  --scan ./src \
  --format HTML \
  --format JSON \
  --out ./reports \
  --failOnCVSS 7

# Maven plugin
mvn org.owasp:dependency-check-maven:check \
  -DfailBuildOnCVSS=7 \
  -Dformat=HTML,JSON

# NVD API key (avoids rate limiting)
dependency-check.sh --nvdApiKey $NVD_API_KEY ...
```

#### Grype

```bash
# Scan container image
grype myimage:latest

# Scan directory
grype dir:.

# Scan from SBOM
grype sbom:./sbom.cyclonedx.json

# Fail on high/critical
grype myimage:latest --fail-on high

# Output SARIF
grype myimage:latest -o sarif > grype.sarif
```

#### OSV-Scanner

```bash
# Recursive scan of project
osv-scanner -r .

# Scan specific lockfile
osv-scanner --lockfile=package-lock.json

# Scan SBOM
osv-scanner --sbom=sbom.spdx.json

# JSON output
osv-scanner -r . --json > osv-results.json
```

OSV-Scanner queries the OSV.dev database which aggregates from GitHub Advisory Database, NVD, PyPI Advisory Database, RustSec, and Go vulnerability database.

#### Socket.dev

Real-time analysis of npm and PyPI packages for:
- Protestware / malicious code injection
- Typosquatting detection
- Install scripts executing network calls
- Dependency confusion risk
- Abandoned maintainer detection

```bash
# CLI
socket scan create --repo . --report-format sarif
```

#### GitHub Dependabot

**.github/dependabot.yml:**
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    groups:
      development-dependencies:
        dependency-type: "development"
    ignore:
      - dependency-name: "aws-sdk"
        update-types: ["version-update:semver-major"]

  - package-ecosystem: "pip"
    directory: "/backend"
    schedule:
      interval: "daily"
    reviewers:
      - "security-team"
    labels:
      - "security"
      - "dependencies"
```

---

### Vulnerability Sources

| Source | Coverage |
|--------|----------|
| NVD (NIST) — nvd.nist.gov | CVEs with CVSS scores |
| GitHub Advisory DB — github.com/advisories | GHSA IDs, package-specific |
| OSV.dev — osv.dev | Unified schema, 20+ ecosystems |
| Snyk Vuln DB — security.snyk.io | Curated, earlier disclosure |
| VulnDB (Risk Based) | Commercial, broadest coverage |

---

### Transitive Dependency Risk

Direct dependencies typically represent only 10-20% of the total dependency tree. Transitive (indirect) dependencies carry equal risk.

```bash
# Visualize full npm dependency tree
npm ls --all 2>/dev/null | head -100

# Specific package path
npm ls lodash

# Maven dependency tree
mvn dependency:tree -Dverbose -Dincludes=log4j

# Snyk with full tree
snyk test --print-deps

# Gradle
./gradlew dependencies --configuration runtimeClasspath
```

**Risk factors for transitive deps:**
- Deeply nested (hard to patch — must wait for intermediate package update)
- Unmaintained intermediate packages blocking security updates
- Version conflicts causing older vulnerable versions to be selected

**Mitigation:** Use lockfiles to pin exact transitive versions; enable Dependabot for transitive updates; use `overrides` (npm) or `resolutions` (yarn) to force patched versions when intermediaries are slow.

---

### License Compliance Automation

| License | Commercial Use | Copyleft | Risk Level |
|---------|---------------|----------|------------|
| MIT | Yes | No | Low |
| Apache 2.0 | Yes | No | Low |
| BSD 2/3 Clause | Yes | No | Low |
| LGPL 2.1/3 | Yes (with care) | Weak | Medium |
| GPL 2.0/3.0 | Restricted | Strong | High |
| AGPL 3.0 | SaaS triggers copyleft | Strong | Very High |
| SSPL | Cloud service triggers | Strong | Very High |

```bash
# FOSSA CLI
fossa analyze
fossa test --config .fossa.yml

# Scancode-toolkit
scancode -l -r --json-pp results.json ./src

# License Finder
license_finder --decisions-file doc/dependency_decisions.yml
```

SPDX 2.3 defines compound expressions: `MIT AND Apache-2.0`, `GPL-2.0-only OR MIT`, `LicenseRef-custom`. Tools like `spdx-tools` validate these expressions.

---

### Dependency Confusion Attack Mitigations

Dependency confusion occurs when an attacker publishes a public package with the same name as a private internal package at a higher version, causing package managers to pull the malicious public version.

**Mitigations:**

```ini
# .npmrc — always prefer internal registry for scoped packages
@myorg:registry=https://registry.internal.example.com/
//registry.internal.example.com/:_authToken=${NPM_TOKEN}
```

```ini
# pip.conf — require internal index
[global]
index-url = https://pypi.internal.example.com/simple/
# Avoid extra-index-url which falls through to public PyPI
```

**Artifactory/Nexus controls:**
- Enable "exclude patterns" to block public resolution of internal package names
- Use virtual repositories with priority ordering, internal first
- Enable "block requests on namespace collision"

---

### Lockfile Security

```bash
# npm — install only from lockfile, no network modification
npm ci --ignore-scripts

# pip — verify hashes (add with pip-compile --generate-hashes)
pip install -r requirements.txt --require-hashes

# Verify lockfile integrity
npm audit signatures  # verifies registry signatures on installed packages
```

Lockfile tampering detection: Use git hooks or CI checks to verify lockfile was not modified without corresponding package manifest change. Tools: `lockfile-lint` for npm.

---

### SBOM Generation and Attestation

```bash
# cdxgen — CycloneDX SBOM for multiple ecosystems
cdxgen -o sbom.cyclonedx.json -t python .
cdxgen -o sbom.cyclonedx.json -t npm .

# syft — SBOM for containers and filesystems
syft myimage:latest -o cyclonedx-json > sbom.cyclonedx.json
syft dir:. -o spdx-json > sbom.spdx.json

# Attach SBOM attestation with Cosign
cosign attest --predicate sbom.cyclonedx.json \
  --type cyclonedx \
  myimage:latest
```

**NTIA Minimum Elements for SBOMs:**
1. Supplier name
2. Component name
3. Version
4. Other unique identifiers (PURL, CPE)
5. Dependency relationships
6. Author of SBOM data
7. Timestamp

---
## 4. Secrets Detection & Management in CI/CD

### Pre-Commit Hook Tools

Detecting secrets before they are committed is the most cost-effective prevention. Pre-commit hooks execute locally on the developer's machine.

#### git-secrets (AWS Labs)

```bash
# Install and configure
brew install git-secrets
git secrets --install     # install hooks in current repo
git secrets --register-aws  # add AWS secret patterns

# Manual scan
git secrets --scan
git secrets --scan-history  # scan entire git history

# Add custom pattern
git secrets --add 'INT-[A-Z0-9]{32}'
git secrets --add --literal 'my-actual-secret-value'
```

#### Gitleaks

```bash
# Detect secrets in working directory
gitleaks detect --source . --verbose

# Detect in git log
gitleaks detect --source . --log-opts="--all"

# Generate baseline (allow existing findings)
gitleaks detect --source . --baseline-path .gitleaks-baseline.json --report-path report.json

# Protect pre-commit (staged files only)
gitleaks protect --staged

# In CI
gitleaks detect --source . --exit-code 1
```

**.gitleaks.toml configuration:**
```toml
[extend]
useDefault = true  # use built-in ruleset

[[rules]]
id = "custom-internal-token"
description = "Internal API Token"
regex = "INT-[A-Z0-9]{32}"
entropy = 3.5
keywords = ["INT-"]

[allowlist]
commits = ["abc123def456"]  # known safe commits
paths = ["(?i)test", "\.md$"]  # test files, docs
```

#### detect-secrets

```bash
# Create baseline (all current findings become baseline)
detect-secrets scan > .secrets.baseline

# Audit baseline (review each finding)
detect-secrets audit .secrets.baseline

# Scan and fail on new secrets not in baseline
detect-secrets scan --baseline .secrets.baseline
```

**.pre-commit-config.yaml:**
```yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

#### truffleHog

```bash
# Scan current repo
trufflehog git file://.

# Scan remote repo
trufflehog github --repo https://github.com/org/repo

# Scan with depth limit
trufflehog git file://. --since-commit HEAD~100

# Only verified secrets (reduces FPs via live API validation)
trufflehog git file://. --only-verified

# Scan S3 bucket
trufflehog s3 --bucket=my-bucket

# JSON output
trufflehog git file://. --json
```

---

### GitHub Secret Scanning

Auto-enabled for all public repositories and GHAS-licensed private repositories.

**Partner Program:** 100+ token types; when detected, GitHub notifies the provider (AWS, GCP, Slack, Stripe, etc.) who can immediately revoke the exposed credential.

**Push Protection:** Blocks pushes containing detected secrets before they reach the repository. Developer sees a blocking message with remediation options. Bypass requires choosing a reason (creates audit trail and security alert).

**Custom Patterns (Organization or Repository level):**
```
Pattern name: Internal Service Token
Pattern: INT-[A-Z]{4}-[0-9]{8}-[A-Z0-9]{16}
Test string: INT-AUTH-20240101-ABC1234567890XYZ
```

---

### Historical Repository Scanning

When secrets may have been committed historically:

```bash
# trufflehog — scan all branches and tags
trufflehog git file://. --log-opts="--all" --json | jq .

# gitleaks — scan full history
gitleaks detect --source . --log-opts="--all" --report-path history-report.json

# Remove file from history after secret found (BFG Repo Cleaner)
java -jar bfg.jar --delete-files secret-config.py
git reflog expire --expire=now --all && git gc --prune=now --aggressive
# Coordinate force push with team before executing
```

**Important:** Rotating credentials is mandatory. History rewriting is supplementary — assume the secret is compromised from the moment it was committed to any shared repository.

---

### Common Secret Types & Detection Patterns

| Secret Type | Pattern Example | Notes |
|-------------|----------------|-------|
| AWS Access Key ID | AKIA[A-Z0-9]{16} | Always 20 chars starting AKIA |
| AWS Secret Access Key | [A-Za-z0-9/+=]{40} | High entropy 40-char string |
| GitHub PAT (classic) | ghp_[A-Za-z0-9]{36} | Personal access token |
| GitHub OAuth token | gho_[A-Za-z0-9]{36} | OAuth token |
| GitHub App user token | ghu_[A-Za-z0-9]{36} | User-to-server token |
| GitHub Actions token | ghs_[A-Za-z0-9]{36} | Server-to-server token |
| Private key header | -----BEGIN RSA PRIVATE KEY----- | PEM format |
| DB connection string | Server=.*;Database=.*;User Id=.*;Password= | Multiple variants |
| Slack webhook | https://hooks.slack.com/services/T.../B.../... | Webhook URL format |
| Stripe secret key | sk_live_[A-Za-z0-9]{24,} | Live key prefix |

---

### HashiCorp Vault CI/CD Integration

#### AppRole Authentication

```bash
# Vault setup (one-time)
vault auth enable approle
vault write auth/approle/role/ci-role \
  secret_id_ttl=10m \
  token_num_uses=10 \
  token_ttl=20m \
  token_max_ttl=30m \
  secret_id_num_uses=40

# CI pipeline: get short-lived secret_id
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/ci-role/secret-id)

# Login and get token
VAULT_TOKEN=$(vault write -field=token auth/approle/login \
  role_id=$ROLE_ID secret_id=$SECRET_ID)

# Fetch secret
vault kv get -field=api_key secret/ci/external-api
```

#### Dynamic Secrets (Database)

```bash
# Vault auto-generates short-lived DB credentials
vault read database/creds/my-role
# Returns: username=v-ci-abc123, password=A1B2C3..., lease_duration=1h
# Credentials expire automatically — no manual rotation required
```

#### GitHub Actions + Vault

```yaml
- uses: hashicorp/vault-action@v3
  with:
    url: https://vault.example.com
    method: approle
    roleId: ${{ secrets.VAULT_ROLE_ID }}
    secretId: ${{ secrets.VAULT_SECRET_ID }}
    secrets: |
      secret/data/ci/deploy api_key | DEPLOY_API_KEY ;
      database/creds/readonly username | DB_USER ;
      database/creds/readonly password | DB_PASS
```

---

### AWS Secrets Manager in Pipelines

```python
import boto3, json
client = boto3.client('secretsmanager', region_name='us-east-1')
secret = json.loads(
    client.get_secret_value(SecretId='prod/myservice/dbcreds')['SecretString']
)
DB_PASSWORD = secret['password']
```

**GitHub Actions (OIDC -> AWS Secrets Manager — no static keys):**
```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/github-actions-role
    aws-region: us-east-1
- name: Get secret
  run: |
    SECRET=$(aws secretsmanager get-secret-value \
      --secret-id prod/myservice/apikey \
      --query SecretString --output text)
    echo "API_KEY=$SECRET" >> $GITHUB_ENV
```

---

### Secrets Rotation Automation

**Rotation pattern — AWS Lambda + Secrets Manager:**
1. Secrets Manager triggers Lambda on rotation schedule
2. Lambda: `createSecret` -> generate new credential at target service
3. Lambda: `setSecret` -> store new credential in Secrets Manager (staging)
4. Lambda: `testSecret` -> validate new credential works
5. Lambda: `finishSecret` -> promote staging to current, retire old

**Rotation cadence recommendations:**
- CI/CD service tokens: every 30 days
- Database passwords: every 90 days (or on team member offboarding)
- API keys: per service SLA (many providers support 60-day rotation)
- Certificate private keys: annually or on CA compromise

---
## 5. CI/CD Pipeline Security

### Pipeline Security Principles

**Ephemeral Build Agents:** Every build job runs in a fresh, clean environment. Never reuse build agents across jobs — persistent agents accumulate secrets, caches with malicious content, and state from previous (potentially compromised) builds.

**Least Privilege Pipeline Identities:** Pipeline service accounts and OIDC roles should have only the permissions required for that specific job. Separate read-only roles for test jobs from read-write roles for deployment jobs.

**Signed Artifacts with Provenance:** Every artifact that flows through the pipeline should be signed and accompanied by a provenance attestation describing how it was built.

**No Secrets in Environment Variables:** Secrets in env vars are readable by all process children and appear in crash dumps. Use Vault, AWS Secrets Manager, or similar — fetch at use time, not at job start.

---

### GitHub Actions Security Hardening

#### Permissions Block (Principle of Least Privilege)

```yaml
# Default to no permissions; grant minimally per job
permissions: {}

jobs:
  build:
    permissions:
      contents: read
      packages: write
  security-scan:
    permissions:
      security-events: write
      contents: read
  deploy:
    permissions:
      id-token: write   # required for OIDC
      contents: read
```

#### OIDC Federation — Eliminate Long-Lived Cloud Keys

```yaml
# GitHub Actions -> AWS (no static AWS keys stored anywhere)
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/github-oidc-role
    aws-region: us-east-1
    role-session-name: github-actions-${{ github.run_id }}

# GitHub Actions -> GCP
- uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: projects/123/locations/global/workloadIdentityPools/github/providers/github
    service_account: deploy@project.iam.gserviceaccount.com

# GitHub Actions -> Azure
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

**AWS IAM trust policy for GitHub OIDC:**
```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
    }
  }
}
```

#### Action Pinning to Full SHA

```yaml
# Insecure — tag can be moved to malicious commit
- uses: actions/checkout@v4

# Secure — immutable reference
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

Use Dependabot to keep pinned SHA actions up to date automatically via `.github/dependabot.yml` with `package-ecosystem: "github-actions"`.

#### Environment Protection Rules

```yaml
jobs:
  deploy-production:
    environment:
      name: production
      url: https://app.example.com
    # GitHub environment configured with:
    # - Required reviewers: security-team, lead-engineer
    # - Deployment branches: main only
    # - Wait timer: 5 minutes (time to cancel)
    runs-on: ubuntu-latest
```

#### Reusable Workflows for Centralized Security Controls

```yaml
# Centralized security workflow (org/.github/workflows/security-scan.yml)
on:
  workflow_call:
    inputs:
      language:
        required: true
        type: string

# Consuming workflow in any repo
jobs:
  security:
    uses: myorg/.github/workflows/security-scan.yml@main
    with:
      language: python
    secrets: inherit
```

#### CODEOWNERS for Security-Critical Files

```
# .github/CODEOWNERS
/.github/workflows/    @myorg/security-team
/infrastructure/       @myorg/security-team @myorg/platform-team
/src/auth/             @myorg/security-team
*.tf                   @myorg/platform-team
```

---

### GitLab CI Security

```yaml
# Protected variables: set in UI as "masked" — not shown in logs
# Protected branches: only maintainers can push to main

# Limiting job token scope
job:
  variables:
    CI_JOB_TOKEN_SCOPE_ENABLED: "true"

# Protected runners for sensitive jobs
deploy-prod:
  tags:
    - protected  # only runs on runners tagged 'protected'
  environment: production
```

---

### Jenkins Security

```groovy
// Credential binding — credentials never exposed as plain env var
withCredentials([
  usernamePassword(credentialsId: 'aws-creds',
    usernameVariable: 'AWS_ACCESS_KEY_ID',
    passwordVariable: 'AWS_SECRET_ACCESS_KEY'),
  string(credentialsId: 'api-token', variable: 'API_TOKEN')
]) {
  sh 'aws s3 cp artifact.zip s3://my-bucket/'
}
// Credentials masked in build log after this block
```

**Script Security Plugin:** Groovy scripts in Jenkinsfiles run in a sandbox. Unsafe methods require explicit administrator approval. Avoid `@Grab` and `evaluate()` in pipeline scripts.

**Agent-to-Controller Security:** Enable "Agent -> Master Access Control" in Jenkins security settings. Agents should not be able to read arbitrary files from the controller or modify configurations.

---

### Supply Chain Attacks on CI/CD — Historical Examples

| Incident | Year | Attack Vector | Impact |
|----------|------|--------------|--------|
| SolarWinds SUNBURST | 2020 | Build system compromise; malicious code injected into Orion builds | 18,000+ organizations; US government agencies |
| Codecov bash uploader | 2021 | Attacker modified uploaded script; CI pipelines curl'd malicious version | Credentials exfiltrated from 29,000+ companies |
| event-stream npm | 2018 | Malicious maintainer added crypto-stealing payload via transitive dep | Targeted Bitcoin wallet apps |
| ua-parser-js | 2021 | npm account hijack; malware published to popular package | Cryptominer + credential stealer |
| node-ipc | 2022 | Maintainer added protestware wiping files for Russian/Belarusian IPs | Supply chain integrity concerns |

**Lessons:**
- Pin action/script versions to immutable references (full SHA, not tags)
- Verify checksums of downloaded scripts before executing
- Use SBOM attestation to detect tampering
- Never `curl | bash` from external sources in CI without verification

---

### SLSA Framework for Build Integrity

SLSA (Supply chain Levels for Software Artifacts) provides a graduated security framework for build systems.

| Level | Requirements |
|-------|-------------|
| Build L1 | Provenance exists in standard format |
| Build L2 | Signed provenance from hosted build platform |
| Build L3 | Hardened isolated build environment; provenance non-falsifiable |

**GitHub Actions SLSA provenance generation:**
```yaml
provenance:
  needs: build
  permissions:
    actions: read
    id-token: write
    contents: write
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
  with:
    base64-subjects: "${{ needs.build.outputs.digests }}"
    upload-assets: true
```

**Verification:**
```bash
slsa-verifier verify-artifact \
  --provenance-path artifact.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.2.3 \
  artifact.tar.gz
```

---
## 6. Container & IaC Security

### Dockerfile Security Scanning

#### hadolint

```bash
# Scan Dockerfile
hadolint Dockerfile

# In CI with SARIF output
hadolint Dockerfile --format sarif > hadolint.sarif
```

**.hadolint.yaml:**
```yaml
ignore:
  - DL3008  # Allow apt-get without version pinning in dev images
trustedRegistries:
  - docker.io
  - gcr.io
  - 123456789012.dkr.ecr.us-east-1.amazonaws.com
failure-threshold: warning
```

**Common Dockerfile security findings:**

| Rule | Issue | Secure Alternative |
|------|-------|-------------------|
| DL3002 | Last USER is root | Add `USER nonroot` at end of Dockerfile |
| DL3007 | FROM image:latest | Pin to digest: `FROM image@sha256:abc...` |
| DL3009 | apt-get lists not deleted | Add `rm -rf /var/lib/apt/lists/*` |
| DL3015 | apt-get without --no-install-recommends | Add flag to reduce attack surface |
| DL3020 | Use ADD for URLs | Use `COPY` — no auto-extraction/URL fetch |

**Minimal secure Dockerfile pattern:**
```dockerfile
FROM python:3.12-slim@sha256:abc123def456...

# Non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copy requirements first (layer caching optimization)
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Copy source
COPY --chown=appuser:appuser src/ .

# Drop to non-root
USER appuser

EXPOSE 8080
ENTRYPOINT ["python", "app.py"]
```

---

### Container Image Scanning in CI Pipeline

#### Trivy (GitHub Action)

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myimage:${{ github.sha }}'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'
    ignore-unfixed: true

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

#### Snyk Container

```bash
snyk container test myimage:latest \
  --file=Dockerfile \
  --severity-threshold=high \
  --sarif-file-output=snyk-container.sarif

snyk container monitor myimage:latest --project-name=my-service
```

#### Grype

```bash
# Fail build on any critical vulnerability
grype myimage:latest --fail-on critical

# SARIF output
grype myimage:latest -o sarif > grype-results.sarif
```

**Policy configuration (.grype.yaml):**
```yaml
fail-on-severity: high
ignore:
  - vulnerability: CVE-2023-XXXX
    reason: "Not exploitable in our configuration — tracked in issue #1234"
```

---

### Image Signing Workflow — Cosign Keyless

Keyless signing uses ephemeral keys tied to the build identity via OIDC, eliminating the need to manage long-term signing keys.

```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3

- name: Sign image (keyless, using GitHub OIDC)
  run: |
    cosign sign --yes \
      --certificate-identity ${{ github.server_url }}/${{ github.repository }}/.github/workflows/build.yml@${{ github.ref }} \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      myimage:${{ github.sha }}
```

**Verification:**
```bash
cosign verify \
  --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  myimage:latest
```

**How it works:**
1. GitHub Actions OIDC token presented to Fulcio CA (Sigstore's free CA)
2. Fulcio issues short-lived certificate binding the key to the OIDC identity
3. Signature + certificate stored in Rekor transparency log
4. No private key to manage; full audit trail in public append-only log

---

### Kubernetes Admission Control for Supply Chain

#### Kyverno verify-image policy

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "123456789012.dkr.ecr.us-east-1.amazonaws.com/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

---

### IaC Scanning Tools

#### Checkov

```bash
# Scan Terraform directory
checkov -d . --framework terraform --output sarif --output-file-path results/

# Scan specific checks
checkov -f main.tf --check CKV_AWS_20,CKV_AWS_57

# Scan Kubernetes manifests
checkov -d k8s/ --framework kubernetes

# Inline suppression
# checkov:skip=CKV_AWS_20:S3 bucket is intentionally public for static website
```

#### tfsec

```bash
tfsec . --format sarif --out tfsec.sarif
tfsec . --minimum-severity HIGH
tfsec . --exclude aws-s3-enable-versioning
```

#### terrascan

```bash
terrascan scan -i terraform -d . --output sarif > terrascan.sarif
terrascan scan -i k8s -f deployment.yaml
```

#### Snyk IaC

```bash
snyk iac test --severity-threshold=high
snyk iac test main.tf --report
```

---

### Terraform State Security

```hcl
terraform {
  backend "s3" {
    bucket         = "myorg-tfstate-prod"
    key            = "services/myservice/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/abc123"
    dynamodb_table = "terraform-state-lock"
    # No credentials in backend config — use OIDC/instance profile
  }
}
```

**State security rules:**
- Never store state locally in CI (state files contain plaintext secrets)
- Enable S3 versioning + MFA delete for state buckets
- Restrict state bucket access to pipeline roles only
- Enable S3 access logging for audit trail
- Use workspace isolation (separate state files per environment)

---
## 7. DAST & API Testing in Pipelines

### DAST Integration Approaches

Dynamic Application Security Testing tests running applications by sending crafted inputs and analyzing responses, finding runtime vulnerabilities that static analysis cannot detect (authentication flaws, authorization bypasses, session management issues, business logic vulnerabilities).

#### OWASP ZAP

```bash
# API scan against OpenAPI spec (Docker)
docker run --rm -v $(pwd):/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t /zap/wrk/openapi.yaml \
  -f openapi \
  -r zap-report.html \
  -J zap-report.json \
  -x zap-report.xml

# Full site scan
docker run ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t https://staging.example.com \
  -r full-scan-report.html

# GitHub Action
- uses: zaproxy/action-api-scan@v0.7.0
  with:
    target: 'https://staging.example.com/openapi.json'
    format: openapi
    fail_action: true
    rules_file_name: '.zap/rules.tsv'
```

**ZAP rules configuration (.zap/rules.tsv):**
```
10202	IGNORE	Absence of Anti-CSRF Tokens (handled by SPA framework)
10038	WARN	Content Security Policy not set
10098	FAIL	Cross-Domain Misconfiguration
```

#### Burp Suite Enterprise

```bash
# Trigger scan via REST API
curl -X POST https://burp-enterprise.internal/api/v1/scan \
  -H "Authorization: $BURP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_configurations": [{"type": "NamedConfiguration", "name": "API scan"}],
    "urls": ["https://staging.api.example.com"]
  }'
```

#### Nuclei

```bash
# Scan for known CVEs
nuclei -t cves/ -u https://staging.example.com -o nuclei-results.txt

# Technology-specific templates
nuclei -t technologies/ -t misconfigurations/ -u https://staging.example.com

# Scan with severity filter
nuclei -t cves/ -severity critical,high -u https://staging.example.com -json > nuclei.json

# Custom template example
id: custom-sqli-check
info:
  name: Custom SQLi Check
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=1' OR '1'='1"
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
        condition: or
```

---

### REST API Security Testing

#### OWASP API Security Top 10 (2023)

| # | Vulnerability | Description |
|---|--------------|-------------|
| API1 | Broken Object Level Authorization (BOLA) | Accessing other users' resources by manipulating object IDs |
| API2 | Broken Authentication | Weak auth, missing rate limiting on auth endpoints |
| API3 | Broken Object Property Level Authorization | Over-exposure of object properties (mass assignment) |
| API4 | Unrestricted Resource Consumption | No rate limiting leads to DoS or financial impact |
| API5 | Broken Function Level Authorization (BFLA) | Regular users access admin endpoints |
| API6 | Unrestricted Access to Sensitive Business Flows | Abuse of valid API flows (cart manipulation) |
| API7 | Server Side Request Forgery (SSRF) | API fetches attacker-controlled URLs |
| API8 | Security Misconfiguration | Verbose errors, debug endpoints, open CORS |
| API9 | Improper Inventory Management | Undocumented or legacy API versions exposed |
| API10 | Unsafe Consumption of APIs | Trusting third-party API data without validation |

#### Schemathesis — Property-Based API Testing

```bash
# Run all checks against OpenAPI spec
schemathesis run https://staging.api.example.com/openapi.json \
  --checks all \
  --auth "Bearer $TOKEN" \
  --stateful links \
  --report schemathesis-report.html

# Specific checks
schemathesis run openapi.json \
  --checks not_a_server_error,status_code_conformance,content_type_conformance \
  --max-response-time 500

# CI with JUnit output
schemathesis run openapi.json \
  --checks all \
  --exitfirst \
  --junit-xml schemathesis-results.xml
```

#### Dredd — OpenAPI Contract Testing

```bash
# Test API implementation against OpenAPI spec
dredd openapi.yaml https://staging.example.com \
  --hookfiles dredd-hooks.js \
  --reporter junit
```

---

### GraphQL Security Testing

#### graphql-cop

```bash
# Run all GraphQL security checks
graphql-cop -t https://staging.example.com/graphql \
  -H "Authorization: Bearer $TOKEN"

# Checks performed:
# - Introspection enabled (information disclosure)
# - Field suggestions enabled (schema enumeration)
# - Batch query attacks
# - Query depth attacks via aliases
# - Circular fragment detection
# - GET-based mutations allowed
```

#### Common GraphQL Vulnerabilities

```graphql
# Introspection query — should be disabled in production
{ __schema { types { name fields { name } } } }

# Deeply nested query for DoS via complexity
{ user { friends { friends { friends { name email phone } } } } }

# Batch query abuse — rate limit bypass (1000 login attempts in one HTTP request)
[
  {"query": "mutation { login(email:"a@a.com", pass:"pass1") { token } }"},
  {"query": "mutation { login(email:"a@a.com", pass:"pass2") { token } }"}
]
```

**Mitigations:** Query complexity limits, depth limits (max 5-7), persisted queries, rate limiting per operation type, disable introspection in production.

---

### Authentication Testing Automation

#### JWT Testing

```bash
# jwt_tool — algorithm confusion and common JWT attacks
python3 jwt_tool.py $JWT -X a  # RS256->HS256 algorithm confusion
python3 jwt_tool.py $JWT -X n  # none algorithm attack
python3 jwt_tool.py $JWT -X b  # blank password brute force

# Validate PKCE implementation
# S256 (correct): code_challenge = BASE64URL(SHA256(code_verifier))
# Plain (insecure — should be rejected): code_challenge = code_verifier
```

---

### Fuzzing in CI

#### AFL++ for Binary Targets

```bash
# Instrument binary with AddressSanitizer
CC=afl-cc CXX=afl-c++ ./configure && make

# Run fuzzer
afl-fuzz -i corpus/ -o findings/ -- ./target @@

# Parallel fuzzing (1 main + N workers)
afl-fuzz -M main -i corpus/ -o findings/ -- ./target @@
afl-fuzz -S worker1 -i corpus/ -o findings/ -- ./target @@
```

#### Atheris — Python Fuzzing with Coverage Guidance

```python
import atheris, sys

@atheris.instrument_func
def test_one_input(data):
    fdp = atheris.FuzzedDataProvider(data)
    target_function(fdp.ConsumeUnicodeNoSurrogates(100))

atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
```

#### CI Fuzzing Budget

```bash
# LibFuzzer with time-bounded CI run
clang++ -fsanitize=fuzzer,address -o fuzz_target fuzz_target.cpp
./fuzz_target -max_total_time=60 corpus/
# Crashes saved to crash-* files and uploaded as build artifacts
# OSS-Fuzz provides continuous fuzzing for open source with 30-day disclosure SLA
```

---
## 8. Infrastructure as Code Security Practices

### Terraform Security Controls

#### Provider Version Pinning

```hcl
terraform {
  required_version = ">= 1.6.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"  # minor updates OK, major blocked
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "= 2.24.0"  # exact pin for stability
    }
  }
}
```

#### Remote State with S3 + DynamoDB Encryption and Locking

```hcl
terraform {
  backend "s3" {
    bucket               = "myorg-tfstate-production"
    key                  = "services/payment-api/terraform.tfstate"
    region               = "us-east-1"
    encrypt              = true
    kms_key_id           = data.aws_kms_key.tfstate.arn
    dynamodb_table       = "terraform-state-locks"
    workspace_key_prefix = "workspaces"
  }
}
```

#### Sentinel Policy-as-Code (Terraform Enterprise/Cloud)

```python
# sentinel/policy/restrict-instance-types.sentinel
import "tfplan/v2" as tfplan

allowed_types = ["t3.micro", "t3.small", "t3.medium"]

main = rule {
  all tfplan.resource_changes as _, rc {
    rc.type is not "aws_instance" or
    rc.change.after.instance_type in allowed_types
  }
}
```

**Policy enforcement levels:**
- `advisory` — log violation, allow plan to proceed
- `soft-mandatory` — block unless overridden by operator with justification
- `hard-mandatory` — always block; no override possible

#### Atlantis PR Workflow

```yaml
# atlantis.yaml
version: 3
projects:
  - name: payment-api
    dir: services/payment-api
    workspace: production
    apply_requirements: [approved, mergeable, undiverged]
    autoplan:
      when_modified: ["*.tf", "../modules/**/*.tf"]

workflows:
  secure:
    plan:
      steps:
        - run: tfsec . --minimum-severity HIGH --no-colour
        - run: checkov -d . --framework terraform --compact --quiet
        - init
        - plan
    apply:
      steps:
        - apply
```

---

### Pulumi Security

```python
import pulumi

# Store secret (encrypted in Pulumi state with stack-specific key)
db_password = pulumi.Config().require_secret("dbPassword")
# CLI: pulumi config set --secret dbPassword mysecretvalue
# State stores ciphertext only — plaintext never written to disk
```

**Pulumi ESC (Environments, Secrets, Config):**
```yaml
# esc/environments/production.yaml
values:
  aws:
    creds:
      fn::open::aws-secrets:
        login:
          roleArn: arn:aws:iam::123456789012:role/pulumi-esc
        get:
          db-password:
            secretId: prod/myapp/db-password
  pulumiConfig:
    dbPassword: ${aws.creds.db-password}
```

---

### AWS CDK Security — cdk-nag

```python
from aws_cdk import App, Stack, Aspects
from cdk_nag import AwsSolutionsChecks, NagSuppressions

app = App()
stack = MyStack(app, "MyStack")

# Apply AwsSolutions rule pack
Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

# Suppress specific findings with mandatory justification
NagSuppressions.add_stack_suppressions(stack, [
    {
        "id": "AwsSolutions-S1",
        "reason": "S3 access logging disabled for cost reasons in dev; enabled in prod"
    }
])

# Suppress on specific resource
NagSuppressions.add_resource_suppressions(
    my_bucket,
    [{"id": "AwsSolutions-S2", "reason": "Public read intentional for static website"}],
    apply_to_children=True
)
```

**Available rule packs:**
- `AwsSolutionsChecks` — general AWS best practices
- `HIPAASecurityChecks` — HIPAA compliance requirements
- `NIST80053R5Checks` — NIST 800-53 Rev 5
- `PCIDSS321Checks` — PCI DSS 3.2.1

---

### Ansible Security Hardening

#### ansible-vault for Sensitive Variables

```bash
# Encrypt a string value
ansible-vault encrypt_string 'my-db-password' --name 'db_password'
# Output: db_password: !vault | $ANSIBLE_VAULT;1.1;AES256...

# Encrypt an entire file
ansible-vault encrypt group_vars/production/secrets.yml

# Edit encrypted file
ansible-vault edit group_vars/production/secrets.yml

# Run playbook with vault
ansible-playbook site.yml --vault-password-file ~/.vault_pass
```

#### Security Best Practices in Playbooks

```yaml
# tasks/deploy.yml
- name: Deploy application
  become: yes
  become_user: appuser   # escalate to specific user, not root
  block:
    - name: Copy secret config
      template:
        src: config.j2
        dest: /etc/myapp/config.yml
        owner: appuser
        mode: '0600'  # restrictive permissions

    - name: Call external API
      uri:
        url: https://api.example.com/register
        method: POST
        body_format: json
        body:
          api_key: "{{ vault_api_key }}"
      no_log: true  # prevent secret from appearing in Ansible output
```

---

### CIS Benchmark Automation

#### Chef InSpec

```bash
# Run CIS AWS Foundations Benchmark
inspec exec https://github.com/dev-sec/cis-aws-benchmark \
  -t aws:// \
  --reporter cli html:report.html json:report.json

# Custom InSpec control
control 's3-encryption' do
  impact 1.0
  title 'Ensure S3 bucket has server-side encryption enabled'
  describe aws_s3_bucket('my-bucket') do
    it { should have_default_encryption_enabled }
  end
end
```

#### OpenSCAP

```bash
# Scan RHEL system against CIS benchmark
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Generate remediation script
oscap xccdf generate fix \
  --fix-type bash \
  --output remediation.sh \
  scan-results.xml
```

#### AWS Security Hub CIS Auto-Remediation

```python
# Lambda triggered by Security Hub finding events
import boto3

def handler(event, context):
    finding = event['detail']['findings'][0]
    control_id = finding['ProductFields']['ControlId']
    resource = finding['Resources'][0]

    if control_id == 'CIS.2.1.1':  # S3 no public access
        s3 = boto3.client('s3')
        bucket = resource['Id'].split(':::')[1]
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
```

---

### Drift Detection

**Terraform Cloud drift detection:**
- Enable in workspace settings: Drift Detection > automatic health assessment
- Runs `terraform plan` on schedule, compares result to state
- Alerts via Slack, PagerDuty, or webhook integrations

**AWS Config Rules for drift:**
```python
# Config Rule — detect unencrypted EBS volumes
def evaluate_compliance(configuration_item):
    if configuration_item['resourceType'] != 'AWS::EC2::Volume':
        return 'NOT_APPLICABLE'
    if configuration_item['configuration'].get('encrypted'):
        return 'COMPLIANT'
    return 'NON_COMPLIANT'
```

**Drift response playbook:**
1. Alert fires (Config rule non-compliant or Terraform drift detected)
2. Automated remediation attempted (if pre-approved via Lambda)
3. If remediation fails: create Jira ticket with P1 priority, engineering on-call reviews within 4 hours
4. Revert to IaC-defined state or create approved exception with CISO sign-off
5. Post-incident: add preventive control (SCPs, permissions boundary, Config rule)

---
## 9. Software Supply Chain in DevSecOps

### SLSA Framework Implementation

SLSA (Supply chain Levels for Software Artifacts) provides a framework for measuring and improving the security of the software supply chain by requiring provenance attestations about how software was built.

#### GitHub Actions SLSA Generator

```yaml
# .github/workflows/build-and-attest.yml
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digests: ${{ steps.hash.outputs.digests }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Build artifact
        run: |
          make release
          sha256sum artifacts/* > SHA256SUMS
      - name: Generate subject digests
        id: hash
        run: |
          DIGESTS=$(cat SHA256SUMS | base64 -w0)
          echo "digests=$DIGESTS" >> $GITHUB_OUTPUT

  provenance:
    needs: build
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.digests }}"
      upload-assets: true
```

**SLSA Level Requirements:**

| Level | Build Platform | Provenance | Build Environment |
|-------|---------------|------------|-------------------|
| L1 | Any | Generated | No requirement |
| L2 | Hosted (GitHub Actions, Cloud Build) | Signed by platform | No requirement |
| L3 | Hosted | Non-falsifiable (generated by platform) | Isolated, hermetic |

**Verification:**
```bash
slsa-verifier verify-artifact \
  --provenance-path artifact.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.2.3 \
  artifact.tar.gz
```

---

### Sigstore Integration

Sigstore provides free, transparent signing infrastructure using short-lived certificates tied to OIDC identities — eliminating the need for long-term key management.

#### Cosign for Non-Container Artifacts

```bash
# Sign a binary or archive (keyless)
COSIGN_EXPERIMENTAL=1 cosign sign-blob \
  --bundle artifact.bundle \
  artifact.tar.gz

# Verify
COSIGN_EXPERIMENTAL=1 cosign verify-blob \
  --bundle artifact.bundle \
  --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  artifact.tar.gz
```

#### Gitsign — Commit Signing with Fulcio CA

```bash
# Configure git to use gitsign
git config --global gpg.x509.program gitsign
git config --global gpg.format x509
git config --global commit.gpgsign true

# Commits signed with short-lived Fulcio certificate
# No GPG key management required — uses OIDC identity

# Verify a commit
git verify-commit HEAD
```

#### Rekor — Transparency Log Verification

```bash
# Look up an entry in the transparency log
rekor-cli get --uuid $UUID --format json

# Search by artifact hash
rekor-cli search --sha $(sha256sum artifact.tar.gz | cut -d' ' -f1)

# Search by email identity
rekor-cli search --email developer@example.com
```

---

### in-toto Attestation Framework

in-toto provides cryptographic guarantees about the software supply chain by defining steps, expected commands, and expected artifacts at each step.

```json
{
  "steps": [
    {
      "name": "clone",
      "expected_command": ["git", "clone"],
      "expected_products": [{"artifact": "src/", "rules": ["CREATE"]}]
    },
    {
      "name": "build",
      "expected_command": ["make", "release"],
      "expected_materials": [{"artifact": "src/", "rules": ["MATCH"]}],
      "expected_products": [{"artifact": "artifact.tar.gz", "rules": ["CREATE"]}]
    }
  ]
}
```

Each step generates a signed link metadata file. in-toto-verify checks that the actual build matched the layout.

---

### Package Manager Hardening

#### npm

```bash
# Install from lockfile only — no lockfile modification permitted
npm ci --ignore-scripts

# Security audit
npm audit --audit-level critical
npm audit --json > npm-audit.json

# Verify registry signatures (npm 9+)
npm audit signatures
```

**.npmrc hardening:**
```ini
@myorg:registry=https://registry.internal.example.com/
audit=true
ignore-scripts=true
package-lock=true
save-exact=true
```

#### pip

```bash
# Generate requirements with cryptographic hashes
pip-compile --generate-hashes requirements.in -o requirements.txt

# Install with hash verification (prevents tampering)
pip install -r requirements.txt --require-hashes

# Security audit
pip-audit -r requirements.txt --output json > pip-audit.json
pip-audit --requirement requirements.txt \
  --vulnerability-service pypi \
  --format cyclonedx-json \
  --output sbom.json
```

#### Cargo (Rust)

```bash
# Security audit against RustSec Advisory DB
cargo audit

# cargo-deny — comprehensive dependency checks
deny.toml:
[licenses]
unlicensed = "deny"
deny = ["GPL-2.0"]

[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

cargo deny check
```

---

### OpenSSF Scorecard

Scorecard automatically evaluates 18+ security practices for GitHub repositories and produces a score (0-10) per check.

```yaml
# .github/workflows/scorecard.yml
- uses: ossf/scorecard-action@v2.4.0
  with:
    results_file: results.sarif
    results_format: sarif
    publish_results: true

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Scorecard checks:**

| Check | What it measures |
|-------|-----------------|
| Maintained | Recent commits and releases |
| Code-Review | PRs require review before merge |
| Branch-Protection | Main branch has protection rules |
| Token-Permissions | Workflows follow least privilege |
| Dangerous-Workflow | No script injection in workflows |
| Pinned-Dependencies | Actions pinned to full SHA |
| SAST | Static analysis runs in CI |
| Secret-Scanning | Secret scanning enabled |
| Binary-Artifacts | No binary blobs in repository |
| Signed-Releases | Releases are signed |

---

### Allstar — Organization-Wide Policy Enforcement

```yaml
# .allstar/allstar.yaml (org-level configuration repository)
optConfig:
  optOutStrategy: false  # all repos must comply; exemptions require explicit opt-out

# .allstar/branch_protection.yaml
optConfig:
  optOutStrategy: false
action: fix  # auto-apply branch protection settings

branch_protection:
  enforceDefault: true
  requirePullRequestReviews:
    requiredApprovingReviewCount: 1
    dismissStaleReviews: true
  requireStatusChecks:
    strict: true
    contexts: ["CI", "Security Scan"]
  requireAdminsToAbideByProtection: true
```

---

### SBOM Mandate Compliance

**US Executive Order 14028 (May 2021):**
- Requires SBOM for software sold to US federal government
- NTIA Minimum Elements must be present
- Machine-readable format (SPDX or CycloneDX required)

**EU Cyber Resilience Act (CRA, 2024):**
- Applies to products with digital elements sold in the EU
- SBOM required as part of technical documentation
- Vulnerability disclosure obligations within 24 hours of active exploitation
- Security updates required for entire expected product lifetime

**NTIA Minimum Elements:**

| Element | SPDX Field | CycloneDX Field |
|---------|------------|-----------------|
| Supplier name | PackageSupplier | supplier |
| Component name | PackageName | name |
| Version | PackageVersion | version |
| Other identifiers | ExternalRef: PURL | purl |
| Dependencies | Relationship | dependencies |
| SBOM Author | Creator | metadata.authors |
| Timestamp | Created | metadata.timestamp |

---
## 10. Observability, Compliance & Culture

### Security Observability from Applications

#### Structured Security Event Logging

```python
import json, logging, datetime

def security_event(event_type, severity, actor, resource, action, outcome, **kwargs):
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,      # AUTH_FAILURE, AUTHZ_VIOLATION, DATA_ACCESS
        "severity": severity,          # CRITICAL, HIGH, MEDIUM, LOW, INFO
        "actor": {
            "user_id": actor.get("user_id"),
            "ip": actor.get("ip"),
            "user_agent": actor.get("user_agent"),
            "session_id": actor.get("session_id")
        },
        "resource": {
            "type": resource.get("type"),  # endpoint, file, database_record
            "id": resource.get("id"),
            "owner": resource.get("owner")
        },
        "action": action,   # read, write, delete, login, logout
        "outcome": outcome, # success, failure, blocked
        **kwargs
    }
    logging.getLogger("security").info(json.dumps(event))

# Usage
security_event(
    event_type="AUTH_FAILURE",
    severity="HIGH",
    actor={"user_id": None, "ip": "198.51.100.42"},
    resource={"type": "endpoint", "id": "/api/admin/users"},
    action="login",
    outcome="failure",
    failure_reason="invalid_credentials",
    attempt_count=5
)
```

**SIEM detection rules (Splunk SPL examples):**
```
# Brute force detection
index=app sourcetype=security_events event_type="AUTH_FAILURE"
| stats count by actor.ip, _time span=60s
| where count > 5

# Privilege escalation detection
index=app sourcetype=security_events event_type="AUTHZ_VIOLATION"
  resource.id="/api/admin/*"
| alert

# Data exfiltration indicator
index=app sourcetype=security_events event_type="DATA_ACCESS"
| stats count by actor.user_id, _time span=300s
| where count > 1000
```

#### WAF Integration in DevSecOps

```python
# AWS WAF CDK construct — WAF rules stored as code in git
from aws_cdk import aws_wafv2 as wafv2

web_acl = wafv2.CfnWebACL(self, "ApiWAF",
    scope="REGIONAL",
    default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
    rules=[
        wafv2.CfnWebACL.RuleProperty(
            name="AWSManagedRulesCommonRuleSet",
            priority=1,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    vendor_name="AWS",
                    name="AWSManagedRulesCommonRuleSet"
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="CommonRuleSet",
                sampled_requests_enabled=True
            )
        )
    ],
    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
        cloud_watch_metrics_enabled=True,
        metric_name="ApiWAF",
        sampled_requests_enabled=True
    )
)
```

**ModSecurity / Coraza WAF rules in git:**
```
# Store CRS rules in git repository
# .github/workflows/waf-deploy.yml
- name: Deploy WAF rules
  run: |
    rsync -av modsecurity/rules/ waf-server:/etc/modsecurity/rules/
    ssh waf-server systemctl reload nginx
```

---

### Compliance-as-Code Automation

#### Automated Evidence Collection for SOC 2 / ISO 27001

| Control | Automated Evidence | Collection Method |
|---------|-------------------|------------------|
| CC6.1 - Logical access uses MFA | IAM Credential Report MFA status | AWS Config + Lambda daily export |
| CC6.2 - Access provisioning | GitHub Actions log of role assignments | GitHub Audit Log API |
| CC6.3 - Access removal on termination | IAM user deactivation within 24h | Identity provider webhook + Lambda |
| CC7.2 - Anomalous activity monitoring | SIEM alert rule coverage report | Splunk API weekly export |
| CC8.1 - Change management | PR approvals + deployment logs | GitHub API + ArgoCD |
| A.12.6.1 - Vulnerability management | Scan coverage + MTTR metrics | Snyk + Jira APIs |

**Drata/Vanta/Secureframe API integration:**
```python
import requests, datetime, os

DRATA_API_KEY = os.environ['DRATA_API_KEY']

def push_evidence(control_id, evidence_type, description, file_path=None):
    headers = {"Authorization": f"Bearer {DRATA_API_KEY}"}
    data = {
        "controlId": control_id,
        "evidenceType": evidence_type,  # SCREENSHOT, EXPORT, LINK
        "description": description,
        "collectionDate": datetime.datetime.utcnow().isoformat()
    }
    if file_path:
        with open(file_path, 'rb') as f:
            requests.post(
                "https://api.drata.com/v1/evidence",
                headers=headers, data=data,
                files={"file": f}
            )

# Example: push daily MFA compliance evidence
push_evidence(
    control_id="CC6.1",
    evidence_type="EXPORT",
    description=f"IAM Credential Report showing MFA status — {datetime.date.today()}",
    file_path="/tmp/credential-report.csv"
)
```

---

### Vulnerability SLA Enforcement

#### CVSS-Based SLA Tiers

| Severity | CVSS Score | SLA to Remediate | Escalation Path |
|----------|------------|-----------------|-----------------|
| Critical | 9.0-10.0 | 24 hours | CISO + VP Engineering immediately |
| High | 7.0-8.9 | 7 days | Security team + Engineering manager |
| Medium | 4.0-6.9 | 30 days | Security team notification |
| Low | 0.1-3.9 | 90 days | Engineering backlog |
| Informational | 0.0 | Best effort | No escalation |

**CISA KEV Override:** Any vulnerability on the CISA Known Exploited Vulnerability catalog gets promoted to Critical SLA (24h) regardless of CVSS score.

#### Security Debt Tracking Metrics

```python
# Engineering dashboard metrics
{
    "vulnerability_debt": {
        "critical_open": 0,           # must always be 0 after SLA window
        "high_open_within_sla": 12,
        "high_open_breached_sla": 1,  # any > 0 requires escalation
        "medium_open": 47,
        "low_open": 203
    },
    "mean_time_to_remediate": {
        "critical_hours": 18.2,
        "high_days": 4.2,
        "medium_days": 18.5,
        "low_days": 62.1
    },
    "escape_rate": 0.032,   # 3.2% of vulns found post-deployment
    "scan_coverage": 0.97   # 97% of repos have SAST enabled
}
```

---

### DevSecOps Culture Change Management

#### Developer Empathy Approach

Security programs fail when they create friction without empathy. Key principles:

- **Fix the tool, not the developer**: If SAST has 40% false positive rate, fix the rules before demanding developers triage findings
- **Context in findings**: Every alert includes "Why this matters" and "How to fix it" — not just "CWE-89"
- **One-click remediation**: Where possible, provide automated fix (Snyk fix PR, Dependabot PR, suggested code change in PR comment)
- **Security office hours**: Weekly 30-minute open Q&A with security team — no judgment, all questions welcome
- **Hack-and-fix days**: Quarterly event where developers fix security findings in other teams' codebases (cross-pollination and empathy building)
- **Blameless post-mortems**: Security incidents analyzed for system failures, not individual blame

#### Security Newsletter for Developers

Monthly 5-minute read format:
- 1 recent relevant breach and the root cause
- 1 new tool or technique relevant to the team's stack
- Top 3 security findings caught this month (anonymized)
- Recognition: developer who found or fixed the most impactful security issue

#### Gamification with Security Achievements

| Achievement | Trigger | Recognition |
|-------------|---------|-------------|
| First Blood | First security finding filed | Mention in newsletter |
| Bug Slayer | 10 confirmed vulnerabilities fixed | Swag package |
| Guardian | Introduce a security guardrail adopted by team | Conference budget |
| Champion | Become certified security champion | Salary adjustment + title |
| Zero Day Hero | Report CVE in upstream dependency | CISO recognition + bounty |

---

### DevSecOps Tool Chain Evaluation Matrix

| Criteria | Weight | How to Score |
|----------|--------|-------------|
| Scan accuracy (FP/FN rate) | 25% | Benchmark against known-vulnerable code corpus |
| CI/CD integration effort | 20% | Time to integrate into existing pipeline |
| Developer experience | 20% | Finding quality, fix guidance, PR comment integration |
| Coverage (languages/frameworks) | 15% | Percentage of your stack covered |
| Remediation guidance quality | 10% | Actionability of fix recommendations |
| Pricing model fit | 10% | Per-scan vs per-developer vs enterprise licensing |

---

### Demonstrating DevSecOps ROI

#### Vulnerability Reduction Rate

```
VRR = (Vulns_Year_N-1 - Vulns_Year_N) / Vulns_Year_N-1 x 100

Example:
  Year 1 (pre-DevSecOps): 450 vulnerabilities found in production
  Year 2 (post-DevSecOps): 180 vulnerabilities found in production
  VRR = (450 - 180) / 450 x 100 = 60% reduction in production vulnerabilities
```

#### Breach Cost Avoidance

Using IBM Cost of a Data Breach 2024 ($4.88M average):
```
Before DevSecOps:
  Breach probability: 32% per year
  Expected Annual Cost = 0.32 x $4,880,000 = $1,561,600

DevSecOps program cost: $400,000/year (tools + training + headcount)

If DevSecOps reduces breach probability by 40% (to 19.2%):
  New Expected Annual Cost = 0.192 x $4,880,000 = $936,960
  Annual Avoidance = $1,561,600 - $936,960 = $624,640
  Net ROI = ($624,640 - $400,000) / $400,000 x 100 = 56%
```

#### Audit Efficiency Improvement

```
Evidence collection hours per audit cycle:
  Before DevSecOps (manual): 800 hours
  After DevSecOps (automated evidence): 120 hours

  Time saved: 680 hours x $150/hour loaded cost = $102,000 per audit
  Annual savings (2 audit cycles): $204,000
```

---

### Security Champions Community of Practice

**Meeting cadence:** Monthly 1-hour call for all champions across teams.

**Agenda template:**
1. Threat landscape update (10 min) — 2-3 relevant recent incidents
2. Tool tip of the month (10 min) — deep dive on one specific feature or technique
3. Champion showcase (15 min) — champion presents a security improvement shipped this month
4. Open discussion and Q&A (15 min)
5. Metrics review (10 min) — org-wide security KPIs, celebrate improvements

**Communication channels:**
- `#security-champions` Slack: async Q&A, tool tips, threat intel sharing
- `#security-alerts`: critical vulnerability notifications requiring immediate action
- Monthly digest email with metrics and achievements

**Champion recognition:**
- Quarterly Champion of the Quarter award ($500 L&D budget + leadership recognition)
- Annual Security Summit attendance (fully paid)
- Speaking opportunity at internal and external tech talks
- Visible credit in security reports shared with the board

---

## Quick Reference

### CVSS v3.1 Severity Ratings

| Score | Severity |
|-------|----------|
| 0.0 | None |
| 0.1-3.9 | Low |
| 4.0-6.9 | Medium |
| 7.0-8.9 | High |
| 9.0-10.0 | Critical |

### Essential DevSecOps Resources

| Resource | Description |
|----------|-------------|
| owasp.org/www-project-top-ten | OWASP Top 10 Web Application Risks |
| owasp.org/www-project-api-security | OWASP API Security Top 10 |
| nvd.nist.gov | NIST National Vulnerability Database |
| cisa.gov/known-exploited-vulnerabilities-catalog | CISA KEV Catalog |
| osv.dev | Open Source Vulnerabilities database |
| sigstore.dev | Sigstore signing infrastructure |
| slsa.dev | SLSA supply chain framework |
| securityscorecards.dev | OpenSSF Scorecard |
| bsimm.com | Building Security In Maturity Model |
| owaspsamm.org | OWASP Software Assurance Maturity Model |

---

*Last updated: 2026-05-04 | Maintained by the DevSecOps Practice*
