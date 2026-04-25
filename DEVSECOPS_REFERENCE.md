# DevSecOps Reference

> A comprehensive DevSecOps reference covering security integration across the full CI/CD pipeline with real tool configurations, GitHub Actions examples, and vendor-specific implementations.

---

## Table of Contents

1. [DevSecOps Philosophy](#1-devsecops-philosophy)
2. [Threat Modeling in SDLC](#2-threat-modeling-in-sdlc)
3. [SAST (Static Application Security Testing)](#3-sast-static-application-security-testing)
4. [SCA (Software Composition Analysis)](#4-sca-software-composition-analysis)
5. [Secret Detection](#5-secret-detection)
6. [DAST (Dynamic Application Security Testing)](#6-dast-dynamic-application-security-testing)
7. [Container Security in CI/CD](#7-container-security-in-cicd)
8. [Infrastructure as Code (IaC) Security](#8-infrastructure-as-code-iac-security)
9. [GitHub Actions Security Hardening](#9-github-actions-security-hardening)
10. [SBOM (Software Bill of Materials) in CI/CD](#10-sbom-software-bill-of-materials-in-cicd)
11. [Security Gates in CI/CD Pipeline](#11-security-gates-in-cicd-pipeline)
12. [Secrets Management in Applications](#12-secrets-management-in-applications)
13. [OWASP DevSecOps Guideline](#13-owasp-devsecops-guideline)
14. [Compliance Integration](#14-compliance-integration)

---

## 1. DevSecOps Philosophy

### Shift Left Security

"Shift Left" is the foundational principle of DevSecOps: find and fix vulnerabilities during development, not in production. Moving security testing earlier in the SDLC reduces cost, reduces risk, and increases developer ownership of security.

**Cost of fixing a vulnerability by phase (IBM Systems Sciences Institute):**
- Design: 1x
- Development: 6x
- Testing: 15x
- Production: 100x

### DevSecOps vs. DevOps

DevOps integrated development and operations teams. DevSecOps adds security as a **shared responsibility** across all roles — developers, ops engineers, and security professionals. Security is no longer a gate at the end of the pipeline; it is a continuous activity embedded throughout.

**Key differences:**
| Aspect | DevOps | DevSecOps |
|--------|--------|-----------|
| Security responsibility | Security team | Everyone |
| When security happens | Pre-release gate | Throughout SDLC |
| Security tools | Separate toolchain | Integrated in CI/CD |
| Security culture | Compliance checkbox | Continuous improvement |
| Incident response | Reactive | Proactive + reactive |

### Security Champions Program

Security champions embed security advocates directly in development teams — engineers with interest in security who bridge the gap between the security team and their dev squad.

**Responsibilities:**
- First point of contact for security questions
- Conduct threat modeling with the team
- Review security findings from automated tools
- Evangelize secure coding practices
- Participate in security training and relay knowledge

**Program elements:**
- Regular champions meetings (bi-weekly or monthly)
- Dedicated training budget and conference attendance
- Recognition program (security champion awards, badges)
- Access to security team slack channel or office hours
- Champions as reviewers on security-sensitive PRs

### OWASP SAMM (Software Assurance Maturity Model)

SAMM provides a measurable framework for evaluating and improving a software security program. It defines **5 business functions**, each with **3 security practices**, each with **3 maturity levels**.

**Business Functions:**
1. **Governance** — Strategy, Policy, Education & Guidance
2. **Design** — Threat Assessment, Security Requirements, Security Architecture
3. **Implementation** — Secure Build, Secure Deployment, Defect Management
4. **Verification** — Architecture Assessment, Requirements Testing, Security Testing
5. **Operations** — Incident Management, Environment Management, Operational Management

**Maturity Levels (per practice):**
- Level 1: Initial understanding and ad hoc practice
- Level 2: Increase efficiency and/or effectiveness
- Level 3: Comprehensive mastery

**Assessment approach:**
- Use SAMM Toolbox (spreadsheet or SaaS tool) to score current state
- Set target maturity per practice based on risk appetite
- Build roadmap to close gaps

### BSIMM (Building Security In Maturity Model)

BSIMM is an observational study of real-world software security programs — not prescriptive, but descriptive. It measures what organizations actually do and lets you benchmark against your industry.

**12 Practices across 4 domains:**
- **Governance:** Strategy & Metrics, Compliance & Policy, Training
- **Intelligence:** Attack Models, Security Features & Design, Standards & Requirements
- **SSDL Touchpoints:** Architecture Analysis, Code Review, Security Testing
- **Deployment:** Penetration Testing, Software Environment, Configuration Management & VM

**Current release:** BSIMM14 (2023) — 130+ participating firms, ~$2T in market cap represented

### Key DevSecOps Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| MTTD in CI/CD | Mean time to detect vulnerabilities in pipeline | < 10 min |
| Vulnerability escape rate | % of vulns that reach production | < 5% |
| Mean time to remediate (MTTR) | Time from finding to fix merged | Critical < 24h, High < 7d |
| SAST false-positive rate | % of SAST findings that are not real | < 20% |
| Security debt ratio | Open security issues / total open issues | < 10% |
| Coverage rate | % of repos with automated security scanning | 100% |
| Security gate pass rate | % of builds passing security gates | > 95% |
| Patch currency | % of dependencies up to date | > 90% |

---

## 2. Threat Modeling in SDLC

### When to Threat Model

- **Sprint 0** for significant new features or new services
- During **architecture reviews** for any system handling sensitive data
- **Before significant changes** to authentication, authorization, or data flows
- When introducing **new third-party integrations** or APIs
- After a **security incident** that reveals a design flaw

### Who Should Participate

Threat modeling does not require a dedicated security team for every session:
- **Developer** — knows the code and implementation details
- **Security champion** — brings security mindset, owns facilitation
- **Architect** — understands system boundaries and data flows

Invite the security team for high-risk systems (payment processing, identity management, PII-heavy systems).

### STRIDE Threat Model

The classic Microsoft methodology — identify threats by category:

| Threat | Description | Example |
|--------|-------------|---------|
| **S**poofing | Impersonating another user or system | Session hijacking, CSRF |
| **T**ampering | Modifying data in transit or at rest | Parameter tampering, SQLi |
| **R**epudiation | Denying actions occurred | Missing audit logs |
| **I**nformation Disclosure | Exposing data to unauthorized parties | Path traversal, IDOR |
| **D**enial of Service | Making system unavailable | ReDoS, resource exhaustion |
| **E**levation of Privilege | Gaining unauthorized permissions | Privilege escalation |

### PASTA (Process for Attack Simulation and Threat Analysis)

A risk-centric, 7-stage methodology:
1. Define objectives and scope
2. Define technical scope (architecture, components)
3. Decompose the application (DFDs, trust boundaries)
4. Analyze threats (attack libraries, threat intelligence)
5. Vulnerability analysis (map threats to vulnerabilities)
6. Attack modeling (attack trees, simulation)
7. Risk/impact analysis and controls

### Tool Integration

**OWASP Threat Dragon:**
```bash
# Run locally
docker run -it --rm -p 3000:3000 \
  -e ENCRYPTION_JWT_SIGNING_KEY=my-signing-key \
  -e ENCRYPTION_JWT_REFRESH_SIGNING_KEY=my-refresh-key \
  owasp/threat-dragon:latest

# Store threat model in Git repo
# threat-models/feature-x-auth.json
```

**IriusRisk** — enterprise SaaS, integrates with Jira:
- Auto-generates threat models from architecture diagrams
- Links threats to Jira tickets automatically
- Supports STRIDE, PASTA, CVSS scoring

### Abuse Cases as User Stories

Security requirements expressed in developer-friendly format:

```
As an attacker, I can bypass authentication by replaying a stolen session token,
so the application must invalidate tokens on logout and implement absolute session expiry.

As an attacker, I can enumerate user accounts via the password reset endpoint's
different error messages, so the application must return identical responses for
valid and invalid email addresses.

As an attacker, I can inject SQL via the search parameter because it is not
parameterized, so all database queries must use prepared statements.
```

### Security Requirements → Acceptance Criteria

Threat model outputs become ticket acceptance criteria:

```
Story: User login
Acceptance Criteria (Security):
- [ ] Passwords hashed with bcrypt (cost factor >= 12)
- [ ] Account lockout after 5 failed attempts (15 min lockout)
- [ ] MFA supported (TOTP)
- [ ] Login failures logged with IP, timestamp, username
- [ ] Session token is 128-bit random, HttpOnly, Secure, SameSite=Strict
- [ ] Session invalidated on logout (server-side)
```

---

## 3. SAST (Static Application Security Testing)

### What SAST Does

SAST analyzes **source code without executing it** to find:
- Common Weakness Enumeration (CWE) patterns
- Insecure coding patterns (hardcoded secrets, SQL injection sinks)
- Taint flows from user input to dangerous functions
- Misconfigurations in code (e.g., disabled TLS verification)

**False positive challenge:** SAST tools are known for high false positive rates. Mitigation:
- Tune rules per project (disable irrelevant rules)
- Add suppression comments with justification (not blanket suppresses)
- Establish a triage workflow — SLA for reviewing new findings
- Track false positive rate as a metric

### Semgrep

Lightweight, rule-based, fast SAST that runs in seconds. Rules are YAML, open-source, and highly customizable.

```yaml
# Custom Semgrep rule example
rules:
  - id: hardcoded-secret-key
    patterns:
      - pattern: $KEY = "..."
      - metavariable-regex:
          metavariable: $KEY
          regex: (?i)(secret|password|api_key|token|passwd)
    message: "Potential hardcoded secret in $KEY"
    severity: ERROR
    languages: [python, javascript, java, go]
    metadata:
      cwe: CWE-798
      owasp: A07:2021 - Identification and Authentication Failures

  - id: sql-injection-string-format
    patterns:
      - pattern: |
          $DB.execute("..." % $USER_INPUT)
      - pattern: |
          $DB.execute("..." + $USER_INPUT)
    message: "Potential SQL injection via string concatenation"
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-89
```

```bash
# Run Semgrep
semgrep --config=p/security-audit --config=p/owasp-top-ten .
semgrep --config=./custom-rules/ --json --output results.json .

# CI integration (uses rules from .semgrep.yml or Semgrep Cloud)
semgrep ci --config=auto

# Scan with multiple rulesets
semgrep --config=p/python --config=p/secrets --config=p/jwt .

# Suppress false positive inline
x = user_input  # nosemgrep: rule-id (reason: input is already validated by schema)
```

**Semgrep Registry:** https://semgrep.dev/r — thousands of community and official rules

### SonarQube

Comprehensive, enterprise-grade platform with taint analysis, Quality Gates, and dashboards.

**Key features:**
- **Quality Gates:** configurable criteria that block PR merge (e.g., no new Critical issues, Security Hotspots reviewed)
- **Taint analysis:** tracks data flow from user-controlled source to dangerous sink
- **Issue lifecycle:** Open → Confirmed → Resolved → Won't Fix
- **Security Hotspots:** code that needs manual review (not a confirmed bug)

```bash
# Scanner invocation
sonar-scanner \
  -Dsonar.projectKey=myapp \
  -Dsonar.sources=src \
  -Dsonar.host.url=https://sonar.company.com \
  -Dsonar.login=$SONAR_TOKEN

# Quality Gate check in CI
curl -s "https://sonar.company.com/api/qualitygates/project_status?projectKey=myapp" \
  | jq '.projectStatus.status'
# Returns: OK or ERROR
```

**Key rules:**
- `RSPEC-2091` — SQL injection (taint analysis)
- `RSPEC-5145` — Log injection
- `RSPEC-2076` — OS command injection
- `RSPEC-4830` — Certificate validation disabled
- `RSPEC-2115` — Database password in connection string

### CodeQL (GitHub Advanced Security)

Semantic code analysis by GitHub — queries written in QL language, extremely powerful for finding complex vulnerability patterns.

```yaml
# .github/workflows/codeql.yml
name: CodeQL
on:
  push:
    branches: [main]
  pull_request:
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    strategy:
      matrix:
        language: [python, javascript]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-and-quality
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
          upload: true
```

**Custom CodeQL query example:**
```ql
/**
 * @name Hardcoded credentials
 * @kind problem
 * @severity error
 * @id py/hardcoded-credentials
 */
import python
import semmle.python.security.dataflow.HardcodedCredentials

from HardcodedCredentialsSink sink
select sink, "Hardcoded credential found."
```

### Language-Specific SAST Tools

| Language | Tool | Command / Notes |
|----------|------|----------------|
| Python | Bandit | `bandit -r . -f json -o bandit-report.json` |
| Python | Semgrep + p/python | Fast, low false positive rate |
| JavaScript/TS | ESLint (eslint-plugin-security) | Add to `.eslintrc` |
| JavaScript/TS | njsscan | `njsscan --json -o njsscan.json .` |
| Java | SpotBugs + FindSecBugs | Maven/Gradle plugin |
| Java | Checkmarx | Enterprise, taint analysis |
| Go | gosec | `gosec ./...` |
| Ruby | Brakeman | Rails-specific: `brakeman -o report.json` |
| C/C++ | Flawfinder | `flawfinder --html . > report.html` |
| C/C++ | Cppcheck | `cppcheck --enable=all --xml . 2> report.xml` |
| PHP | PHPCS Security Audit | `phpcs --standard=Security src/` |
| .NET/C# | Roslyn Analyzers | Built into VS, MSBuild |
| Infrastructure | checkov | `checkov -d . --framework terraform` |
| Infrastructure | tfsec | `tfsec .` |
| Infrastructure | kics | `kics scan -p .` |

---

## 4. SCA (Software Composition Analysis)

### What SCA Does

SCA scans **open-source dependencies** (libraries, packages, transitive deps) for:
- Known CVEs from public databases
- License compliance issues (GPL in commercial product)
- Outdated packages (upgrade paths)
- Malicious packages (typosquatting detection)

**Key vulnerability databases:**
- NVD (National Vulnerability Database) — https://nvd.nist.gov
- GitHub Advisory Database — https://github.com/advisories
- OSV (Open Source Vulnerabilities) — https://osv.dev
- Sonatype OSS Index — https://ossindex.sonatype.org

### Snyk

Commercial SCA with developer-friendly output, fix PRs, and container scanning.

```bash
# Test project for vulnerabilities
snyk test --severity-threshold=high

# Continuous monitoring (registers project in Snyk dashboard)
snyk monitor

# Container image scanning
snyk container test nginx:latest
snyk container test myapp:latest --file=Dockerfile

# IaC scanning
snyk iac test terraform/
snyk iac test k8s-manifests/

# Fix automatically (opens PR)
snyk fix

# Auth
snyk auth $SNYK_TOKEN
```

**GitHub Actions:**
```yaml
- name: Run Snyk
  uses: snyk/actions/node@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: --severity-threshold=high
```

### OWASP Dependency-Check

Open-source SCA tool, integrates with Maven/Gradle/CLI.

```bash
# CLI scan
dependency-check \
  --project "MyApp" \
  --scan ./lib \
  --format JSON \
  --format HTML \
  --out reports/

# Fail build if CVSS >= 7
dependency-check --project "MyApp" --scan . --failOnCVSS 7
```

**Maven plugin:**
```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>9.0.9</version>
  <configuration>
    <failBuildOnCVSS>7</failBuildOnCVSS>
    <format>JSON</format>
    <suppressionFile>suppression.xml</suppressionFile>
  </configuration>
  <executions>
    <execution>
      <goals><goal>check</goal></goals>
    </execution>
  </executions>
</plugin>
```

**Suppression file:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
  <suppress>
    <notes>False positive: CVE-2023-1234 does not affect this usage pattern</notes>
    <cve>CVE-2023-1234</cve>
  </suppress>
</suppressions>
```

### GitHub Dependabot

Native GitHub dependency management — automated PRs for security updates and version upgrades.

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
      timezone: "America/New_York"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    ignore:
      - dependency-name: "legacy-package"
        versions: ["2.x"]
    groups:
      dev-dependencies:
        dependency-type: "development"

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

**Dependabot security alerts:** Auto-enabled on all GitHub repos — creates alerts in Security tab for vulnerable dependencies.

### OSV-Scanner (Google)

Fast, open-source SCA using the OSV database — great for lockfile scanning.

```bash
# Install
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Scan by lockfile
osv-scanner --lockfile=package-lock.json
osv-scanner --lockfile=requirements.txt
osv-scanner --lockfile=Gemfile.lock
osv-scanner --lockfile=go.sum

# Recursive scan
osv-scanner -r ./project

# Scan SBOM
osv-scanner --sbom=sbom.spdx.json

# Output formats
osv-scanner --format table -r .
osv-scanner --format json -r . > osv-results.json
```

### License Compliance

SCA tools also flag license issues:

| License | Restriction | Risk |
|---------|-------------|------|
| MIT, BSD, Apache 2.0 | Permissive | Low |
| LGPL | Must open-source modifications to the library | Medium |
| GPL v2/v3 | Copyleft — can infect entire project | High |
| AGPL | Network use triggers copyleft | Very High |
| Proprietary | Commercial restrictions | Review required |

**Tools:** FOSSA, licensee, WhiteSource (Mend), Black Duck

---

## 5. Secret Detection

Secrets in version control are one of the most common and most damaging security incidents. Prevention requires scanning at multiple stages.

### Defense in Depth for Secrets

```
Developer machine
  └── pre-commit hook (gitleaks protect --staged)

Git push
  └── CI secret scanning (gitleaks detect, GitHub Secret Scanning)

Code review
  └── PR check — secrets surfaced as review annotations

Repository
  └── GitHub Secret Scanning (continuous, all pushes)
  └── Periodic full history scan
```

### Gitleaks

Fast, open-source tool for detecting secrets in git repos and commit history.

```bash
# Scan current repo (all history)
gitleaks detect --source=. --report-format=json --report-path=gitleaks-report.json

# Scan only staged changes (pre-commit)
gitleaks protect --staged

# Scan specific commit range
gitleaks detect --log-opts="HEAD~10..HEAD"

# GitHub Actions
- uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}  # for org scans
```

**Custom .gitleaks.toml rules:**
```toml
[[rules]]
id = "company-api-key"
description = "Company internal API key"
regex = '''MYCO_[A-Z0-9]{32}'''
tags = ["key", "internal"]

[allowlist]
paths = [
  '''tests/fixtures/''',
  '''\.gitleaks\.toml'''
]
regexes = [
  '''EXAMPLE_KEY_FOR_DOCS''',
]
```

### detect-secrets (Yelp)

Python-based, creates a baseline of known false positives.

```bash
pip install detect-secrets

# Create baseline (scan all files, mark existing as known)
detect-secrets scan > .secrets.baseline

# Audit baseline interactively (mark true/false positives)
detect-secrets audit .secrets.baseline

# Pre-commit hook usage
detect-secrets-hook --baseline .secrets.baseline

# Update baseline after adding intentional test fixtures
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

### TruffleHog

Detects secrets with entropy analysis and verified credentials (actually tests if secret is valid).

```bash
# Scan git history (only verified secrets)
trufflehog git file://. --only-verified

# Scan GitHub org
trufflehog github --org=myorg --token=$GITHUB_TOKEN

# Scan Docker image layers
trufflehog docker --image=myapp:latest

# Scan S3 bucket
trufflehog s3 --bucket=my-bucket

# GitHub Actions
- uses: trufflesecurity/trufflehog@main
  with:
    path: ./
    base: ${{ github.event.repository.default_branch }}
    head: HEAD
    extra_args: --only-verified
```

### Git Pre-commit Hook (Project-Level Enforcement)

```bash
#!/bin/bash
# .git/hooks/pre-commit  (or use pre-commit framework)
set -e

echo "Running secret detection..."
if command -v gitleaks &> /dev/null; then
  if ! gitleaks protect --staged --no-banner 2>&1; then
    echo "ERROR: Gitleaks found potential secrets. Commit blocked."
    echo "Review findings and add to allowlist if false positive."
    exit 1
  fi
else
  echo "WARNING: gitleaks not installed. Install: brew install gitleaks"
fi

echo "Secret scan passed."
exit 0
```

### GitHub Secret Scanning

Native GitHub feature — automatically scans for 200+ secret patterns from 100+ service providers.

**Enable in repository settings:**
- Settings → Security → Secret scanning → Enable
- Push protection: blocks pushes that contain secrets (not just detects)

**Supported partners (sample):** AWS, Azure, GCP, GitHub, Stripe, Twilio, SendGrid, Slack, npm, PyPI, Docker Hub

---

## 6. DAST (Dynamic Application Security Testing)

### What DAST Does

DAST tests a **running application** by sending malicious inputs and analyzing responses. It finds:
- XSS, SQLi, command injection in live application behavior
- Authentication and session management flaws
- Broken access control (BOLA, BFLA)
- Security misconfigurations in headers, TLS, cookies
- Business logic flaws

**Requires:** A deployed application (staging or test environment), valid credentials for authenticated scanning.

### OWASP ZAP (Zed Attack Proxy)

The most widely-used open-source DAST tool.

```bash
# Passive/API scan (safe for staging)
docker run -t zaproxy/zap-stable zap-api-scan.py \
  -t https://api.example.com/openapi.json \
  -f openapi \
  -r api-report.html

# Baseline scan (passive only, safe for production)
docker run -t zaproxy/zap-stable zap-baseline.py \
  -t https://staging.example.com \
  -r baseline-report.html

# Full active scan (aggressive — staging only!)
docker run -t zaproxy/zap-stable zap-full-scan.py \
  -t https://staging.example.com \
  -r full-report.html \
  -I  # do not fail on warning

# GitHub Actions integration
- name: ZAP API Scan
  uses: zaproxy/action-api-scan@v0.7.0
  with:
    target: 'https://staging.example.com/api/openapi.json'
    format: openapi
    rules_file_name: '.zap/rules.tsv'

- name: ZAP Full Scan
  uses: zaproxy/action-full-scan@v0.7.0
  with:
    target: 'https://staging.example.com'
    rules_file_name: '.zap/rules.tsv'
    cmd_options: '-a'
```

**ZAP rules.tsv** (configure pass/warn/fail per alert):
```
10016	WARN	# Web Browser XSS Protection Not Enabled
10017	WARN	# Cross-Domain JavaScript Source File Inclusion
10021	FAIL	# X-Content-Type-Options Header Missing
10038	FAIL	# Content Security Policy (CSP) Header Not Set
40012	FAIL	# Cross Site Scripting (Reflected)
40018	FAIL	# SQL Injection
```

### Nuclei

Template-based vulnerability scanner with a massive community template library.

```bash
# Install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Scan with CVE templates
nuclei -u https://target.example.com -t cves/ -severity medium,high,critical

# Multiple template categories
nuclei -u https://target.example.com \
  -t cves/ -t exposures/ -t misconfiguration/ \
  -severity high,critical \
  -o nuclei-results.txt

# Automatic template selection based on tech stack
nuclei -u https://target.example.com -as

# Scan multiple targets
nuclei -list targets.txt -t cves/ -c 50

# GitHub Actions
- name: Nuclei Scan
  uses: projectdiscovery/nuclei-action@main
  with:
    target: https://staging.example.com
    flags: "-severity high,critical"
```

**Custom Nuclei template:**
```yaml
id: custom-debug-endpoint

info:
  name: Debug Endpoint Exposed
  author: security-team
  severity: high
  tags: exposure,debug

http:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/admin/debug"
      - "{{BaseURL}}/_debug"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "debug"
          - "stack trace"
        condition: or
        part: body
```

### API Security Testing — OWASP API Top 10

| Risk | Description | Test Approach |
|------|-------------|---------------|
| API1 — BOLA | Broken Object Level Authorization | Change object IDs in requests (`/users/1` → `/users/2`) |
| API2 — Broken Auth | Weak authentication | Test with expired/invalid tokens, no token |
| API3 — BOPLA | Broken Object Property Level Auth | Request sensitive fields not in UI |
| API4 — Unrestricted Resource Consumption | No rate limiting | Rapid fire requests, large payloads |
| API5 — BFLA | Broken Function Level Authorization | Access admin endpoints as regular user |
| API6 — Unrestricted Business Flow | No abuse prevention | Automate checkout, skip payment steps |
| API7 — SSRF | Server-Side Request Forgery | Inject internal URLs in URL parameters |
| API8 — Security Misconfiguration | Default creds, verbose errors | Check headers, error messages |
| API9 — Improper Inventory Management | Shadow/undocumented APIs | Enumerate API versions, old endpoints |
| API10 — Unsafe Consumption of APIs | Trusting 3rd party APIs | Inject malicious data via 3rd party |

**Automated API testing tools:**
- **RESTler** (Microsoft): fuzzes REST APIs based on OpenAPI spec
- **CATS** (Endpoint Fuzzer): `cats --contract=openapi.yml --server=https://api.example.com`
- **42Crunch API Security Audit**: static analysis of OpenAPI specs

---

## 7. Container Security in CI/CD

### Trivy (Aqua Security)

The most comprehensive open-source container security scanner — images, filesystems, IaC, SBOM.

```bash
# Scan Docker image
trivy image nginx:latest --severity HIGH,CRITICAL

# Scan with SARIF output (GitHub integration)
trivy image --format sarif --output trivy-results.sarif myapp:latest

# Scan filesystem / repository
trivy fs . --security-checks vuln,config,secret

# Scan Kubernetes cluster
trivy k8s --report all cluster

# Generate SBOM
trivy image --format spdx-json --output sbom.spdx.json myapp:latest
trivy image --format cyclonedx --output sbom.cyclonedx.json myapp:latest

# Scan IaC files
trivy config ./terraform/
trivy config ./k8s-manifests/

# GitHub Actions with SARIF upload
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:${{ github.sha }}'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    ignore-unfixed: true

- name: Upload Trivy scan results to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

**.trivyignore (suppress known false positives):**
```
# CVE-2023-1234 -- false positive in alpine base, does not affect our usage
CVE-2023-1234
# Suppress entire package
golang.org/x/net
```

### Security-Focused Dockerfile Best Practices

```dockerfile
# 1. Use specific digest — not mutable tag
FROM node:20-alpine@sha256:abc123def456...

# 2. Run as non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup
USER appuser

# 3. Multi-stage build — minimize attack surface
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY . .
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
# Copy only what's needed
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
# No secrets in ENV (inject at runtime)
EXPOSE 3000
CMD ["node", "dist/server.js"]

# 4. Labels for tracking
LABEL org.opencontainers.image.source="https://github.com/org/repo"
LABEL org.opencontainers.image.revision="${GIT_SHA}"

# 5. Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1
```

### Kubernetes Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /app/.cache
      volumes:
        - name: tmp
          emptyDir: {}
        - name: cache
          emptyDir: {}
```

### Hadolint (Dockerfile Linting)

```bash
# CLI
hadolint Dockerfile
hadolint --ignore DL3008 --ignore DL3009 Dockerfile

# GitHub Actions
- name: Lint Dockerfile
  uses: hadolint/hadolint-action@v3.1.0
  with:
    dockerfile: Dockerfile
    ignore: DL3008,DL3009
    failure-threshold: warning
```

**Key Hadolint rules:**
- `DL3006` — Always tag Docker images (avoid `latest`)
- `DL3007` — Pin Docker image versions
- `DL3008` — Pin package versions in apt-get install
- `DL3013` — Pin pip package versions
- `DL3020` — Use COPY instead of ADD for files
- `DL3025` — Use JSON array CMD
- `SC2086` — Double-quote variables to prevent word splitting

### Container Image Signing (Cosign + Sigstore)

```bash
# Install cosign
brew install cosign  # or download from releases

# Generate key pair
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key myregistry.io/myapp:latest

# Verify signature
cosign verify --key cosign.pub myregistry.io/myapp:latest

# Keyless signing (using OIDC, no key management)
cosign sign myregistry.io/myapp:latest  # uses Fulcio CA + Rekor transparency log

# Verify keyless
cosign verify --certificate-identity=user@example.com \
  --certificate-oidc-issuer=https://accounts.google.com \
  myregistry.io/myapp:latest
```

---

## 8. Infrastructure as Code (IaC) Security

### Checkov (Bridgecrew/Prisma Cloud)

Multi-framework IaC scanner — Terraform, CloudFormation, Kubernetes, Helm, ARM, Bicep.

```bash
# Scan Terraform
checkov -d . --framework terraform

# Specific checks only
checkov -d . --check CKV_AWS_18,CKV_AWS_20

# Skip certain checks
checkov -d . --skip-check CKV_AWS_8

# SARIF output
checkov -f main.tf --output sarif > checkov-results.sarif

# GitHub Actions
- name: Checkov IaC Scan
  uses: bridgecrewio/checkov-action@master
  with:
    directory: terraform/
    framework: terraform
    output_format: sarif
    output_file_path: checkov-results.sarif
    soft_fail: false
```

### tfsec (Terraform-Specific)

```bash
# Basic scan
tfsec .

# SARIF output
tfsec . --format sarif --out tfsec-results.sarif

# Custom checks
tfsec . --custom-check-dir ./custom-checks/

# Ignore specific warning
# tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "example" {
  ...
}
```

### KICS (Keeping Infrastructure as Code Secure)

```bash
# Install
curl -sfL https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh | bash

# Scan
kics scan -p ./terraform -o results/ --report-formats sarif,json

# Scan multiple types
kics scan -p ./ --type Terraform,CloudFormation,Kubernetes -o results/
```

### Key IaC Security Controls

**AWS Terraform security checks:**
```hcl
# S3 — block all public access
resource "aws_s3_bucket_public_access_block" "main" {
  bucket                  = aws_s3_bucket.main.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# RDS — encryption at rest, no public access
resource "aws_db_instance" "main" {
  storage_encrypted      = true
  publicly_accessible    = false
  deletion_protection    = true
  backup_retention_period = 7
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
}

# Security Group — no 0.0.0.0/0 ingress on sensitive ports
resource "aws_security_group_rule" "bad_example" {
  # WRONG: Open SSH to the world
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # checkov: CKV_AWS_25
}

# IAM — no wildcard
resource "aws_iam_policy" "bad_example" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"      # checkov: CKV_AWS_49
      Resource = "*"
    }]
  })
}
```

**Checklist of IaC security controls:**
- [ ] S3 bucket public access block enabled
- [ ] S3 bucket versioning and MFA delete
- [ ] RDS encryption at rest + in transit
- [ ] EBS volume encryption
- [ ] No security groups with 0.0.0.0/0 on SSH (22) or RDP (3389)
- [ ] CloudTrail enabled with log file validation
- [ ] VPC flow logs enabled
- [ ] IMDSv2 required on EC2 instances
- [ ] EKS cluster endpoint not public
- [ ] Lambda functions not publicly accessible
- [ ] IAM policies use least privilege (no `*` actions)
- [ ] KMS key rotation enabled

---

## 9. GitHub Actions Security Hardening

### Principle of Least Privilege

Always declare minimal workflow permissions:

```yaml
# Global default — read only
permissions: read-all

# Or per-workflow with specific grants
permissions:
  contents: read        # read-only checkout
  security-events: write  # SARIF upload to Security tab
  pull-requests: write   # PR comments only
  id-token: write        # OIDC for cloud auth
  packages: write        # Push to GitHub Packages
```

### Pin Actions to Commit SHA

Mutable tags like `@v4` can be hijacked by supply chain attacks. Pin to a specific commit SHA:

```yaml
# BAD — mutable tag, can be changed by attacker
- uses: actions/checkout@v4
- uses: actions/setup-node@v4

# GOOD — pinned to immutable SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
- uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4.0.2
```

**Automate with Dependabot:**
```yaml
# .github/dependabot.yml
- package-ecosystem: "github-actions"
  directory: "/"
  schedule:
    interval: "weekly"
```

### Prevent Script Injection

Untrusted event data (PR titles, commit messages, branch names) can inject commands:

```yaml
# BAD — direct interpolation enables injection
- run: |
    echo "Building PR: ${{ github.event.pull_request.title }}"
    git tag "${{ github.event.pull_request.head.ref }}"

# GOOD — pass through environment variable
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    BRANCH: ${{ github.event.pull_request.head.ref }}
  run: |
    echo "Building PR: $PR_TITLE"
    git tag "$BRANCH"
```

### OIDC for Cloud Authentication

Eliminate long-lived cloud credentials stored as secrets:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  # AWS
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/github-actions-role
      aws-region: us-east-1
      role-session-name: GitHubActionsSession

  # GCP
  - uses: google-github-actions/auth@v2
    with:
      workload_identity_provider: projects/123/locations/global/workloadIdentityPools/pool/providers/provider
      service_account: github-actions@project.iam.gserviceaccount.com

  # Azure
  - uses: azure/login@v2
    with:
      client-id: ${{ secrets.AZURE_CLIENT_ID }}
      tenant-id: ${{ secrets.AZURE_TENANT_ID }}
      subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

### Secrets Best Practices

```yaml
# Store in: Settings → Secrets and variables → Actions
# OR use Environments for deployment-specific secrets

# Reference in workflow
- name: Deploy
  env:
    DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
    API_KEY: ${{ secrets.API_KEY }}
  run: ./deploy.sh

# NEVER do:
- run: echo "${{ secrets.DB_PASSWORD }}"  # logs to console!
- run: curl https://api.example.com?key=${{ secrets.API_KEY }}  # URL logged!

# Secrets are automatically masked in logs when referenced via ${{ secrets.X }}
# but NOT when echoed explicitly or passed in URLs
```

### Restrict Workflow Triggers

```yaml
# DANGEROUS: pull_request_target has write access + runs attacker code
on:
  pull_request_target:
    types: [opened, synchronize]

# Use pull_request instead (no write access, safe for external PRs)
on:
  pull_request:
    branches: [main, develop]

# If you MUST use pull_request_target, never checkout PR code:
- uses: actions/checkout@v4
  with:
    ref: ${{ github.base_ref }}  # checkout base, not PR head
```

### Workflow Linting Tools

```bash
# actionlint — lint workflow files
brew install actionlint
actionlint .github/workflows/*.yml

# zizmor — deeper security analysis
pip install zizmor
zizmor .github/workflows/

# GitHub Actions Security Hardening checklist (Datree)
```

### Branch Protection Rules

Enforce in repository settings:
- [ ] Require PR before merging (no direct push to main)
- [ ] Require status checks to pass (security scans must pass)
- [ ] Require code review (1-2 approvals)
- [ ] Require conversation resolution
- [ ] Do not allow force pushes
- [ ] Do not allow deletions
- [ ] Require signed commits

---

## 10. SBOM (Software Bill of Materials) in CI/CD

### Why SBOM Matters

**Executive Order 14028** (US, May 2021) mandates SBOMs for software sold to federal government. Beyond compliance:
- Rapid vulnerability response: know within minutes which products are affected by CVE-2021-44228 (Log4Shell)
- Transparency for customers and auditors
- Supply chain risk visibility

**SBOM formats:**
- **SPDX** (ISO/IEC 5962:2021) — Linux Foundation standard
- **CycloneDX** — OWASP standard, richer security metadata
- **SWID** (ISO/IEC 19770-2) — enterprise asset management

### Generate SBOM in CI (Syft + Grype)

```yaml
# GitHub Actions
- name: Generate SBOM with Syft
  uses: anchore/sbom-action@v0
  with:
    image: myapp:${{ github.sha }}
    format: spdx-json
    artifact-name: sbom.spdx.json

- name: Scan SBOM for vulnerabilities with Grype
  uses: anchore/scan-action@v3
  with:
    sbom: sbom.spdx.json
    fail-build: true
    severity-cutoff: high
    output-format: sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.scan.outputs.sarif }}
```

```bash
# CLI usage
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM
syft myapp:latest -o spdx-json > sbom.spdx.json
syft myapp:latest -o cyclonedx-json > sbom.cyclonedx.json
syft dir:./src -o spdx-json > sbom.spdx.json

# Scan SBOM with Grype
grype sbom:sbom.spdx.json --fail-on high
grype myapp:latest --fail-on critical
```

### SBOM Attestation (Cosign + Sigstore)

Cryptographically sign and verify SBOMs:

```bash
# Sign SBOM as an attestation
cosign attest \
  --predicate sbom.spdx.json \
  --type spdxjson \
  myregistry.io/myapp:latest

# Verify SBOM attestation
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity=ci@company.com \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  myregistry.io/myapp:latest | jq '.payload | @base64d | fromjson'
```

### SLSA (Supply Chain Levels for Software Artifacts)

SLSA (pronounced "salsa") is a framework for supply chain security:

| Level | Requirements |
|-------|-------------|
| SLSA 1 | Build process documented, provenance generated |
| SLSA 2 | Version control, authenticated provenance |
| SLSA 3 | Hardened build platform, non-falsifiable provenance |
| SLSA 4 | Two-party review, hermetic builds |

```yaml
# Generate SLSA provenance in GitHub Actions
- uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
  with:
    base64-subjects: "${{ needs.build.outputs.hashes }}"
```

---

## 11. Security Gates in CI/CD Pipeline

### Full Pipeline Security Architecture

```
Developer Workstation
├── IDE plugins: SonarLint, Snyk IDE, Semgrep (real-time feedback)
└── Pre-commit hooks: gitleaks, detect-secrets, code formatting

Code Commit / Push
├── Branch protection: require PR, signed commits
└── GitHub Secret Scanning: push protection blocks secrets

Pull Request / CI Build
├── SAST: Semgrep (fast, <2min), CodeQL (thorough, ~15min)
│   └── Results as PR annotations, block merge on High/Critical
├── SCA: Snyk or Dependabot
│   └── Block on Critical CVE with available fix
├── Secret scanning: Gitleaks
│   └── Block immediately on any new secret
├── IaC scanning: Checkov, tfsec
│   └── Block on policy violations (configurable severity)
├── License compliance: FOSSA
│   └── Warn on GPL, block on AGPL/proprietary conflicts
└── Workflow security: actionlint, zizmor

Container Build Gate
├── Image scan: Trivy
│   └── Block on Critical CVE in OS packages or app deps
├── Dockerfile lint: Hadolint
├── SBOM generation: Syft (attach to artifact)
└── Image signing: Cosign (sign with OIDC)

Staging Deployment Gate
├── DAST: OWASP ZAP API scan
│   └── Block on OWASP Top 10 findings (High+)
├── Nuclei: template-based CVE checks
└── Smoke tests: verify health endpoints, auth flows

Production Deployment Gate
├── Approval: security sign-off for major changes
├── Attestation: verify SLSA + SBOM + image signature
└── Change management: CAB approval for regulated environments

Post-Deployment
├── Runtime security: Falco (K8s syscall monitoring)
├── RASP: Contrast Security, Sqreen (request-level protection)
├── Continuous monitoring: CloudTrail → SIEM alerts
└── Periodic penetration testing (quarterly)
```

### Configuring Quality Gates

**GitHub branch protection rulesets:**
```yaml
# Via GitHub API
{
  "name": "main-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "pull_request", "parameters": {"required_approving_review_count": 1}},
    {"type": "required_status_checks", "parameters": {
      "required_status_checks": [
        {"context": "CodeQL / analyze (javascript)"},
        {"context": "Semgrep / semgrep"},
        {"context": "Snyk / snyk-test"}
      ],
      "strict_required_status_checks_policy": true
    }},
    {"type": "non_fast_forward"},
    {"type": "deletion"}
  ]
}
```

### Fail-Fast vs. Warn-Only Strategy

| Finding Type | Recommended Gate | Rationale |
|-------------|-----------------|-----------|
| Critical CVE (exploitable, fix available) | Hard block | High risk, actionable |
| High CVE (fix available) | Block with override | High risk, should fix |
| High CVE (no fix available) | Warn + track | Can't fix, track debt |
| Medium CVE | Warn | Background noise if always blocking |
| SAST Critical | Hard block | Code issue, must fix |
| SAST High | Block | Strong signal |
| SAST Medium | Warn | Review triage first |
| Secret detected | Hard block | Immediate risk |
| IaC policy violation | Block | Infrastructure risk |
| License conflict | Warn → escalate | Legal review needed |

---

## 12. Secrets Management in Applications

### Anti-Patterns to Avoid

```python
# NEVER: Hardcode secrets
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-abc123..."

# NEVER: Committed .env files
# .env
DATABASE_URL=postgresql://user:password@host/db

# NEVER: Environment variables set in Dockerfile
ENV DB_PASSWORD=secret  # visible in image layers!

# NEVER: Log secrets
logger.info(f"Connecting with password: {db_password}")

# NEVER: Secrets in Git history (even if later deleted)
# git filter-branch or BFG needed if this happens
```

### Correct Approaches

**12-Factor App — Config from Environment:**
```python
import os
from functools import lru_cache

@lru_cache
def get_settings():
    return {
        "db_url": os.environ["DATABASE_URL"],      # Required — fail fast if missing
        "api_key": os.environ.get("API_KEY", ""),  # Optional
        "debug": os.environ.get("DEBUG", "false").lower() == "true"
    }
```

### AWS Secrets Manager

```python
import boto3
import json
from botocore.exceptions import ClientError

def get_secret(secret_name: str, region: str = "us-east-1") -> dict:
    client = boto3.client("secretsmanager", region_name=region)
    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise RuntimeError(f"Failed to retrieve secret {secret_name}: {e}")

    secret = response.get("SecretString") or \
             base64.b64decode(response["SecretBinary"]).decode("utf-8")
    return json.loads(secret)

# Usage
creds = get_secret("prod/myapp/database")
DB_HOST = creds["host"]
DB_PASSWORD = creds["password"]
```

```bash
# CLI
aws secretsmanager get-secret-value --secret-id prod/myapp/db --query SecretString --output text
```

### HashiCorp Vault

```bash
# Vault Agent — auto-inject secrets as files or env vars
vault agent -config=vault-agent.hcl

# vault-agent.hcl
auto_auth {
  method "kubernetes" {
    config = {
      role = "my-app-role"
    }
  }
}

template {
  source      = "/etc/vault-templates/db-config.ctmpl"
  destination = "/etc/app/db.env"
}
```

**Kubernetes External Secrets Operator:**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
    - secretKey: db-password
      remoteRef:
        key: prod/myapp/database
        property: password
```

### Secret Rotation

```python
# AWS Secrets Manager automatic rotation Lambda
def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    if step == "createSecret":
        # Generate new password
        new_password = generate_secure_password()
        put_secret_value(arn, token, new_password)

    elif step == "setSecret":
        # Update the actual database/service
        set_new_password_in_database(new_password)

    elif step == "testSecret":
        # Verify new credentials work
        test_database_connection(new_password)

    elif step == "finishSecret":
        # Mark new version as AWSCURRENT
        finalize_rotation(arn, token)
```

---

## 13. OWASP DevSecOps Guideline

**Official resource:** https://owasp.org/www-project-devsecops-guideline/

The OWASP DevSecOps Guideline covers the entire pipeline from pre-commit to production.

### OWASP Top 10 CI/CD Security Risks

Reference: https://owasp.org/www-project-top-10-ci-cd-security-risks/

| Risk | Name | Description | Mitigation |
|------|------|-------------|-----------|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms | Unauthorized pipeline triggers or bypasses | Branch protection, required PR reviews, job conditions |
| CICD-SEC-2 | Inadequate Identity and Access Management | Excessive permissions on CI/CD systems | OIDC, least privilege, no shared service accounts |
| CICD-SEC-3 | Dependency Chain Abuse | Typosquatting, dependency confusion attacks | Lockfiles, private registries, SCA scanning |
| CICD-SEC-4 | Poisoned Pipeline Execution (PPE) | Code injection via CI config in PR | Avoid `pull_request_target`, review CI config changes |
| CICD-SEC-5 | Insufficient PBAC | Pipeline jobs have too many permissions | Scope tokens per job, use environments |
| CICD-SEC-6 | Insufficient Credential Hygiene | Long-lived secrets, secrets in logs | OIDC, secret scanning, auto-rotation |
| CICD-SEC-7 | Insecure System Configuration | Default credentials, unpatched CI runners | Harden runners, ephemeral runners, patch management |
| CICD-SEC-8 | Ungoverned Usage of 3rd Party Services | Unreviewed GitHub Actions, cloud services | Action allowlists, vendor review process |
| CICD-SEC-9 | Improper Artifact Integrity Validation | Running unsigned or unverified artifacts | Image signing (Cosign), SLSA provenance |
| CICD-SEC-10 | Insufficient Logging and Visibility | No audit trail for pipeline events | SIEM integration, pipeline audit logs |

### Dependency Confusion Attack (CICD-SEC-3)

One of the most impactful supply chain attacks:

```bash
# Attacker publishes malicious package to public registry (npm/PyPI)
# with same name as your internal private package but higher version number.
# Build system fetches from public registry first.

# Mitigation 1: Use scoped packages (npm @company/package-name)
# Mitigation 2: Set registry to private first with fallthrough disabled
# npm config:
# @company:registry=https://internal-npm.company.com
# always-auth=true

# Mitigation 3: Pin all dependencies with lockfiles
# Mitigation 4: Hash verification in CI
# Mitigation 5: Network egress controls on build runners
```

### OWASP SAMM Toolbox Mapping

| SAMM Activity | DevSecOps Control |
|--------------|-------------------|
| Threat Assessment | Threat Dragon in repo, threat modeling in sprint |
| Security Requirements | Abuse cases as acceptance criteria |
| Secure Build | SAST, SCA, secret scanning in CI |
| Secure Deployment | IaC scanning, image signing, deployment gates |
| Defect Management | SAST results tracked in issue tracker |
| Security Testing | DAST in staging pipeline |

---

## 14. Compliance Integration

### SOC 2 Type II

SOC 2 auditors look for **evidence** that controls operate continuously. CI/CD automation provides automated, auditable evidence.

| SOC 2 Criterion | CI/CD Control | Evidence |
|-----------------|---------------|---------|
| CC6.1 — Logical Access | Branch protection, required reviews | GitHub audit log |
| CC6.2 — Authentication | SSO required, MFA enforced | IdP audit log |
| CC6.3 — Segregation of duties | No direct commits to main | Branch protection settings |
| CC7.1 — Change management | All changes via PR, approved by reviewer | PR history |
| CC7.2 — Monitoring | SIEM alerts on anomalous events | SIEM logs |
| CC8.1 — Change management | Automated tests + security scans must pass | CI/CD run history |

### PCI DSS v4.0

| Requirement | Description | Implementation |
|-------------|-------------|----------------|
| 6.2.4 | Prevent common software vulnerabilities | SAST (Semgrep/CodeQL) + DAST (ZAP) in pipeline |
| 6.3.1 | Maintain security policies for development | SDLC policy doc, developer training |
| 6.3.2 | Software inventory | SBOM generated per build |
| 6.4.1 | WAF deployed | AWS WAF / Cloudflare in front of CHD environment |
| 6.4.2 | WAF detecting and preventing web attacks | WAF rules, blocking mode |
| 6.5.1 | Protect web-facing apps | DAST + SAST + RASP |
| 12.3.2 | Targeted risk analysis | Risk assessment for each significant change |

### NIST SSDF (SP 800-218)

Secure Software Development Framework — referenced in EO 14028 and CISA guidance.

| Practice | ID | Implementation |
|----------|-----|----------------|
| Implement supporting toolchains | PO.3 | SAST/SCA/DAST toolchain in CI/CD |
| Implement secure environments | PO.5 | Hardened CI runners, ephemeral environments |
| Protect all code from unauthorized access | PS.1 | Branch protection, signed commits |
| Verify third-party software compliance | PW.4 | SCA scanning, vendor assessments |
| Design software to meet security requirements | PW.1 | Threat modeling, security architecture review |
| Review and/or analyze human-readable code | PW.7 | SAST + manual code review |
| Test executable code | PW.8 | DAST, IAST, penetration testing |
| Identify and confirm vulnerabilities | RV.1 | Triaging SAST/SCA/DAST findings |
| Analyze vulnerabilities to determine root cause | RV.2 | Post-incident analysis, RCA process |
| Address vulnerabilities | RV.3 | Remediation SLAs, patch pipeline |

### FedRAMP / FISMA

For US federal or FedRAMP-authorized systems:
- NIST SP 800-53 Rev 5 controls apply
- **SA-11**: Developer Security Testing and Evaluation — requires SAST, DAST
- **SA-15**: Development Process, Standards, and Tools — approved toolchain
- **CM-14**: Signed Components — SBOM + code signing
- **RA-5**: Vulnerability Monitoring and Scanning — continuous SCA + image scanning

### ISO/IEC 27001:2022

| Control | Annex A Reference | Implementation |
|---------|-------------------|----------------|
| Secure development policy | A.8.25 | SDLC policy, developer training |
| Secure development environment | A.8.31 | Hardened CI/CD, network segmentation |
| Application security testing | A.8.29 | SAST + DAST in pipeline |
| Secure coding | A.8.28 | Secure coding standards + SAST enforcement |
| Outsourced development | A.8.30 | SCA for third-party components |

---

## Quick Reference: Tool Selection

| Need | Open Source | Commercial |
|------|------------|-----------|
| SAST (fast) | Semgrep | Checkmarx, Veracode |
| SAST (thorough) | CodeQL | SonarQube Enterprise |
| SCA | OSV-Scanner, OWASP DC | Snyk, Mend (WhiteSource) |
| Secrets detection | Gitleaks, detect-secrets | Nightfall, GitGuardian |
| Container scanning | Trivy, Grype | Aqua Security, Sysdig |
| DAST | OWASP ZAP, Nuclei | Invicti, Rapid7 InsightAppSec |
| IaC scanning | Checkov, tfsec, KICS | Prisma Cloud, Wiz |
| SBOM | Syft, Trivy | Anchore Enterprise |
| Secret management | HashiCorp Vault (OSS) | AWS Secrets Manager, Azure Key Vault |
| Workflow security | actionlint, zizmor | Legit Security, Cycode |

---

*Part of the [TeamStarWolf Cybersecurity Reference Library](README.md)*
