# Application Security Testing

This reference covers the methods used to find security defects in software: static analysis, software composition analysis, software bills of materials, dynamic analysis, interactive analysis, secrets scanning, and runtime protection. It explains what each method sees, what it misses, where it fits in the development lifecycle, and how the findings are triaged. It is written for a vulnerability management or application security analyst who has to combine several testing tools into one defensible picture of application risk.

| Attribute | Value |
|---|---|
| Methods | SAST, SCA, SBOM, DAST, IAST, secrets scanning, RASP |
| Targets | Source code, dependencies, running applications, APIs, containers, IaC |
| Finding identity | CWE, OWASP Top 10, CVE (for dependencies), tool rule IDs |
| Workflow target | ASPM or defect trackers; ServiceNow Application Vulnerability Response |

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Application security and vulnerability management analysts combining code, dependency, and running-application testing

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,348 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to know what SAST, DAST, IAST, SCA, and SBOM each find and miss, you are deciding which methods to gate a pipeline on, or you are consolidating application findings alongside infrastructure findings

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[The testing methods at a glance](#the-testing-methods-at-a-glance), [Choosing and combining methods](#choosing-and-combining-methods), [Where these fit in the SDLC](#where-these-fit-in-the-sdlc)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](SECURE_CODING_REFERENCE.md), [Web Application Security Reference](WEB_APPLICATION_SECURITY_REFERENCE.md), [DevSecOps Reference](DEVSECOPS_REFERENCE.md), [Scanner Platforms and Findings Catalog](SCANNER_PLATFORMS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## The testing methods at a glance

Each method trades coverage against accuracy and against how early it runs.

- Static analysis (SAST) reads source or bytecode without running it. Earliest signal, full code reach, higher false positives, no runtime proof.
- Software composition analysis (SCA) inventories third-party and open-source dependencies and matches them to known vulnerabilities. Finds `CVE`s you inherited rather than wrote.
- Software bill of materials (SBOM) is the dependency inventory itself, in a standard format, that SCA and incident response consume.
- Dynamic analysis (DAST) exercises a running application from the outside. Finds runtime, configuration, and authentication issues; cannot point to the line of code.
- Interactive analysis (IAST) instruments a running application during testing, combining static context with runtime confirmation.
- Secrets scanning looks for credentials committed to code or configuration.
- Runtime protection (RASP) is a defense that runs inside the application in production; it is a control, not a testing method, and is included here for contrast.

A single weakness class often shows up in more than one method: an injection flaw can be predicted by SAST, confirmed by DAST or IAST, and the vulnerable parser behind it flagged by SCA.

## Static analysis (SAST)

SAST parses code into an abstract syntax tree and data-flow graph and traces untrusted input from sources (request parameters) to sinks (a query, a command, the file system). It runs with no deployed application, so it fits pre-commit hooks, pull-request checks, and build pipelines.

- Strengths: runs on the first line of code, reaches paths that tests never exercise, and names the exact file and line.
- Weaknesses: false positives from paths that cannot actually be reached, no view of runtime configuration, and difficulty with dynamic language features.
- Finding identity: `CWE` and the tool's own rule ID; severity from the rule plus context.
- Common tools: `Semgrep`, `CodeQL`, `SonarQube`, `Snyk Code`, Checkmarx, and Fortify.

Tune SAST by suppressing confirmed-safe rules per repository rather than lowering severity globally, so new instances of a real issue still surface.

## Software composition analysis (SCA)

Most code in an application is not written in-house. SCA reads the dependency manifests and lockfiles, resolves the full transitive tree, and matches each component and version to advisory databases.

- Finds: known `CVE`s in direct and transitive dependencies, and license obligations.
- Key nuance: reachability. A vulnerable function in a dependency matters only if the application calls it; mature SCA distinguishes a present vulnerability from a reachable one, which cuts noise.
- Finding identity: `CVE` plus the package and fixed version, usually with a direct upgrade path.
- Common tools: `Snyk Open Source`, GitHub Dependabot, `syft` plus `Grype`, OWASP Dependency-Check, and `Trivy`.

## Software bill of materials (SBOM)

An SBOM is a formal, machine-readable list of the components in a piece of software, in a standard format (CycloneDX or SPDX). It is the input SCA matches against advisories, and the artifact incident response uses to answer "are we affected" when a new dependency vulnerability lands.

- Generation: `syft` and `cdxgen` produce an SBOM from source, a build, or a container image.
- Consumption: `Grype` and other scanners read an SBOM and report vulnerabilities without re-scanning.
- VEX (Vulnerability Exploitability eXchange) rides alongside an SBOM to state that a listed vulnerability is or is not exploitable in this product, so consumers can stand down on components that are present but not reachable. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

## Dynamic analysis (DAST)

DAST sends requests to a running application and reads the responses, with no access to source. It behaves like an external attacker, so it finds issues that only exist at runtime.

- Strengths: catches server and framework misconfiguration, authentication and session flaws, and injection that actually responds; it is language-agnostic.
- Weaknesses: only reaches what it can crawl or is told about, so coverage depends on authentication and API definitions, and it cannot name the vulnerable code.
- Finding identity: weakness class mapped to `CWE` and the OWASP Top 10; severity from the tool.
- Common tools: `Invicti` (which includes the former Acunetix), Burp Suite, OWASP ZAP, and `Nuclei`. For APIs, point the scanner at an OpenAPI definition so it exercises every endpoint, not just what it can crawl.
- Proof-based scanning: some DAST tools safely confirm a finding by demonstrating it, which removes most false positives from the queue.

## Interactive analysis (IAST)

IAST places an agent inside the running application while functional or DAST tests drive it. The agent watches data flow from inside, so it reports a runtime-confirmed finding with the code location attached.

- Strengths: low false positives (the flaw was observed executing) with the precision of a code location.
- Weaknesses: needs an agent in the test environment and only covers code paths the tests exercise.
- Common tools: Contrast Security and Seeker.

## Secrets scanning

Credentials committed to a repository are a recurring breach cause. Secrets scanning matches known credential patterns and high-entropy strings across code, history, and configuration.

- Common tools: `gitleaks`, `TruffleHog`, and `ggshield`.
- Place it in pre-commit hooks and in CI so a secret is caught before it merges; rotate any secret that reaches history, because deletion alone does not revoke it. See [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md).

## Runtime protection (RASP)

RASP instruments the production application and blocks exploitation at runtime, for example stopping an injection as it executes. It is a mitigating control, not a test, and does not replace fixing the defect; treat it as defense in depth while remediation proceeds.

## Where these fit in the SDLC

Shift-left means running the cheapest, earliest method that can catch a class of defect, without removing the later gates that catch what earlier ones miss.

- Pre-commit: secrets scanning and fast SAST on changed files.
- Pull request: SAST and SCA as required status checks, failing on new high-severity findings only.
- Build: full SAST, SCA, SBOM generation, and container image scanning.
- Pre-deploy: DAST or IAST against a staging deployment.
- Production: RASP and continuous dependency monitoring, since new `CVE`s land against code that has not changed. See [DevSecOps Reference](/DEVSECOPS_REFERENCE.md).

## Choosing and combining methods

No single method is sufficient; they cover different defect classes.

- First-party logic flaws (injection, access control): SAST predicts, DAST or IAST confirms.
- Inherited vulnerabilities: SCA and SBOM, with reachability to cut noise.
- Runtime and configuration: DAST.
- Leaked credentials: secrets scanning.

Gate on new findings, not the standing backlog, so a pipeline does not block on debt while still stopping new high-severity issues. Calibrate each tool's false-positive profile before you make it blocking: SAST and unauthenticated DAST are the noisiest, IAST and proof-based DAST the cleanest.

## Where findings go

Application findings are consolidated the same way scanner findings are, so they do not live in separate tool silos.

- An application security posture management (ASPM) tool or a defect aggregator such as `DefectDojo` deduplicates findings across SAST, DAST, SCA, and IAST, and tracks them against the application.
- From there, findings route to the developer's tracker for the fix and, where the organization runs it, to ServiceNow Application Vulnerability Response for program-level reporting alongside infrastructure findings. See [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md) for the infrastructure side and the ServiceNow flow.
- Prioritize with the same precedence as infrastructure findings: known exploitation first, then likelihood, then environment. See [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).

## Learning resources

- The OWASP Top 10 and OWASP Application Security Verification Standard frame what to test for; confirm the current edition before citing a specific list.
- For the weakness classes themselves, see [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md); for dependency and build-chain risk, see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Application and supply chain security](/hubs/application-and-supply-chain.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [DevSecOps Reference](/DEVSECOPS_REFERENCE.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)

<!-- related:end -->
