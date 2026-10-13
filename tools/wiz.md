# Wiz

*Wiz, Inc. (acquired by Google / Alphabet; part of Google Cloud) · Agentless Cloud-Native Application Protection Platform (CNAPP)*

Wiz is a unified, agentless CNAPP that scans entire multicloud environments by connecting to cloud provider APIs and analyzing workload snapshots, then normalizes everything into the Wiz Security Graph to surface the toxic combinations and attack paths that create real, exploitable risk. It solves the problem of fragmented cloud security point tools by giving one agentless platform covering posture, workloads, data, identities, containers, code and runtime. It is known for fast time-to-value and for prioritizing the handful of truly critical issues out of thousands of findings.

## Capabilities & architecture

**Core capabilities**
- CSPM - cloud security posture management and compliance across AWS/Azure/GCP/OCI/Alibaba and Kubernetes
- CWPP - agentless workload scanning for vulnerabilities, malware, secrets and misconfigurations via snapshot analysis
- CIEM - cloud infrastructure entitlement management (effective identity/permissions, privilege risk)
- DSPM - data security posture management (sensitive-data discovery and exposure)
- KSPM - Kubernetes security posture management; container and registry scanning
- AI-SPM - AI pipeline/model security posture
- Wiz Code - IaC scanning and code-to-cloud / CI-CD and PR security (shift-left)
- Wiz Defend (CDR) - cloud detection and response / runtime threat detection, strengthened by the Gem Security acquisition; optional lightweight runtime sensor
- Wiz Security Graph - the correlation engine mapping attack paths across all the above; Wiz Explorer for graph queries

**Architecture & deployment.** Primarily agentless SaaS. Wiz connects to cloud accounts via API/role with read permissions and performs snapshot-based scanning of workloads (no agent on each VM for baseline coverage), building the Security Graph in the Wiz tenant. An optional lightweight eBPF-based runtime sensor can be deployed for real-time detection and response where deeper runtime telemetry is needed. Deploys in minutes to hours across multicloud; data is analyzed in Wiz's SaaS with configurable scanning scope.

**Editions & licensing.** Subscription priced per cloud workload (resource), typically billed in 100-workload increments; no public list price, contracts negotiated. Tiers commonly structured as Essential and Advanced (Advanced adds broader modules such as CIEM/DSPM/AI-SPM and runtime coverage - exact tier contents vary and should be confirmed), with the runtime sensor (Wiz Defend) as an add-on priced per sensor. Third-party benchmarks cite roughly $24k/yr per 100 workloads (Essential) to $38k/yr (Advanced) with a runtime-sensor add-on ~$28k/yr per 100, median enterprise contracts ~$149k-$154k/yr and ~22% average discount off list; enterprise 1,000-5,000-workload deals commonly $100k-$200k+/yr (all third-party estimates - confirm with a quote).

**Key integrations.** SIEM/SOAR (Splunk, Microsoft Sentinel, Google Chronicle/SecOps, Sumo Logic); Ticketing (Jira, ServiceNow); Clouds (AWS, Azure, GCP, OCI, Alibaba) and Kubernetes; Identity (Entra ID, Okta, AWS IAM); CI/CD and code (GitHub, GitLab, Azure DevOps); Ingests AWS Inspector/GuardDuty and other scanner findings; Validates/consumes hardened images (Chainguard integration); Messaging (Slack, Teams); deep Google Cloud Security alignment post-acquisition.

**Differentiators**
- Agentless, graph-based correlation (Security Graph) that collapses thousands of alerts into a few real attack paths / toxic combinations - the category-defining strength
- Extremely fast deployment and time-to-value (minutes to full-environment visibility)
- True multicloud breadth with consistent model across providers
- Single platform spanning CSPM/CWPP/CIEM/DSPM/KSPM/AI-SPM/code/CDR, reducing tool sprawl
- Strong usability and prioritization that security and dev teams both adopt

**Limitations & considerations**
- Premium pricing; per-workload model gets expensive at scale and tier/module contents are opaque (negotiated, no list price)
- Baseline agentless snapshot scanning is periodic, not continuous real-time - true runtime detection requires the add-on sensor (extra cost/ops)
- Depth of runtime/CDR historically behind agent-based EDR-style tools (improving via Gem acquisition/Wiz Defend)
- Google ownership raises neutrality/roadmap questions for customers standardized on AWS/Azure (Wiz pledged to remain multicloud - monitor over time)
- As SaaS with broad cloud read access, it concentrates sensitive posture data and requires trust/compliance review
- It detects and prioritizes but does not itself patch or virtual-patch - remediation hand-off to other tools/processes

## Vulnerability-mitigation role

Wiz is the discover-assess-prioritize powerhouse: it continuously (snapshot-based) inventories workloads, finds CVEs plus secrets/malware/misconfig, and - critically - uses the Security Graph to tell you which vulnerable assets are actually exploitable (internet-exposed + over-privileged + touching sensitive data), so scarce patch effort targets genuine exposure during the window. It is a prioritization and exposure-reduction control rather than a patching engine: it drives compensating mitigation by pinpointing the toxic path to break (remove a public exposure, cut an over-broad entitlement via CIEM, quarantine), and Wiz Defend adds runtime detection to catch exploitation before the patch lands. Remediation (the patch itself) is handed to CI/CD, image rebuilds (e.g. Chainguard), or cloud patch tooling, then Wiz re-scans to validate.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Identify (asset/vuln/data inventory, Security Graph), Protect (CIEM least-privilege, posture hardening), Detect (Wiz Defend/CDR); CIS Controls v8: 1-2 (inventory), 3 (data protection/DSPM), 4 (secure config), 5-6 (identity/CIEM), 7 (continuous vulnerability management), 13 (monitoring); MITRE ATT&CK mitigations: M1030 Network Segmentation (cut exposure), M1026 Privileged Account Management (CIEM), M1051 Update Software (drives/validates patching), M1018 User Account Management, M1022 Restrict File/Directory Permissions

**In a critical-CVE scenario.** First 24-72h of a critical CVE in an internet-facing app + cloud workload: Wiz instantly queries the Security Graph to list every affected resource across all clouds and, far more importantly, ranks the few that are internet-exposed AND over-privileged AND near sensitive data - the real blast radius. Teams immediately break the attack path as compensating mitigation (remove public exposure, revoke excessive entitlements via CIEM, isolate), while Wiz Defend watches for active exploitation. Wiz feeds the prioritized target list to the remediation pipeline (rebuild images / patch), then re-scans to confirm the toxic combination is resolved.

## Validation & telemetry

**Log sources**
- Authoritative source: Wiz GraphQL API at https://api.<DC>.app.wiz.io/graphql (DC = us1|us2|eu1|eu2), OAuth2 client-credentials from a service account (scope read:issues etc.).
- Issues (issuesV2 query): correlated risks, each tied to a sourceRule union — concrete types Control, CloudConfigurationRule, CloudEventRule.
- Vulnerability findings (vulnerabilityFindings): per-CVE results from agentless disk scanning / the Wiz sensor.
- Cloud configuration findings (cloudConfigurationFindings): result PASS|FAIL|ERROR|NOT_ASSESSED.
- SIEM delivery: Wiz webhooks (automation rules on Issue create/update with a Severity filter) deliver Wiz.IssuesWebhook JSON near real-time; or scheduled API pull (Wiz.Issues) via Splunk/Sentinel/Cortex XSOAR add-ons; or the Wiz data connector / cloud-events stream. Wiz Sensor (eBPF) + Admission Controller add runtime detections and deploy-time enforcement.
- VERIFIED via third-party integrations: issuesV2 query, sourceRule union (Control/CloudConfigurationRule/CloudEventRule fragments), finding result PASS/FAIL/ERROR/NOT_ASSESSED, issue status OPEN/IN_PROGRESS/RESOLVED/REJECTED, regional GraphQL endpoint pattern.

**Telemetry format / transport.** GraphQL JSON (API pull) and webhook JSON (push). SIEM add-ons normalize to their own sourcetypes (Splunk 'wiz:issue', Panther Wiz.IssuesWebhook / Wiz.Issues). Transport: HTTPS GraphQL + HTTPS webhook POST. Sentinel parsers map sourceRule fields into a custom schema.

**Control-presence check (present & configured?).** Confirm connector coverage first: query CloudAccounts/graph to confirm the target subscription/account is connected and recently scanned (stale/disconnected = findings not authoritative). Control presence is itself a Wiz Control/CloudConfigurationRule: query cloudConfigurationFindings for the resource+rule — result == 'PASS' means the config control is present and satisfied, 'FAIL' absent/misconfigured, 'NOT_ASSESSED' out of scope. Sensor/runtime presence: confirm the Wiz Sensor DaemonSet / admission controller is deployed (graph node or cluster connector health). Agentless vuln-scan presence: confirm the scanner role/outpost is attached to the cloud account.

**Validation signals (actually working?)**
- CONFIGURED: cloudConfigurationFinding result == PASS for the hardening/compensating control, account connected + recently scanned.
- EFFECTIVE: the Issue tied to the vulnerability transitions OPEN->RESOLVED (Wiz re-evaluates on next scan and auto-resolves when the underlying finding clears), i.e. the CVE vulnerabilityFinding no longer returns with hasFix/fixedVersion applied.
- EFFECTIVE: a CloudEventRule-sourced Issue showing a detected cloud event (suspicious API/exploitation) proves the detection path is live.
- EFFECTIVE (inline): an admission-rejection event showing a non-compliant/vulnerable image was blocked at deploy.
- Distinguish: a PASS configuration finding proves the control is PRESENT; an Issue auto-resolving after the next scan + the CVE finding disappearing prove it WORKED; an admission-controller denial proves active inline blocking.

**Key events / fields / tables / APIs**
- issuesV2: id, status (OPEN|IN_PROGRESS|RESOLVED|REJECTED), severity (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL), type, createdAt, resolvedAt, entitySnapshot{id,type,name,cloudPlatform,subscriptionExternalId,region}.
- sourceRule union: __typename + ...on Control{id,name,resolutionRecommendation,securitySubCategories}, ...on CloudConfigurationRule{id,name,remediationInstructions,serviceType}, ...on CloudEventRule{id,name,sourceType}.
- cloudConfigurationFindings: rule{id,name}, result (PASS|FAIL|ERROR|NOT_ASSESSED), severity, resource/target_external_id, remediation, analyzedAt, firstSeenAt, securitySubCategories.
- vulnerabilityFindings: CVE id/name, severity, hasFix, fixedVersion, detailedName/version, vulnerableAsset{id,name,cloudPlatform}, firstDetectedAt, resolvedAt.
- Webhook (Wiz.IssuesWebhook) carries issue + entitySnapshot + sourceRule; payload differs slightly from the API's Wiz.Issues shape.
- NOTE: exact GraphQL type names beyond those above are from third-party connectors — run a GraphQL introspection against your tenant to confirm.

**Example queries**

*Presence/validation: open CRITICAL/HIGH issues with source rule + affected entity (which controls failing vs cleared)* (GraphQL)

```
query Issues($after:String){ issuesV2(first:100, after:$after, filterBy:{severity:[CRITICAL,HIGH], status:[OPEN,IN_PROGRESS]}){ nodes{ id status severity type createdAt entitySnapshot{ name type cloudPlatform subscriptionExternalId } sourceRule{ __typename ... on Control{ id name resolutionRecommendation } ... on CloudConfigurationRule{ id name remediationInstructions } ... on CloudEventRule{ id name sourceType } } } pageInfo{ hasNextPage endCursor } } }
```

*Presence: confirm a specific hardening control PASSES on a resource (control present & configured)* (GraphQL)

```
query CfgFindings{ cloudConfigurationFindings(filterBy:{ rule:{ name:{ equals:"<rule name>" } }, result:[PASS,FAIL] }){ nodes{ result severity analyzedAt resource{ providerId } rule{ id name } } } }
```

*Validation: Wiz issues that transitioned to RESOLVED (mitigation worked) in 7d, by source rule* (SPL)

```spl
index=wiz (sourcetype="wiz:issue" OR sourcetype="Wiz.IssuesWebhook") status=RESOLVED | eval age=resolvedAt-createdAt | stats count by sourceRule.name, severity, entitySnapshot.cloudPlatform
```

**How it mitigates (mechanism).** Wiz is agentless/graph-based: 'mitigation' is reachability/exposure removal confirmed on the next scan (a toxic-combination Issue auto-resolves when any node in the attack path — public exposure, vulnerable package, or excessive permission — is removed), not an inline block; the only true inline enforcement is the Wiz Admission Controller rejecting a non-compliant/vulnerable workload at deploy.

**Logging gotchas**
- Findings are only as fresh as the last agentless scan (hours-cadence) — a just-patched resource keeps an OPEN Issue until re-scan, so OPEN != 'still vulnerable right now'.
- A PASS configuration finding proves config state, not that an attack was blocked (Wiz mostly observes, rarely blocks inline).
- NOT_ASSESSED silently means the control wasn't evaluated (out of scope / scanner permission gap) and is easily mistaken for a pass.
- Webhook (Wiz.IssuesWebhook) and API-pull (Wiz.Issues) payloads differ, so a parser built for one can drop fields from the other.
- Cloud-event detections depend on the cloud audit log (CloudTrail/Activity Log) being connected to Wiz — if that ingestion is off, CloudEventRule issues never fire.
- Service-account client secret is shown once at creation; exact GraphQL schema is behind login — verify field/type names by introspection, not third-party connector field maps.

## Documentation & repositories

_Official documentation & manuals_
- [Wiz Documentation portal (requires tenant login)](https://docs.wiz.io/)
- [Wiz docs / reference (win.wiz.io)](https://win.wiz.io/reference)
- [Wiz API prerequisites (service account, API/token URL, client ID/secret)](https://win.wiz.io/reference/prerequisites)

_API & developer docs_
- [Wiz GraphQL API reference (win.wiz.io/reference)](https://win.wiz.io/reference)
- [Wiz API endpoint pattern: https://api.<dc>.app.wiz.io/graphql (dc = us1/us2/eu1/eu2 etc.), token via OAuth client credentials](https://win.wiz.io/reference/prerequisites)
- [Wiz CLI (wizcli) for CI/CD & IaC/image scanning —  (Wiz CLI section)](https://docs.wiz.io/)

_GitHub (official)_
- [wiz-sec-public org (Wiz's public GitHub presence)](https://github.com/wiz-sec-public)
- [wiz-sec org](https://github.com/wiz-sec)
- [Wiz Sensor GitHub Action](https://github.com/wiz-sec-public/wiz-sensor-github-action)

_Community / integration / detection repos_
- [Roadie Backstage Wiz plugin (community, RoadieHQ)](https://github.com/RoadieHQ/roadie-backstage-plugins)
- [Harness IDP Wiz plugin docs (integration reference)](https://developer.harness.io/docs/internal-developer-portal/plugins/available-plugins/wiz)

_Learning & reference_
- [Wiz Academy (free cloud security courses)](https://www.wiz.io/academy)
- [Wiz blog (incl. PEACH tenant-isolation framework, cloud threat research)](https://www.wiz.io/blog)
- [CloudSec Academy](https://www.wiz.io/academy/cloud-security)

> Note: Wiz is largely a closed/SaaS product: the full product documentation (docs.wiz.io) and the API/GraphQL reference under win.wiz.io require an authenticated Wiz tenant, so most of it is login-gated. Wiz has a limited official open-source footprint under the wiz-sec-public GitHub org (confirmed via third-party mirror for the wiz-sensor-github-action repo); verify the org/repo list directly on github.com since the search index did not return the org page. API uses a per-data-center GraphQL endpoint + OAuth client-credentials. The Roadie Backstage plugin is community-maintained, not an official Wiz repo.

## Current state (2025-26)

Google/Alphabet completed its ~$32B all-cash acquisition of Wiz, with the deal reported closed around March 11, 2026 after US DOJ and EU clearance; Wiz joined Google Cloud while pledging to keep operating under its own brand with continued multicloud support (verify Google's primary closing statement). Module set spans CSPM, CWPP, CIEM, DSPM, KSPM, AI-SPM, Wiz Code (IaC/code), and Wiz Defend (CDR, built on the Gem Security acquisition). Pricing remains per-workload/negotiated with no public list; third-party benchmarks only. Catalog '2,000+' and tier specifics should be confirmed directly with Wiz.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
