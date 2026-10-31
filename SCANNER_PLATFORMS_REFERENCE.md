# Scanner Platforms and Findings Catalog

This reference maps the vulnerability and exposure scanners common in an enterprise: how each one works, how it is deployed, the kinds of findings it produces and what they mean, and where those findings end up in ServiceNow Vulnerability Response. It is written for a vulnerability management analyst who has to reconcile output from several platforms into one defensible remediation queue.

| Attribute | Value |
|---|---|
| Scope | Network, agent, agentless, cloud-connector, and application scanners |
| Platforms | Tenable, Qualys, Rapid7, Microsoft, CrowdStrike, Wiz, Snyk, Invicti, Nessus, OpenVAS |
| Finding identity | CVE, CPE, plugin or QID, CWE, plus vendor-specific risk scores |
| Workflow target | ServiceNow Vulnerability Response (Vulnerable Items, Vulnerability Groups) |

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management analysts reconciling output from several scanners into one remediation queue

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 8 min (1,779 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to know how a given scanner is deployed and what its findings mean, you are mapping findings from several platforms onto one asset, or you need to see where scanner output lands in ServiceNow Vulnerability Response

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Platform catalog](#platform-catalog), [A cross-scanner findings catalog](#a-cross-scanner-findings-catalog), [Where findings land in ServiceNow](#where-findings-land-in-servicenow)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Vulnerability Management Reference](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Vulnerability Prioritization Reference](VULNERABILITY_PRIORITIZATION_REFERENCE.md), [CTEM Reference](CTEM_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## How scanners work: deployment models

The deployment model decides what a scanner can see, and most false negatives trace back to the wrong model for the asset.

- Network, unauthenticated: the scanner reaches a target over the network and infers vulnerabilities from banners, service responses, and safe probes. Broad reach, shallow accuracy, and prone to version-inference false positives.
- Authenticated (credentialed): the scanner logs in over SSH, SMB, WinRM, or an API and reads installed-package and configuration state directly. This is the accurate mode for missing-patch and benchmark findings; uncredentialed scans of the same host miss most of them.
- Agent-based: a persistent agent on the host collects state locally and reports to the console. It covers roaming and cloud hosts that a network scanner never reaches, at the cost of an agent to deploy and maintain.
- Agentless (cloud): the platform reads a snapshot of a cloud workload's disk through the cloud provider API, with no agent and no credentials on the instance. This is the model behind modern cloud-native scanning.
- Cloud connector or API pull: the platform ingests posture from a cloud control plane (for example AWS, Azure, or a SaaS admin API) rather than touching the host.
- Passive or network-monitoring: the platform watches traffic and identifies assets and some vulnerabilities without sending probes, useful for fragile operational technology networks.

A mature program combines models: agents or credentialed scans for depth, agentless for cloud breadth, and passive discovery for assets that cannot be scanned.

## Finding identity and severity schemes

A single real-world weakness can appear under several identifiers, and deduplication depends on reading them correctly.

- `CVE`: the industry identifier for a specific vulnerability. One asset can have many CVEs; one CVE can map to many findings.
- `CPE`: the product and version identifier a scanner uses to decide whether a CVE applies.
- `CWE`: the weakness class (for example `CWE-79` for cross-site scripting), used mostly by application scanners.
- Plugin or check ID: the scanner's own detection unit. Tenable calls these plugins, Qualys calls them QIDs, Rapid7 calls them vulnerability checks. One plugin can test for one or many CVEs.
- Vendor risk score: most platforms layer their own score on top of CVSS to rank what to fix first. Treat the CVSS base score as severity, not priority, and let exploitation signals (KEV, EPSS) drive order. See [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).

## Platform catalog

### Tenable

Tenable runs from the Nessus engine, through Tenable Vulnerability Management (formerly Tenable.io) and Tenable Security Center (on-premises), up to the Tenable One exposure platform that unifies vulnerability, cloud, identity, and operational-technology findings. Deployment covers network scanners, Nessus Agents, and cloud connectors.

- Findings: `plugins`, grouped into plugin families (for example Windows, Web Servers, SSL, Databases). A plugin encodes the detection logic and the CVEs it covers.
- Severity: CVSS plus the Vulnerability Priority Rating (VPR), a dynamic score that folds in exploitation and threat context.
- ServiceNow: the Tenable connector creates Vulnerable Items keyed to the plugin and asset.

### Qualys

Qualys VMDR (Vulnerability Management, Detection and Response) uses scanner appliances (physical, virtual, or cloud) and the Qualys Cloud Agent.

- Findings: `QIDs` (Qualys IDs), each a detection with a type (Confirmed, Potential, or Information Gathered) and a category.
- Severity: a 1 to 5 severity level, with the TruRisk score as the prioritization layer.
- ServiceNow: the Qualys integration maps QIDs to Vulnerable Items, and a single item can carry multiple detections.

### Rapid7 InsightVM

InsightVM (the successor to Nexpose) uses scan engines and the Insight Agent.

- Findings: vulnerability checks, reported against assets and asset groups.
- Severity: CVSS plus the Real Risk Score, a 1 to 1000 scale weighted by exploit and malware exposure.
- ServiceNow: the Rapid7 connector feeds Vulnerable Items and supports remediation projects.

### Microsoft Defender Vulnerability Management

Defender Vulnerability Management (MDVM) is built on the Microsoft Defender for Endpoint (MDE) sensor, so coverage follows endpoints already onboarded to Defender, with an add-on for broader assessment.

- Findings: security recommendations and weaknesses tied to software inventory, plus configuration findings against baselines.
- Severity: CVSS, surfaced through the organization and device exposure score and the Microsoft Secure Score for Devices.
- ServiceNow: exported through Microsoft Graph security APIs or the Defender connector.

### CrowdStrike Falcon Exposure Management

Falcon Exposure Management (the evolution of Falcon Spotlight) is cloud-only and draws from the Falcon sensor already installed on the host, so it needs no separate scan.

- Findings: vulnerabilities on managed hosts, with asset and network reach from the same sensor data.
- Severity: CVSS plus the ExPRT.AI rating, which predicts exploitation likelihood.
- ServiceNow: delivered through the CrowdStrike integration and the Falcon API.

### Wiz

Wiz is a cloud-native application protection platform (CNAPP) that scans cloud workloads agentlessly by reading disk snapshots through the cloud provider API, and ingests control-plane posture through a cloud connector.

- Findings: Issues, which combine a detection with context; the platform highlights toxic combinations where several findings together create an attack path (for example a public workload with a critical CVE and a high-privilege role).
- Severity: Critical through Low, driven by the Wiz risk model rather than CVSS alone.
- ServiceNow: the Wiz integration creates Vulnerable Items and Configuration findings and maps them to cloud resources.

### Snyk

Snyk is a developer-first platform for software composition analysis, static analysis, container images, and infrastructure as code.

- Findings: issues in open-source dependencies (`Snyk Open Source`), first-party code (`Snyk Code`), container layers, and IaC templates, each with a fix or upgrade path.
- Severity: CVSS plus a Snyk priority score; many findings carry a direct remediation (a dependency upgrade or a pull request).
- ServiceNow: integrated through the Snyk API and application-vulnerability-response connectors.

### Invicti

Invicti (which includes the former Acunetix) is a dynamic application security testing (DAST) platform that scans running web applications and APIs.

- Findings: web vulnerabilities by class (for example SQL injection, cross-site scripting, broken access control), mapped to `CWE` and the OWASP Top 10.
- Severity: Critical through Informational, with proof-based scanning that confirms many findings by safe exploitation to cut false positives.
- ServiceNow: exported to application vulnerability response or through the API.

### Nessus and OpenVAS

Nessus is the widely deployed standalone scanner underneath Tenable's platforms. OpenVAS, maintained by Greenbone, is the open-source network scanner; its detections are Network Vulnerability Tests (NVTs). Both are the baseline for network and credentialed scanning and are covered with install and command detail in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## A cross-scanner findings catalog

Regardless of platform, findings fall into a small set of classes. Reading the class tells you who owns the fix.

- Missing patch or vulnerable version: a `CVE` present because software is below a fixed version. Owner: patching. The most common class, and the most accurate from credentialed or agent scans.
- Misconfiguration or benchmark failure: a setting that diverges from a hardening baseline (CIS, DISA STIG). Owner: platform or system engineering.
- Weak or expiring cryptography: deprecated TLS versions, weak ciphers, expired or soon-to-expire certificates, or a distrusted certificate authority. Owner: platform or PKI. See [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md).
- Default or weak credentials: a default account or a guessable password on a service. Owner: system owner.
- Exposed service: a sensitive service reachable from an untrusted network (for example SMB, RDP, or a database port). Owner: network or firewall.
- End-of-life software: a product past vendor support with no patches available. Owner: lifecycle and architecture.
- Web application vulnerability: injection, cross-site scripting, broken access control, and similar, from a DAST or SAST tool. Owner: application development.
- Dependency or container vulnerability: a `CVE` in an open-source package or image layer, from software composition analysis. Owner: application development or platform.
- Infrastructure-as-code or cloud posture: an insecure setting in a template or a live cloud resource. Owner: cloud or platform engineering.
- Identity exposure: an over-privileged or exposed identity, often surfaced by a CNAPP or identity tool. Owner: identity and access management.
- Information disclosure: a banner, path, or error that leaks detail. Often low severity, and a frequent false-positive source on unauthenticated scans.

## Where findings land in ServiceNow

Most enterprises route scanner output into ServiceNow Vulnerability Response (VR) so that remediation runs through the same change and task process as the rest of IT.

- Vulnerable Items (`sn_vul_vulnerable_item`): one record per vulnerability on one asset, created automatically when a third-party integration imports results. Carries a risk rating, a risk score, and a state that starts at Open and moves through Under Investigation to a closed state. A single Vulnerable Item can hold multiple detections when more than one scan or scanner reports the same vulnerability on the same asset.
- Vulnerability Groups (`sn_vul_vulnerability_group`): a rollup that gathers many Vulnerable Items under a rule, for example all items for one CVE or one assignment group, so remediation and reporting happen in bulk rather than item by item.
- CMDB and configuration items: Vulnerable Items reconcile to configuration items, which drive asset ownership, assignment groups, and business-criticality context.
- Remediation Tasks and change: a remediation task tracks the fix and connects to change management; some integrations open vendor tickets as related records.
- Integrations: Tenable, Qualys, Rapid7, Wiz, and others ship certified connectors that create and update these records on a schedule. Access to imported data needs at least the `sn_vul.read_all` role.

The practical implication for an analyst: deduplicate at the Vulnerable Item and Vulnerability Group level, not at the raw-finding level, and let the group rule and CI ownership decide who gets the work.

## Operational notes

- Credentialed and agent findings outrank unauthenticated findings for accuracy; when they disagree, trust the authenticated result.
- Reconcile overlap: the same host scanned by Tenable, an agent, and a CNAPP will produce three finding sets. Map them to one asset and one CVE before counting.
- Overlay exploitation signals (KEV, then EPSS, then environment) on top of every platform's native score to set remediation order, rather than fixing by raw severity. See [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).
- Watch scan coverage, not just scan results: an asset that no model reaches is a silent gap, which is what continuous exposure management is meant to close. See [CTEM Reference](/CTEM_REFERENCE.md).

## Learning resources

- Each vendor publishes platform and connector documentation; confirm plugin, QID, and connector behavior against the current vendor docs for your deployment.
- For prioritization method, see [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md); for program structure and scanner commands, see [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [GRC and security program](/hubs/grc-and-security-program.md)
- [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- [CTEM Reference](/CTEM_REFERENCE.md)

<!-- related:end -->
