# Splunk Enterprise Security

Splunk Enterprise Security is a security information and event management (SIEM) application that runs on the Splunk platform, turning ingested machine data into detections, investigations, and risk-based alerts.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

SOC analysts and detection engineers who run, tune or assess Splunk Enterprise Security

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,299 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Splunk Enterprise Security for security event management and detection, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [IBM QRadar](/platforms/qradar.md), [Cortex XSOAR](/platforms/cortex-xsoar.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Splunk collects and indexes machine data, then makes it searchable. Enterprise Security (ES) is the security content layer on top: correlation searches, notable events, risk scoring, and investigation workflow for a security operations center.

The base platform is a general data engine. ES adds the security use case. Splunk SOAR (Security Orchestration, Automation and Response) adds automated playbooks for response. Together they cover detection, triage, and action.

Where VR governs remediation work and QRadar or ES detect, Splunk ES is the analytics and detection surface for a SOC. It answers what is happening across logs, not what to patch.

## Architecture and how it works

The platform separates data movement, storage, and search.

- Forwarders collect data at the source and send it onward. A universal forwarder is a lightweight agent; a heavy forwarder can parse and route.
- The indexing tier receives, parses, and stores events in indexes on disk. Indexers also run the first stage of most searches.
- Search heads run the search language, present results, and host apps including ES. In larger sites search heads are clustered.

Data is schema-on-read. Splunk indexes raw events and applies field extraction at search time, which is why one data source can be reinterpreted without reindexing.

Search Processing Language (SPL) is the query language. It chains commands with the pipe character to filter, transform, aggregate, and correlate events. SPL is the foundation under every detection and dashboard.

The Common Information Model (CIM) is a set of normalized field names and data models. When data is mapped to the CIM, a correlation search written against the model works regardless of the original vendor format. Data models accelerate searches by precomputing summaries.

Correlation searches run on a schedule or in real time and raise a notable event when their conditions match. Notable events populate the ES incident review queue. Risk-based alerting (RBA) assigns risk scores to objects such as users and hosts; when accumulated risk crosses a threshold, a single higher-fidelity alert fires instead of many low-value ones.

## Key capabilities

- Ingestion of log, event, and metric data from across the stack at scale.
- SPL for ad hoc search, correlation, and reporting.
- CIM normalization so detections are vendor-neutral.
- Data models and acceleration for fast searching over large volumes.
- Correlation searches and notable events for detection and triage.
- Risk-based alerting to cut alert volume and raise signal quality.
- Incident review and investigation workflow in ES.
- Dashboards, glass tables, and reporting for situational awareness.
- Splunk SOAR playbooks for automated and semi-automated response.

## Deployment and operations

Splunk runs on-premises, in a customer cloud, or as Splunk Cloud Platform managed by the vendor. The components are the same in concept across these: forwarders feed indexers, and search heads query them.

Capacity planning is a core operational task. Index volume, retention, and search concurrency drive the sizing of the indexing and search tiers. Index-time versus search-time work is a deliberate tradeoff that affects both cost and performance.

Data onboarding is ongoing work. Each new source needs parsing, timestamp recognition, and CIM mapping to be useful to ES content. Poorly onboarded data produces weak or missing detections.

Operators tune correlation searches to control false positives, manage the notable event queue, and maintain data model acceleration so dashboards and searches stay fast.

## Integrations and data flow

The inbound flow is broad: endpoints, network devices, firewalls, identity providers, cloud services, applications, and other security tools all forward data. Technology add-ons map each source to the CIM.

ES content consumes that normalized data to produce notable events and risk scores. SOAR takes those events and runs playbooks that call out to other tools, for example to enrich an indicator, isolate a host through an endpoint platform, or open a ticket.

Data flows from sources into indexes, from indexes into searches and detections, and from detections into response and reporting. Outbound actions happen through SOAR and alert actions rather than from the index itself.

## Adversary perspective

Splunk ES is the detection surface a SOC relies on, so adversaries work to blind it or starve it of the events that would reveal them, and the platform's broad data access and ingestion credentials are themselves a target. The defensive steps are in the "Hardening and secure use" section that follows.

### Evasion and tampering

- Blinding the log source (ATT&CK T1685.001, Disable or Modify Tools: Disable or Modify Logging, and T1070, Indicator Removal): with host access an attacker stops the forwarder, disables Windows event logging, or clears logs so events never reach the indexer. Detection depends on data that was never collected.
- Starving or spoofing ingestion: a leaked HTTP Event Collector token lets an attacker inject noise or spoofed events to bury or misdirect a true signal ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)). Gaps in CIM mapping mean a source is indexed but invisible to the content written against the model.
- Console and search abuse: a hijacked account or an over-broad role can delete indexes, disable correlation searches, or read sensitive data, turning the SIEM into reconnaissance ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).

### Residual risk and own exposure

A SIEM can only correlate what reaches it, so an attacker who acts before a source is onboarded, or who disables that source first, is not caught. The platform aggregates sensitive data across the estate and holds credentials to many sources, so its own servers belong in the patch and monitoring scope, and SIEM software has carried its own serious flaws.

### Why it matters

Treat gaps in log flow as a detection signal in their own right: alert on forwarders going silent, correlation searches disabled, and index deletions. See [the red team reference](/RED_TEAM_REFERENCE.md) for the evasion techniques and [the incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) for log integrity.

## Hardening and secure use

Control access by role. Splunk role-based access defines which users can search which data and which capabilities they hold. Assign roles by need so that analysts see only the indexes their work requires.

Enforce index-level permissions. Sensitive data such as authentication logs or cardholder environments should live in indexes that only authorized roles can search. Do not rely on search filters alone when a permission boundary is the correct control.

Handle HTTP Event Collector (HEC) tokens as secrets. HEC accepts data over HTTP using a token. A leaked token lets an attacker inject or spoof events. Treat tokens as credentials, scope each to a single source, and rotate them; do not commit them to code or configuration. Hardcoded tokens map to CWE-798 (Use of Hard-coded Credentials).

Require TLS. Encrypt forwarder-to-indexer traffic, HEC endpoints, and the web and management ports. Data in transit between tiers should not travel in cleartext.

Audit searches and administrative actions. Splunk logs its own activity; review who ran sensitive searches and who changed roles, inputs, or correlation content. Unmonitored search access over sensitive indexes is an exposure in its own right.

## Where it fits in the program

Splunk ES is the detection and investigation hub for a SOC. It is where normalized telemetry becomes alerts an analyst can act on, and where risk accumulates into fewer, better signals.

In a wider program it complements, rather than replaces, the vulnerability and remediation tooling. Vulnerability findings and asset context can be ingested to enrich detections; detections and incidents feed the response process. SOAR extends it from detection into coordinated action.

For leadership, ES dashboards show detection coverage and incident trends. For analysts, it is the daily queue and the search bar behind every investigation.

## Resources

- Splunk Enterprise Security documentation
- Splunk Platform administration and distributed deployment documentation
- Splunk Common Information Model documentation
- Splunk SOAR documentation
- Splunk Search Reference (SPL)

## Related pages

- [Platforms index](/platforms/README.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Vulnerability Management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [QRadar](/platforms/qradar.md)
- [Cortex XSOAR](/platforms/cortex-xsoar.md)
- [Tines](/platforms/tines.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Splunk entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=splunk) · [Splunk Enterprise Security entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?product=splunk-enterprise-security) · [Splunk entries linked to CISA KEV](https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=splunk)

<!-- hub-links:end -->
