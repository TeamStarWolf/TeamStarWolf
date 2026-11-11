# Cortex XSOAR

Cortex XSOAR is Palo Alto Networks' security orchestration, automation, and response (SOAR) platform. It was formerly named Demisto. The platform coordinates case handling across the security stack, runs automated playbooks, and gives analysts a shared workspace for investigations.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

SOC engineers and automation builders who run, tune or assess Cortex XSOAR

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,320 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Cortex XSOAR for security orchestration and automation, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Splunk Enterprise Security](/platforms/splunk.md), [Tines](/platforms/tines.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Cortex XSOAR sits between detection tools and the people who respond to alerts. Detection products raise signals. A SIEM or a ticketing system groups some of them. Cortex XSOAR takes those signals as incidents and drives a consistent response for each one.

The platform targets repetitive, high-volume work. Triage of phishing reports, enrichment of indicators, and containment steps are common cases. Analysts keep judgement calls; the platform handles the mechanical parts around them.

In a security operations program, Cortex XSOAR is the automation and coordination layer. It does not replace endpoint, network, or identity controls. It connects to them and acts through them, so its value depends on the tools already in place.

## Architecture and how it works

A Cortex XSOAR deployment centers on a server that stores incidents, playbooks, and content. The server exposes a web console for analysts and administrators, and an API for programmatic access.

Engines extend the server's reach. An engine is a worker that runs integration commands and automation scripts on behalf of the server. Engines let the platform reach systems in segmented networks without a direct path from the main server. This supports network segmentation and keeps credentials closer to the systems they serve.

Content packs deliver the building blocks. A pack can include integrations, playbooks, automation scripts, incident layouts, and field definitions. Packs are versioned, so an administrator can pin, test, and roll back changes rather than taking every update at once.

Automation scripts run logic that playbooks call. Scripts commonly transform data, parse indicators, or shape the layout an analyst sees. They run inside the platform's execution environment under the identity the deployment assigns.

## Key capabilities

- Playbooks: visual, step-based workflows that define how an incident type is handled. Steps can branch on conditions, loop over lists, and pause for human approval before a sensitive action.
- Incident management: a structured record for each case, with fields, severity, owner, and a timeline of what ran and what an analyst did.
- The war room: a shared investigation space tied to an incident. Analysts run commands, record notes, and see the full history of actions in one place.
- Integrations: connectors to the security stack delivered through content packs. These cover endpoint, network, identity, threat intelligence, and ticketing tools.
- Automation scripts: reusable logic that playbooks invoke for enrichment, transformation, and formatting.
- Threat Intel Management: ingestion, scoring, and distribution of indicators, so playbooks and analysts work from a common view of known-bad data.

## Deployment and operations

Cortex XSOAR runs as a self-managed server or as a cloud-delivered service. The self-managed form gives an organization control over the host and network placement. The cloud form shifts infrastructure upkeep to the vendor.

Engines are added where the server cannot reach systems directly. Each engine runs in a network zone and executes the integration work for that zone. Planning engine placement is part of the deployment design.

The license tier decides which features and content are in force. Confirm entitlements against the tier in use rather than assuming a feature is present.

Day-to-day operations include tuning playbooks, keeping content packs current, and reviewing which automated actions fire most often. A playbook that runs thousands of times a day deserves closer change control than one that runs rarely.

## Integrations and data flow

Data enters Cortex XSOAR as incidents. A SIEM, a mail flow, an endpoint tool, or an API call creates an incident, and a mapped layout turns the raw fields into the structure the platform uses.

Playbooks then act. A phishing playbook might extract URLs and attachments, send them to a sandbox, query threat intelligence, and quarantine a message if the verdict is bad. Each action runs through an integration backed by stored credentials.

Results flow back into the incident. Verdicts, enrichment, and the outcome of each action are recorded on the case timeline. Analysts see what ran, and an auditor can trace the full sequence later.

Outbound actions reach other systems. The platform tells an endpoint tool to isolate a host, a firewall to block an address, or an identity provider to disable an account. These are consequential steps and belong behind approval gates where the risk warrants it.

## Adversary perspective

Cortex XSOAR drives response across the stack, so adversaries value the credentials it holds and work to keep their activity out of the cases it would act on, and the server, engines, and API are themselves a target. The defensive steps are in the "Hardening and secure use" section that follows.

### Evasion and tampering

- Suppressing or clearing the case trail (ATT&CK T1685, Disable or Modify Tools, and T1070, Indicator Removal): with access an attacker can disable a playbook, mute an integration, or alter incident records so a response never runs or its history is hidden.
- Credential and engine abuse: a SOAR holds stored credentials to much of the stack, so a compromised server or engine turns those into a foothold that can isolate hosts, block addresses, or disable accounts on the attacker's behalf ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)).
- API and playbook tampering: an API token scoped too broadly, or a changed playbook, can redirect actions, exfiltrate incident data, or quietly weaken containment across thousands of cases ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).

### Residual risk and own exposure

Automation acts only on incidents it receives, so a threat that never raises one is never handled, and an integration call that returns success has not proven the target acted. The platform concentrates credentials to endpoint, network, and identity tools, so its server and engines are high-value and belong in the patch and monitoring scope.

### Why it matters

Treat playbook changes, integration disables, and engine credential use as detection signals, and gate consequential actions behind approval. See [the red team reference](/RED_TEAM_REFERENCE.md) for the evasion techniques and [the incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) for response integrity.

## Hardening and secure use

Apply role-based access so analysts, engineers, and administrators get only the permissions their work requires. Playbook authoring and integration configuration are higher-trust tasks and should be limited.

Protect integration credentials and API keys. Store them in the platform's credential handling rather than embedding them in scripts or playbook inputs. Hardcoded secrets are a known weakness (CWE-798: Use of Hard-coded Credentials), and a SOAR platform holds credentials to much of the stack, so exposure here is costly.

Put change control on playbooks. A change to a widely used playbook can affect thousands of incidents. Use versioned content packs, test in a non-production space, and require review before promoting a change.

Verify downstream actions rather than trusting an interface acknowledgement. An integration call that returns success does not always mean the target system completed the action. Where the outcome matters, confirm the state on the target system before closing the case.

Guard the API and the engines. API tokens should be scoped and rotated. Engines run with real credentials in segmented zones, so treat each engine host as a sensitive asset.

## Where it fits in the program

Cortex XSOAR is the response and orchestration layer for the security operations center. It turns detections from other tools into consistent, auditable handling, and it reduces the manual load on analysts.

For vulnerability management, the platform can automate parts of the remediation workflow: opening tickets, enriching findings, and chasing owners for overdue items. It acts through the vulnerability and ticketing tools rather than replacing them.

The platform's reach is also its risk. It can act across endpoint, network, and identity, so access control, credential handling, and change control decide whether that reach stays safe.

## Resources

- Cortex XSOAR Administrator Guide
- Cortex XSOAR Playbook and Automation documentation
- Palo Alto Networks Cortex XSOAR content pack documentation
- Cortex XSOAR API reference

## Related pages

- [Platforms index](/platforms/README.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Splunk](/platforms/splunk.md)
- [Tines](/platforms/tines.md)
- [ServiceNow VR](/platforms/servicenow-vr.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Cortex XSOAR entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?product=cortex-xsoar)

<!-- hub-links:end -->
