# Cortex XSOAR

Cortex XSOAR is Palo Alto Networks' security orchestration, automation, and response (SOAR) platform. It was formerly named Demisto. The platform coordinates case handling across the security stack, runs automated playbooks, and gives analysts a shared workspace for investigations.

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
