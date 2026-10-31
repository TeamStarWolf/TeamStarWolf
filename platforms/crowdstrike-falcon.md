# CrowdStrike Falcon

CrowdStrike Falcon is a cloud-native endpoint protection platform from CrowdStrike. It runs as a single lightweight agent on each host and reports to the Falcon cloud. The platform covers prevention, detection and response, vulnerability assessment, identity protection, and managed threat hunting. Module entitlement depends on the licence tier purchased.

## What it is and where it fits

Falcon is an endpoint and workload protection platform. It sits at the host layer, protecting workstations, servers, and cloud instances across Windows, macOS, and Linux. One agent collects endpoint telemetry and enforces policy, while analysis and storage live in the Falcon cloud. A security operations team uses Falcon for prevention, for detection and response on endpoints, and for continuous vulnerability visibility without a separate scanner on each host.

The platform is sold as a set of modules on a shared agent and console. What a given tenant can see and do is set by the licence tier and the specific modules enabled. A team should confirm which modules are in force before relying on a capability.

## Architecture and how it works

The core of the platform is the Falcon sensor, a single kernel and user-mode agent installed on each endpoint. The sensor collects process, file, network, registry, and user events and streams them to the Falcon cloud. There is no on-prem management server to run. Policy, detections, and dashboards are served from the cloud console.

In the cloud, event data is recorded in the Threat Graph, CrowdStrike's backend that correlates events across the tenant and across the wider CrowdStrike customer base for pattern analysis. The sensor can enforce prevention locally even when disconnected, using on-sensor machine learning and behavioral rules. When connectivity returns, queued telemetry is uploaded and policy is refreshed.

The data flow is one direction for telemetry (sensor to cloud) and one direction for policy and tasking (cloud to sensor). Administrators and analysts work entirely through the cloud console or the platform API.

## Key capabilities

The platform groups its functions into modules on the shared sensor:

- Next-generation antivirus: machine-learning and behavioral prevention that replaces signature-only antivirus.
- Endpoint detection and response (EDR): continuous recording of endpoint activity, detections mapped to adversary behavior, and investigation timelines.
- Falcon Exposure Management: the vulnerability-assessment module (the capability formerly branded Spotlight). It produces host vulnerability findings from sensor-collected inventory, without a separate network scan, and prioritizes them by exploit and exposure context.
- Identity Threat Detection: monitoring of identity activity and credential-based attack patterns across directory services.
- OverWatch: CrowdStrike analysts hunting across tenant telemetry for threats that automated detection may miss.
- Falcon Firewall Management: central management of the host firewall policy through the same agent.
- Real Time Response: an interactive remote-shell capability for responders to run containment and investigation actions on a host.

For vulnerability management, the Exposure Management findings are the primary product: per-host vulnerability records with severity, exploit status, and affected-product detail. EDR produces detections and the raw telemetry that feed hunting and investigation.

## Deployment and operations

Deployment is a sensor install on each endpoint, pushed through the organization's existing software distribution tooling, an installer script, or a golden image. The sensor registers to the tenant using a customer identifier at install time. There is no on-prem console to size or patch.

Day-to-day operations run in the cloud console: prevention and sensor policy, host groups, detections, and dashboards. Sensor updates can be staged through sensor update policies so that a controlled ring takes new versions first. Host grouping drives policy assignment and keeps production and test populations separate.

## Integrations and data flow

Falcon exposes a platform API for configuration, detection retrieval, and host actions. The Event Streams API provides a near-real-time feed of detections and audit events for downstream systems. Teams commonly forward detections and telemetry to a SIEM for correlation and long-term retention, and drive response playbooks from a SOAR platform through the API.

Vulnerability findings from Exposure Management can be exported or pulled by API into a vulnerability management workflow or a ticketing system such as ServiceNow, so remediation is tracked alongside findings from other scanners. The console also supports prebuilt connectors to common SIEM and SOAR products.

## Hardening and secure use

Securing the platform itself starts in the console. Scope analyst and administrator access with role-based access control, and grant only the roles each person needs. Over-broad roles are a real risk (CWE-862: Missing Authorization); for example, granting Real Time Response rights widely gives many people remote-shell access to every host.

Treat API credentials as sensitive secrets. Create API clients with the narrowest scopes required for each integration, rotate client secrets, and store them in a secret manager rather than in code or configuration files (CWE-798: Use of Hard-coded Credentials). Separate clients per integration so one can be revoked without affecting others.

Restrict Real Time Response to a small responder group and enable its session logging so every remote action is attributable. Enable multi-factor authentication on console accounts and review the audit log, which records policy changes, API client creation, and response sessions. Protect the uninstall and sensor-removal controls so the agent cannot be silently disabled.

## Where it fits in the program

A vulnerability management and security operations team uses Falcon as the endpoint control point. Exposure Management supplies continuous, agent-based vulnerability findings that complement network and authenticated scanners, while EDR and OverWatch give the SOC detection, hunting, and response on the same hosts. Because findings and detections come from one agent, the team correlates exposure and active threat on a host without stitching together separate tools.

## Resources

- CrowdStrike Falcon platform documentation
- Falcon Exposure Management documentation
- CrowdStrike API and Event Streams API reference
- Falcon sensor deployment guide

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /INCIDENT_RESPONSE_REFERENCE.md
- /platforms/microsoft-defender.md
- /platforms/tanium.md
