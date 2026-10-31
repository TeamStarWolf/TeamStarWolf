# SentinelOne Singularity

SentinelOne Singularity is an endpoint and extended detection and response platform from SentinelOne. It runs a single agent with on-device AI models that detect, correlate, and respond to threats without waiting on the cloud. The platform spans endpoint, identity, cloud, and network telemetry, backed by a data lake for long-term analytics.

## What it is and where it fits

Singularity sits in the endpoint protection (EPP) and endpoint detection and response (EDR) category, extending into XDR. It replaces traditional signature antivirus with behavioral AI that scores process activity as it executes. The platform targets security operations teams that need prevention, detection, investigation, and response from one agent and one console.

For a vulnerability management and security operations program, Singularity provides the endpoint telemetry and automated response that complements scanner-driven exposure work. It answers what is executing on a host, not only what is installed or exposed. Licence tier and module entitlement decide which capabilities are in force, including EDR depth, data retention, and add-on modules such as identity or cloud coverage.

## Architecture and how it works

A single agent is installed on each protected endpoint, covering Windows, macOS, and Linux. The agent carries static and behavioral AI models locally, so detection and prevention continue when the host is offline or disconnected from the console. This on-device design reduces dependence on constant cloud lookups for a verdict.

The agent monitors process execution, file activity, registry changes, and network connections. It builds a Storyline model that links related activity into a single attack narrative with a shared identifier. Storyline correlates parent and child processes, file writes, and network calls so an analyst reviews one chain rather than isolated events.

The cloud console provides management, policy, detection review, and investigation. Telemetry feeds the Singularity Data Lake, where events are normalized and retained for hunting and analytics. Retention length and query scope depend on the entitled tier.

ActiveEDR describes the agent-side detection and response capability. Because the agent holds context locally, it can draw the attack story and take action at the endpoint without a round trip. Response actions, including kill, quarantine, and remediation, can run automatically by policy or on analyst command.

## Key capabilities

- Static and behavioral AI prevention that scores processes on the endpoint before and during execution.
- Storyline attack correlation that groups related activity under one identifier for faster triage.
- ActiveEDR for endpoint-resident detection, investigation, and response with local context.
- Automated remediation that reverses unauthorized changes made during an attack.
- Rollback on Windows that restores files altered by ransomware to a prior state.
- Ranger for network discovery that maps connected devices and surfaces unmanaged or rogue hosts.
- Singularity Data Lake for normalized event storage, retention, and threat hunting at scale.
- Purple AI, an assistant that helps analysts query data and summarize investigations in natural language.
- Threat intelligence enrichment that adds context to detections.

Rollback and Ranger availability depend on platform support and the licensed module set. Ranger can identify devices without requiring a separate network appliance, using the existing agents as sensors.

## Deployment and operations

Deployment installs the agent through standard software distribution tools, a management suite, or a scripted push. Policies group endpoints into site and group hierarchies, each with its own prevention and detection settings. Start new groups in detect mode, confirm the behavioral baseline, then move to protect or block settings.

Operational work centers on reviewing Storyline detections, confirming automated responses, and tuning exclusions. Exclusions should be scoped narrowly to a path, hash, or signer rather than a broad directory. Over-broad exclusions create blind spots that an attacker can occupy.

Agent health monitoring confirms that endpoints report in, run current models, and remain in the intended policy mode. Track coverage gaps where hosts have no agent or sit in a weaker mode than intended. Data Lake queries support scheduled hunts and ad hoc investigation.

## Integrations and data flow

Singularity exports detections and telemetry to SIEM platforms for correlation with other sources and long-term archival. Common destinations include Splunk and QRadar-class systems; verify the supported connector set for the entitled tier. Detections and enrichment forward to a SIEM through the console or the data lake export path.

SOAR integration drives automated playbooks. A detection can open a case, enrich it with asset and user context, and trigger containment steps such as network isolation. Cortex XSOAR and similar orchestration tools consume Singularity alerts and call its API to run response actions.

The platform exposes a documented API for retrieving threats, managing endpoints, and invoking response. API access underpins SIEM forwarding, SOAR actions, and custom reporting. Treat the API as a sensitive control plane because it can isolate, kill, and roll back at scale.

## Hardening and secure use

Apply role-based access so console operators hold only the scope their work requires. Separate read-only analyst roles from administrators who can change policy or run destructive response. Map console roles to the organization's duties and review them on a schedule.

Protect API tokens as secrets. Hardcoding a Singularity token in a script or pipeline is a credential exposure risk (CWE-798, use of hard-coded credentials). Store tokens in a secrets manager, scope them to the minimum needed, and rotate them on a defined cadence. Revoke tokens that are no longer used.

Restrict high-impact actions. Remote script execution, kill, and rollback can disrupt production if misused or if an attacker gains console access. Limit these actions to narrow roles and require review for broad or bulk operations. Granting response rights to accounts that do not need them is an authorization weakness (CWE-862, missing authorization).

Enforce multi-factor authentication for console sign-in and prefer single sign-on through the organization's identity provider. Keep tenant configuration consistent, including policy mode, exclusions, and data retention, so no site drifts into a weaker posture. Enable tamper protection on the agent to resist uninstall or disable attempts by an attacker with local privileges.

## Where it fits in the program

Singularity is the endpoint prevention and detection layer. In a security operations and vulnerability management program, it supplies the execution-level visibility and automated response that scanner findings cannot provide. A scanner reports that a host carries a vulnerable component; Singularity reports whether something is exploiting that host now.

Endpoint telemetry also informs remediation priority. A vulnerable asset with active suspicious behavior deserves attention before an equally vulnerable but quiet one. Feeding Singularity detections into the SIEM and SOAR closes the loop from exposure to detection to response.

## Resources

- SentinelOne Singularity Platform documentation
- SentinelOne Knowledge Base
- SentinelOne API documentation
- SentinelOne Singularity Data Lake documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [CrowdStrike Falcon](/platforms/crowdstrike-falcon.md)
- [Microsoft Defender](/platforms/microsoft-defender.md)
- [Splunk](/platforms/splunk.md)
