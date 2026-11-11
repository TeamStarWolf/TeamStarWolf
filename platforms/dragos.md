# Dragos

Dragos is an operational-technology and industrial-control-system security platform. The Dragos Platform gives asset visibility, threat detection, and vulnerability management for control environments. This page describes the generally available product in 2026. Licence tier decides which capabilities are in force.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

OT and ICS security engineers and asset owners who run, tune or assess Dragos

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (1,017 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Dragos for operational technology and industrial control system security, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Claroty](/platforms/claroty.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Information-technology tools assume systems that tolerate scanning and frequent patching. Control systems do not. A probe that is routine on a server can disrupt a programmable logic controller running a physical process.

Dragos is built for that constraint. It monitors operational-technology networks passively and identifies assets, threats, and weaknesses without active interrogation of control devices. The goal is visibility that does not put the process at risk.

In a security program, Dragos is the dedicated operational-technology control. It complements information-technology monitoring and feeds a shared view of risk. See the hub at /hubs/ics-ot-and-hardware.md for the wider control-environment context.

## Architecture and how it works

Dragos collects network traffic through passive taps or span ports in the operational-technology environment. Sensors parse industrial protocols and extract asset identity, communication patterns, and command activity without sending traffic to control devices.

Parsed data feeds a central platform that maintains the asset inventory and runs detection analytics. Detections map to known industrial-control-system threat behaviors and adversary activity groups tracked by the vendor.

Vulnerability management works from the passively discovered inventory. Dragos matches identified devices, firmware, and protocols against known weaknesses, so teams can see exposure without an active scan.

Investigation tooling ties detections to the assets and traffic involved. Playbooks guide analysts through control-environment response, where options differ from information-technology response.

## Key capabilities

- Operational-technology asset visibility built passively from observed traffic, including device identity and communication relationships.
- Threat detection mapped to industrial-control-system threat behaviors and tracked activity groups.
- Vulnerability management for operational technology, prioritized for control-environment impact rather than raw severity.
- Investigation workflows and playbooks tailored to control-system response.
- Integrated operational-technology threat intelligence that informs detections and context.
- Protocol awareness across common industrial protocols so analytics understand control commands.

## Deployment and operations

Deployment places passive sensors at the right network locations in the operational-technology environment. Because collection is passive, sensor placement is the main design task. No agents are installed on control devices.

Operations review detections, confirm asset inventory, and track vulnerability exposure against the process they protect. Control-environment staff and security staff work together, since remediation often waits for a maintenance window.

Least-impact collection is the operating rule. Avoid active queries against control devices, and schedule any permitted active checks for maintenance windows agreed with process owners. Keep the inventory current as the environment changes.

## Integrations and data flow

Dragos forwards detections and asset data to a `SIEM` such as Splunk, so operational-technology events sit beside information-technology events. This supports correlation across the boundary where attacks often cross.

Asset and vulnerability data can feed a vulnerability-management program for unified reporting. Detections can drive a security orchestration tool for notification, while keeping response actions human-gated in the control environment.

Data flows outward as detections, asset records, and vulnerability findings. Inbound change is limited to configuration and intelligence updates. Keep connected accounts scoped to the data each integration consumes.

## Adversary perspective

Dragos monitors operational-technology networks passively, so the adversary angle is evading its detection and the fragility of the control systems it watches, not the platform as a route to code execution. The defensive steps are in the "Hardening and secure use" section that follows.

### Evasion and detection gaps

- Blending with normal operations: detection maps to known industrial threat behaviors and a baseline, so an attacker using valid control commands within expected patterns, or acting slowly, can stay below the threshold.
- Blind spots in passive collection: a passive sensor sees only traffic on a monitored tap or span. Activity on an unmonitored segment, a serial or point-to-point link, or hands-on access to a controller leaves no record to detect.
- Starving or spoofing the view (ATT&CK T1685, Disable or Modify Tools): a foothold that disrupts the tap feeding a sensor, or injects traffic, degrades the inventory and detections so they no longer reflect the real state.

### Residual risk and own exposure

Passive monitoring does not patch or harden the controllers it watches; those devices tolerate little active probing and often wait for a maintenance window to be fixed, so known weaknesses persist. The platform and its sensors hold broad visibility and credentials (leaked keys map to [CWE-798](https://cwe.mitre.org/data/definitions/798.html)), so the management interface belongs off the general network and in the monitoring scope.

### Why it matters

Treat loss of sensor visibility as an event in its own right, keep detection content current, and remember the tool reports exposure it cannot remove. See [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for prioritizing fragile assets and [the incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) for control-environment response.

## Hardening and secure use

- Prefer passive and least-impact collection. Active interrogation of control devices can disrupt a process, so gate any active check behind process-owner approval and a maintenance window.
- Enforce role-based access to the platform, and separate read-only analysts from administrators who change sensors or policy.
- Protect sensor and `API` credentials. Do not embed them in scripts or configuration files, which is a hardcoded-credential weakness (CWE-798). Store them in a secret manager and rotate them.
- Place sensors so they see control traffic without becoming an active path into the control network.
- Require strong authentication for platform access, and keep the management interface off the general network.
- Keep detection content and operational-technology threat intelligence current so coverage tracks known activity groups.

## Where it fits in the program

Dragos is the operational-technology pillar of a converged security program. It extends monitoring into an environment that information-technology tools cannot safely scan, and it gives a shared risk picture across the boundary.

For incident response, Dragos scopes an operational-technology intrusion and shows which process assets are involved, which guides containment that does not halt production. For vulnerability management, it supplies an asset-grounded view of operational-technology exposure for risk-based prioritization.

## Resources

- Dragos Platform documentation
- Dragos deployment and sensor placement guide
- Dragos threat intelligence documentation
- Dragos vulnerability management documentation

## Related pages

- [Security platforms](/platforms/README.md)
- [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Claroty](/platforms/claroty.md)
