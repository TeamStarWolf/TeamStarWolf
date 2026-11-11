# Claroty

Claroty protects cyber-physical systems across operational technology, the Internet of Things, and healthcare. Claroty xDome and Continuous Threat Detection give asset discovery, exposure management, and network monitoring. This page describes the generally available product in 2026. Licence tier decides which capabilities are in force.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

OT and ICS security engineers and asset owners who run, tune or assess Claroty

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (1,034 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Claroty for operational technology and industrial control system security, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Dragos](/platforms/dragos.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Connected devices now reach far beyond servers and laptops. Control systems, building sensors, and connected medical equipment share networks but rarely tolerate traditional scanning or agents. These are cyber-physical systems.

Claroty secures that class of device. It discovers assets, measures their exposure, and watches their network behavior without disrupting the physical processes they run. Healthcare coverage extends this to the Internet of Medical Things.

In a security program, Claroty is the control for the cyber-physical estate. It gives a view that information-technology tools miss and feeds shared risk reporting. See the hub at /hubs/ics-ot-and-hardware.md for the wider control-environment context.

## Architecture and how it works

Claroty discovers assets through passive network monitoring and, where safe, targeted active queries suited to each device type. Passive collection parses traffic to identify devices, firmware, and communication relationships without touching sensitive controllers.

Continuous Threat Detection focuses on operational-technology and industrial networks. It parses industrial protocols, builds a baseline of normal behavior, and alerts on deviations and known threat activity.

Claroty xDome extends the model across operational technology, the Internet of Things, and the Internet of Medical Things. It centralizes asset inventory, exposure and vulnerability findings, and monitoring in one place.

The platform matches discovered assets against known weaknesses to produce exposure findings. It also maps communication so teams can plan and validate network segmentation.

## Key capabilities

- Asset discovery across operational technology, the Internet of Things, and the Internet of Medical Things, built mainly from passive observation.
- Exposure and vulnerability management that prioritizes findings by device role and physical impact.
- Network monitoring with baselining and detection of anomalous or malicious behavior.
- Segmentation guidance that uses observed communication to define and validate zones.
- Protocol awareness across industrial and clinical device protocols.
- Healthcare-specific visibility for connected medical equipment and its clinical context.

## Deployment and operations

Deployment places collection at network locations where device traffic is visible, through passive taps or span ports. Active queries, where enabled, are scoped to device types that tolerate them and scheduled carefully.

Operations maintain the inventory, review exposure findings, and act on detections. Segmentation work is iterative, since observed communication shows which flows a new zone boundary must allow before enforcement.

Passive collection is preferred wherever it covers the need. In clinical and control settings, coordinate any active check with the owners of the equipment and the process, and keep the inventory current as devices change.

## Integrations and data flow

Claroty forwards asset data, exposure findings, and detections to a `SIEM` such as Splunk and to vulnerability-management reporting, so cyber-physical risk sits beside information-technology risk.

Segmentation guidance can inform firewall and network-access-control policy, including a network-access-control platform such as Cisco ISE. Detections can drive a security orchestration tool, with enforcement actions kept human-gated in sensitive environments.

Data flows outward as inventory, findings, and detections. Inbound change is limited to configuration and content updates. Keep connected accounts scoped to the data each integration needs.

## Adversary perspective

Claroty mostly watches rather than blocks, so the adversary angle is evading its detection and the fragility of the cyber-physical systems it monitors, not the tool as a route to code execution. The defensive steps are in the "Hardening and secure use" section that follows.

### Evasion and detection gaps

- Blending with normal operations: because detection baselines normal behavior, an attacker who issues valid-looking control commands within expected patterns, or who moves slowly, can stay under the anomaly threshold.
- Blind spots in passive collection: a passive sensor sees only traffic that crosses a monitored span or tap. Activity on an unmonitored segment, a serial link, or direct physical access to a controller leaves no network record to detect.
- Starving or spoofing the view (ATT&CK T1685, Disable or Modify Tools): an attacker with a foothold can disrupt the span or tap feeding a sensor, or inject traffic, so the inventory and detections no longer reflect the real state.

### Residual risk and own exposure

Monitoring does not harden the underlying devices: the controllers and medical equipment it watches often cannot be patched quickly and tolerate little active probing, so known weaknesses persist by design. The platform and its collectors hold broad visibility and credentials (leaked keys map to [CWE-798](https://cwe.mitre.org/data/definitions/798.html)), so the management interface belongs off the general network and in the monitoring scope.

### Why it matters

Treat loss of sensor visibility as an event, validate segmentation against observed flows, and remember the control reports risk it cannot itself remove. See [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for prioritizing fragile assets and [the incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) for control-environment response.

## Hardening and secure use

- Prefer passive collection where it meets the need. Reserve active queries for device types that tolerate them, and coordinate with equipment and process owners first.
- Enforce role-based access to the platform, and separate analysts who read findings from administrators who change collection or policy.
- Protect collector and `API` credentials. Do not embed them in scripts or configuration files, which is a hardcoded-credential weakness (CWE-798). Store them in a secret manager and rotate them.
- Place collectors so they observe device traffic without becoming an active route into sensitive networks.
- Require strong authentication for platform access, and isolate the management interface from the general network.
- Validate segmentation against observed flows before enforcing, so a new boundary does not break a clinical or control dependency.

## Where it fits in the program

Claroty is the cyber-physical pillar of a converged program. It covers operational technology, the Internet of Things, and healthcare devices that standard tools cannot safely assess, and it supports segmentation that contains them.

For incident response, Claroty scopes an intrusion into the cyber-physical estate and shows which devices and flows are affected. For vulnerability management, it supplies exposure data prioritized by physical and clinical impact for risk-based decisions.

## Resources

- Claroty xDome documentation
- Claroty Continuous Threat Detection documentation
- Claroty deployment and collection guide
- Claroty Healthcare documentation

## Related pages

- [Security platforms](/platforms/README.md)
- [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Dragos](/platforms/dragos.md)
- [Cisco ISE](/platforms/cisco-ise.md)
