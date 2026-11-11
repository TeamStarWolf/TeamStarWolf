# Sophos

Sophos is an endpoint protection and managed detection vendor whose products are managed from the Sophos Central cloud console. Its endpoint line, Intercept X, combines deep-learning malware prevention, anti-ransomware, and exploit prevention. Sophos XDR extends detection across endpoint, server, firewall, and email, while Sophos MDR offers a managed detection and response service run by Sophos analysts.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Endpoint security engineers and SOC analysts who run, tune or assess Sophos

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,080 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Sophos for endpoint protection, detection and response, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [SentinelOne Singularity](/platforms/sentinelone.md), [Trend Vision One (Trend Micro)](/platforms/trend-micro.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Sophos belongs to the endpoint protection (EPP), endpoint detection and response (EDR), and extended detection and response (XDR) categories. It also spans network and email security, so a single vendor can cover several control layers. The common management plane is Sophos Central, a cloud console that holds policy, alerts, and reporting for every product a tenant licenses.

For a security operations and vulnerability management team, Sophos provides prevention and detection on endpoints and servers, plus an optional managed service. Teams short on staff can hand monitoring and response to Sophos MDR while keeping control of policy. Licence tier and module entitlement decide what is in force, including XDR data retention, the MDR service level, and which firewall or email features apply.

## Architecture and how it works

Endpoints and servers run the Sophos agent, which reports to Sophos Central over the internet. The agent carries prevention layers that act locally, so protection continues when a host is offline. Central stores policy and pushes it to agents, and it collects detections and telemetry for review.

Intercept X is the endpoint prevention engine. A deep-learning model classifies files as malicious or clean without relying on signatures for every variant. CryptoGuard watches for the file-encryption behavior typical of ransomware and can stop and roll back unauthorized encryption. Exploit prevention blocks the techniques attackers use to abuse legitimate software, such as memory corruption and process injection.

Sophos XDR adds data collection and query across endpoints, servers, firewalls, and email. Detections from different products correlate in Central, and analysts can run queries against stored telemetry to hunt and investigate. Retention length depends on the licensed tier.

Sophos MDR is a service layer on top of the same telemetry. Sophos analysts monitor the tenant, investigate detections, and take response actions by agreement. The customer defines the response authorization, from notify-only to full containment.

## Key capabilities

- Deep-learning malware prevention in Intercept X that classifies files without per-variant signatures.
- CryptoGuard anti-ransomware that detects malicious encryption and rolls affected files back.
- Exploit prevention that blocks common exploitation techniques against legitimate applications.
- Sophos XDR for cross-product detection, correlation, and threat hunting from Central.
- Sophos MDR, a managed service where Sophos analysts monitor and respond on the tenant's behalf.
- Server protection with controls suited to workloads, including Windows and Linux servers.
- Firewall and email security products managed in the same Central console.
- Device and application control policies that limit what runs and connects.

Feature availability follows the licensed product set. A tenant may run endpoint protection alone or combine it with firewall, email, and the managed service.

## Deployment and operations

Agents install through Sophos Central, a deployment package, or standard software distribution tools. Policies in Central apply to groups of devices and servers, each with its own prevention and detection settings. Begin with recommended policies, confirm the baseline in the environment, then tighten controls such as application and device control.

Operational work centers on reviewing detections in Central, confirming automated responses, and tuning exclusions. Scope exclusions narrowly to a path, process, or hash rather than a broad folder, because wide exclusions create blind spots. Monitor agent health so every host reports in and runs current protection.

Where Sophos MDR is licensed, the team coordinates with Sophos analysts on response authorization and escalation paths. Define in advance which actions Sophos may take without a callback and which require approval. Keep firewall and email policy under the same review discipline as endpoint policy.

## Integrations and data flow

Sophos Central exports alerts and events to SIEM platforms through its API and connectors. This forwards endpoint, server, firewall, and email detections into a central correlation and archival store. Verify the supported connector and the data format for the entitled tier before relying on it.

SOAR platforms can consume Sophos alerts and call the Central API to run response actions, supporting automated playbooks. The API also drives custom reporting and bulk device management. Treat the API as a control plane because it can change policy and isolate hosts.

Sophos products share telemetry inside Central, so a firewall detection can enrich an endpoint investigation. This cross-product flow is part of the XDR value when several Sophos products are licensed. External threat intelligence feeds enrich detections with context.

## Hardening and secure use

Apply role-based administration in Central so each admin holds only the scope their duties need. Separate read-only roles from administrators who can change policy or authorize response. Review role assignments on a schedule and remove access that is no longer needed, because over-broad roles are an authorization weakness (CWE-862, missing authorization).

Protect API credentials as secrets. A Sophos Central API credential embedded in a script or pipeline is a credential exposure risk (CWE-798, use of hard-coded credentials). Store credentials in a secrets manager, scope them to the minimum needed, and rotate them on a defined cadence. Revoke credentials that are unused.

Enable tamper protection so an attacker with local privileges cannot disable or remove the agent. Keep tamper-protection passwords and recovery codes under controlled access in Central. Enforce multi-factor authentication for Central sign-in and prefer federation through the organization's identity provider.

Keep tenant configuration consistent so no device group drifts into a weaker policy than intended. Audit exclusions, application control, and device control settings regularly. Confirm that MDR response authorizations match current policy and that escalation contacts are current.

## Where it fits in the program

Sophos is the endpoint and, where licensed, network and email prevention and detection layer. In a vulnerability management program, it provides the execution-level and traffic-level visibility that scanner findings do not. A scanner reports exposure; Sophos reports whether something is acting on a host or crossing the firewall.

The optional MDR service lets a lean team sustain round-the-clock monitoring without building a full in-house watch. Feeding Sophos detections into the SIEM and SOAR links exposure data to detection and response. Endpoint and firewall signals also help rank which vulnerable assets need attention first.

## Resources

- Sophos Central Admin documentation
- Sophos Intercept X documentation
- Sophos XDR documentation
- Sophos MDR service documentation
- Sophos Central API documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [SentinelOne Singularity](/platforms/sentinelone.md)
- [Trend Micro](/platforms/trend-micro.md)
- [Fortinet](/platforms/fortinet.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Sophos entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=sophos) · [Sophos entries linked to CISA KEV](https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=sophos)

<!-- hub-links:end -->
