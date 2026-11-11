# Tanium

Tanium is an endpoint management and security platform from Tanium. It uses a linear-chain, peer-to-peer architecture so that a single server can query and act on large endpoint estates in near real time. The platform spans vulnerability and compliance assessment, patching, software deployment, asset discovery, and threat response. Module availability depends on the licence and the modules entitled.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Endpoint management and security operations teams who run, tune or assess Tanium

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,279 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Tanium for endpoint management and security, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [CrowdStrike Falcon](/platforms/crowdstrike-falcon.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Tanium gives operations and security teams real-time visibility and control over endpoints at scale. One lightweight client runs on each endpoint, and the platform answers questions and runs actions across the estate in seconds rather than through slow, server-by-server polling. It fits where both IT operations and security need the same current state of every managed host.

The product is a set of modules on a shared client and server. A team's capabilities depend on which modules are licensed, so confirm module entitlement before relying on a function such as patching or threat response.

## Architecture and how it works

The distinguishing feature is the linear chain. Clients form a peer-to-peer ring based on network proximity, and a query passes along the chain rather than every client answering the server directly. Results aggregate as they travel back, so one server can collect current data from many endpoints with little network and server load. This is how Tanium answers live questions across the estate quickly.

The core server components are the Tanium Server, which runs the console and distributes questions and actions, and the Tanium Module Server, which hosts the module workbenches. A Zone Server sits in a DMZ so that clients on untrusted networks or outside the perimeter can connect without exposing the main server. The Tanium Client runs on each endpoint, answers questions using sensors, and runs packaged actions. A cloud-hosted option removes the need to run the server infrastructure on-prem.

Questions use sensors to gather data; actions deliver packages that run on the endpoint. Both sensors and packages are content that the platform distributes to clients.

## Key capabilities

Tanium delivers its functions as modules on the shared client:

- Comply: vulnerability and compliance assessment. It evaluates endpoints against vulnerability definitions and configuration benchmarks and produces findings on each host.
- Patch: operating-system and application patch assessment and deployment, with ring-based rollout.
- Deploy: software distribution and installation across the estate.
- Discover: network discovery that finds managed and unmanaged devices.
- Threat Response: endpoint detection and response, live investigation, and recorded endpoint activity for hunting.
- Enforce: central management of host configuration and security policy, including firewall and encryption settings.
- Provision: operating-system provisioning and imaging of endpoints.

For vulnerability management, Comply produces the primary findings: per-host vulnerability and compliance results evaluated against definitions and benchmarks, with current state because the data is collected live. Threat Response produces detections and the recorded activity used for investigation and hunting.

## Deployment and operations

Deployment is the server infrastructure (Tanium Server and Module Server, with a Zone Server for external or DMZ clients) plus the client on each endpoint, or the cloud-hosted service in place of on-prem servers. The client is distributed through existing software tooling or an image, and registers to the server.

Operations run in the Tanium console through module workbenches. Because questions and actions reach the whole estate quickly, teams scope actions carefully with targeting and approvals. Patch and Deploy use rings and maintenance windows so changes roll out in controlled stages. Content (sensors and packages) is managed centrally, and action approval workflows keep high-impact actions under review.

## Integrations and data flow

Tanium provides connectors that send its data to other systems and pull context in. Connect streams endpoint data, findings, and events to a SIEM for correlation and retention. Integrations with ServiceNow synchronize asset inventory and vulnerability findings so that remediation is tracked in the CMDB and the ticketing workflow.

The platform exposes an API for querying data and running actions programmatically, which SOAR and automation tooling use. Vulnerability and compliance findings from Comply feed the vulnerability management workflow, while asset data from the client keeps the inventory current for other tools.

## Adversary perspective

Because Tanium runs actions across the whole estate in near real time, it is both a control an attacker wants to blind and a high-value foothold if its console or content is subverted, so the client and server are themselves an attack surface. The steps to lock the platform down are in the "Hardening and secure use" section that follows.

### Evasion and tampering

- Impairing the client (ATT&CK T1685, Disable or Modify Tools): with local administrator rights an attacker tries to stop or remove the client, or cut its connection so an endpoint stops answering questions and drops out of the live view.
- Abusing package execution: the ability to author and run packages across the estate is effectively remote code execution, so a hijacked console session, a stolen API token, or compromised signing keys lets an attacker push a malicious action to many hosts at once, which turns the platform into a mass foothold ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).
- Blending in: an attacker who gains access times activity to look like routine patching or deployment so it hides among legitimate estate-wide actions.

### Residual risk and own exposure

The client runs with high privilege on every host and the server can execute code across the estate, so a flaw in the client, the server, or the Zone Server is high-impact, and endpoint-management platforms are attractive targets for exactly this reach. The Zone Server sits in a DMZ and faces untrusted clients, so it belongs in the internet-facing patch and monitoring scope along with the signing keys and API tokens.

### Why it matters

Treating the management platform as trusted infrastructure that needs no watching is the mistake. A mature program monitors Tanium's own audit trail, including questions, actions, approvals, and content changes, as a detection signal, and keeps the server tier current. See [the red team reference](/RED_TEAM_REFERENCE.md) for the techniques and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for keeping the control itself in scope.

## Hardening and secure use

Securing the platform itself centers on access and content control. Use role-based access control together with content set permissions so that users can run only the sensors and packages, and target only the computer groups, that their role allows (CWE-862: Missing Authorization). The ability to run arbitrary packages across the estate is effectively remote code execution, so restrict package authoring and action approval to a small, trusted group.

Require signing of packages and sensors so that only approved, signed content runs on endpoints, and protect the signing keys. Treat API tokens as privileged secrets: issue tokens with the least scope, rotate them, and store them in a secret manager rather than in scripts or configuration (CWE-798: Use of Hard-coded Credentials).

Place the Zone Server correctly in the DMZ and lock down its exposure so external clients connect without reaching the core server directly. Enable and review the audit trail, which records questions, actions, approvals, and configuration changes, and require multi-factor authentication on console access.

## Where it fits in the program

A vulnerability management and security operations team uses Tanium for live, estate-wide state and action. Comply supplies current vulnerability and compliance findings, Patch and Deploy carry out remediation, and Threat Response gives the SOC detection and investigation on the same hosts. Because one client serves both operations and security with real-time data, the team assesses, prioritizes, and remediates without waiting on stale inventory, and tracks the work through ServiceNow and the SIEM.

## Resources

- Tanium Core Platform documentation
- Tanium Comply user guide
- Tanium Patch user guide
- Tanium Threat Response user guide
- Tanium Connect documentation

## Related pages

- [Security platforms](/platforms/README.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [CrowdStrike Falcon](/platforms/crowdstrike-falcon.md)
- [ServiceNow Vulnerability Response](/platforms/servicenow-vr.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Tanium entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=tanium)

<!-- hub-links:end -->
