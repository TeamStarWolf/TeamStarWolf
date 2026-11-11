# Forcepoint

Forcepoint is a data-first security vendor. Its products are organized around understanding and protecting data, whether that data is moving to the web, into cloud applications, or across network boundaries. Data loss prevention is central to its approach.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Data security and network security engineers who run, tune or assess Forcepoint

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,291 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Forcepoint for data security, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Zscaler](/platforms/zscaler.md), [Cisco Secure Access](/platforms/cisco-secure-access.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Forcepoint groups its products around the control of sensitive data. Forcepoint ONE is its security service edge, and Data Security provides data loss prevention across channels. A next-generation firewall addresses network boundaries where that product is deployed.

The organizing idea is that security policy should follow the data and the user, not the network. The platform classifies content and applies policy to where that content is allowed to go.

For a security operations and network team, Forcepoint fills two roles:

- An enforcement point for web and cloud access.
- A control that prevents sensitive data from leaving by unauthorized paths.

It also produces telemetry about access and data movement. Data loss prevention events in particular are useful signals, because an attempt to move protected data can indicate a mistake, a misconfiguration, or deliberate exfiltration.

## Architecture and how it works

Forcepoint ONE is a cloud-delivered security edge. User traffic is steered to the service for inspection and policy enforcement. Enforcement happens in three places, depending on the channel and deployment:

- In the cloud, for web and cloud-application traffic.
- On endpoints, through an agent, for data in use and local controls.
- At network boundaries, where the next-generation firewall is deployed.

Web traffic passes through the secure web gateway, which can decrypt and inspect encrypted sessions. Cloud application use is governed by the cloud access security broker, which can apply controls inline and through application APIs. Private applications are reached through zero-trust access that brokers connections rather than placing users on a network.

Data Security runs policy that inspects content against classifiers and rules. It can enforce at the endpoint, on the web channel, in email, and in cloud applications. The same policy intent can be applied across these channels, so a rule about sensitive data holds wherever the data tries to move.

Where the next-generation firewall is deployed, it enforces network-layer policy and provides inspection at physical and virtual boundaries.

## Key capabilities

Forcepoint ONE combines several edge functions:

- A secure web gateway that filters and inspects internet-bound traffic.
- A cloud access security broker that discovers and controls cloud application use.
- Zero-trust access that brokers connections to private applications without exposing the network.

Data loss prevention, delivered through Data Security, is the central capability:

- It classifies content using patterns, fingerprints, and context.
- It enforces where sensitive data may travel.
- It covers data in motion across web, email, and cloud, and data at rest and in use on endpoints.

The next-generation firewall provides network segmentation, inspection, and policy enforcement at boundaries where it is in place. Together these controls let a team apply one view of acceptable data movement across channels, rather than maintaining separate and inconsistent rules per product.

## Deployment and operations

Deployment of Forcepoint ONE begins with steering web and cloud traffic to the service and enabling the relevant modules. Endpoints run an agent where endpoint enforcement or data controls are needed.

Data loss prevention deployment follows a sequence:

- Define classifiers and policies for the data that matters.
- Choose enforcement modes per channel.
- Start in a monitor mode to measure false positives before switching rules to block.

Policy tuning is ongoing. Classification must be accurate, because a rule that mislabels content either blocks legitimate work or misses real exposure. Operators review incidents, refine classifiers, and adjust actions over time.

The next-generation firewall is managed through its management center where deployed. The licence tier decides which modules and controls are in force, so operators confirm what the subscription includes before relying on a given control.

## Integrations and data flow

Forcepoint integrates with identity providers through `SAML` and `SCIM` so that policy references real users and groups. Cloud access controls can use application APIs to inspect content already stored in sanctioned services.

Incidents and logs flow to a SIEM for correlation. Data loss prevention events are valuable to a security operations team because they show attempts to move sensitive data, which can indicate both mistakes and deliberate exfiltration. Correlating these events with identity and endpoint data helps judge intent and scope.

APIs support configuration and reporting, which allows policy and incident data to be managed alongside other tooling.

## Adversary perspective

Forcepoint enforces web and cloud access and watches for sensitive data leaving, so adversaries work to move data by a channel it does not see and to route around its inspection. The steps to lock the platform down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Channel and steering bypass: data moved over a channel that is not steered or inspected, or from an endpoint where the agent is absent or disabled, escapes data loss prevention (ATT&CK T1685, Disable or Modify Tools).
- Defeating classifiers: encrypting, encoding, renaming, or splitting content can prevent classifiers and fingerprints from matching, so sensitive data passes as something else.
- SSL-inspection exclusions: traffic excluded from decryption is not examined, and an attacker favors those destinations for exfiltration.
- Monitor mode and permissive defaults: a policy left in monitor mode records exposure without blocking it.
- NGFW edge exposure: where the next-generation firewall is deployed, an internet-facing boundary device is a target like any edge appliance.

### Residual risk and own exposure

Data loss prevention catches known patterns on inspected channels, so novel encodings and unmonitored paths remain the real residual risk, and the admin tenant holds sensitive classifiers and incident data. Where appliances are deployed, they are tracked assets with their own patch state. Admin access, API credentials, and agent enforcement belong in the monitoring scope ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)).

### Why it matters

For a tester, an uninspected channel and a classifier that a simple transform defeats are the first things to look for. For a defender, covering every channel, keeping exclusions small, and switching tuned rules from monitor to block are what make the control real. See [the red team reference](/RED_TEAM_REFERENCE.md) and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## Hardening and secure use

- Use role-based administration. Separate the people who write data policy from those who review incidents, and give each role the least privilege needed.
- Protect API credentials and administrator secrets. Credentials placed in scripts or plain configuration are hardcoded credentials, which maps to `CWE-798` (Use of Hard-coded Credentials). Store them in a secret manager and rotate them.
- Tune data loss prevention policy and keep classification accurate. Over-broad rules create alert fatigue, and under-specified rules miss real exposure. Review both the hits and the misses.
- The purpose of data loss prevention is to stop sensitive data from leaving by unauthorized paths. Cleartext handling of sensitive data increases that exposure, which maps to `CWE-312` (Cleartext Storage of Sensitive Information). Ensure protected data is encrypted in storage and in transit, and that policy covers the channels where cleartext could leak.
- Enforce strong authentication for admin consoles and monitor admin activity for unexpected policy or classifier changes.

## Where it fits in the program

Forcepoint is both an access-control layer and a data-protection layer. It narrows the ways sensitive data can leave and inspects web and cloud traffic inline.

Its data loss prevention events support detection and incident response by flagging attempts to move protected data. Its access and inspection logs help reconstruct activity during an investigation and help scope what data a compromised account could have touched. In a program that tracks data exposure as a first-class risk, Forcepoint is a primary source of evidence.

## Resources

- Forcepoint ONE documentation
- Forcepoint Data Security administration guide
- Forcepoint Next-Generation Firewall documentation
- Forcepoint Security Manager documentation
- Forcepoint API reference

## Related pages

- [Security platforms](/platforms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Zscaler](/platforms/zscaler.md)
- [Cisco Secure Access](/platforms/cisco-secure-access.md)
