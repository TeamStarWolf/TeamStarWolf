# Fortinet

Fortinet builds a set of network and security products that are designed to work together. The connective layer is branded the Fortinet Security Fabric. The firewall, FortiGate, is the anchor, and other products extend protection to endpoints, analytics, and detection.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network security engineers who run, tune or assess Fortinet

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (998 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Fortinet for network firewalling and threat prevention, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Check Point](/platforms/check-point.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Fortinet offers a product family rather than a single tool. FortiGate is the next-generation firewall at the center. Around it sit products for network detection, analytics, endpoint protection, and threat intelligence. The Security Fabric is the set of integrations that lets these products share context and policy.

The aim is that each product contributes to a shared view. A firewall decision can draw on endpoint posture, and an analytics platform can correlate events from several products.

For a security operations and network team, Fortinet provides three things:

- Enforcement at network boundaries, through FortiGate.
- Detection on the wire and on endpoints, through FortiNDR and FortiEDR.
- Analytics that tie the events together, through FortiAnalyzer and FortiSIEM.

Fortinet is also an asset class in its own right. Edge devices such as firewalls have a history of CVEs, so the estate is something a vulnerability-management process must track, not only a control it depends on.

## Architecture and how it works

Fortinet products ship as physical appliances and as virtual machines. FortiGate runs on dedicated hardware in many sites and as a virtual instance in data centers and cloud. Virtual deployment lets the same policy model extend to environments without a physical appliance.

Central management holds the fleet together:

- FortiManager pushes policy and configuration to many FortiGate devices from one place.
- FortiAnalyzer centralizes logs and reporting across Fortinet devices.
- FortiSIEM extends correlation across a broader set of sources.

The Security Fabric ties products together through shared telemetry and automation. Posture and detection signals from one product can inform policy on another. FortiGuard supplies threat intelligence that updates signatures, categories, and detection content across the fabric.

Enforcement happens at the boundary with FortiGate, on the endpoint with FortiEDR, and on the wire with FortiNDR. Analytics sit above these to provide detection, reporting, and retention.

## Key capabilities

FortiGate is the next-generation firewall. It provides:

- Network segmentation and policy enforcement at boundaries.
- Inspection of traffic, including encrypted sessions where configured.
- Intrusion prevention and application control.

FortiNDR provides network detection and response. It watches traffic for behavior that signals compromise, including activity that does not match a known signature.

FortiAnalyzer and FortiSIEM provide analytics. FortiAnalyzer centralizes logs and reporting across Fortinet devices. FortiSIEM extends correlation across a broader set of sources for security monitoring.

FortiEDR protects endpoints. It detects and responds to activity on hosts and feeds that context back into the fabric.

FortiGuard is the threat intelligence service. It delivers updates for signatures, URL categories, and detection content that keep the other products current.

## Deployment and operations

FortiGate is deployed at network boundaries as appliances or virtual machines. Larger estates manage these through FortiManager so that policy stays consistent and changes are reviewed in one place.

Logging and analytics follow:

- Logs are directed to FortiAnalyzer, FortiSIEM, or an external SIEM.
- Correlation is tuned so that alerts are meaningful rather than noisy.
- Retention is set to meet investigation and compliance needs.

FortiEDR is rolled out as an agent to endpoints. FortiNDR is placed where it can see the relevant traffic. The Security Fabric integrations are configured so that products share context and can trigger automated actions.

Firmware and signature currency is an ongoing operational task. Edge devices have a history of CVEs, so keeping firmware current is a core part of operating a FortiGate fleet. The licence tier decides which features and FortiGuard services are in force, so operators confirm what the subscription includes.

## Integrations and data flow

The Security Fabric is the integration layer. Products share telemetry and automation triggers, so a detection on one can drive an action on another.

Logs flow to FortiAnalyzer and FortiSIEM, and can be forwarded to an external SIEM for correlation with non-Fortinet sources. This gives a security operations team a combined view across network, endpoint, and boundary events.

FortiGuard feeds threat intelligence into the fabric. APIs on FortiGate and FortiManager allow configuration and reporting to be automated, which supports change control and integration with ticketing and orchestration.

## Hardening and secure use

- Control administrative access tightly. Use role-based administration, and restrict management access to known management addresses using the trusted hosts feature, so that the admin interface is not reachable from arbitrary networks.
- Protect API tokens and administrator credentials. Tokens embedded in scripts or stored in plain configuration are hardcoded credentials, which maps to `CWE-798` (Use of Hard-coded Credentials). Keep them in a secret manager and rotate them.
- Keep firmware current. Given the history of CVEs in edge devices, firmware currency is a primary control. Track advisories, confirm exposure against a vulnerability-management process, and patch on a defined schedule. See /SCANNER_PLATFORMS_REFERENCE.md and /VULNERABILITY_MANAGEMENT_REFERENCE.md for how to find and prioritize these.
- Isolate the management interface from user and internet traffic. A management plane reachable from the internet is a frequent path to compromise. Place management on a dedicated network and require strong authentication.
- Monitor admin activity and configuration changes, and enable logging on the devices so that changes and denied traffic are recorded.

## Where it fits in the program

Fortinet provides enforcement, detection, and analytics across the network and endpoints. FortiGate shapes what crosses boundaries, FortiNDR and FortiEDR detect compromise, and the analytics products tie the events together.

Its logs feed incident response by showing boundary decisions, network behavior, and endpoint activity. Because edge-device CVEs are a known attacker target, the Fortinet estate is itself an asset that vulnerability management must track. The platform is therefore both a control the program relies on and a surface the program must defend.

## Resources

- Fortinet Document Library
- FortiGate Administration Guide
- FortiManager Administration Guide
- FortiAnalyzer and FortiSIEM documentation
- FortiGuard Labs threat intelligence documentation
- Fortinet PSIRT advisories

## Related pages

- [Security platforms](/platforms/README.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Check Point](/platforms/check-point.md)
- [Cisco Secure Access](/platforms/cisco-secure-access.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Fortinet entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=fortinet) · [Fortinet entries linked to CISA KEV](https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=fortinet)

<!-- hub-links:end -->
