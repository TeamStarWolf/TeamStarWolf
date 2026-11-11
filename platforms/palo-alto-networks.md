# Palo Alto Networks

Palo Alto Networks is a network and cloud security vendor. Its products cover
on-premises firewalls, cloud-delivered secure access, and security operations.
A network and security team meets it as perimeter enforcement, as a SASE edge,
and as tooling for detection and response.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network security engineers who run, tune or assess Palo Alto Networks

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,423 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Palo Alto Networks for network firewalling and threat prevention, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md), [Cortex XSOAR](/platforms/cortex-xsoar.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Palo Alto Networks sells three product families that a security team uses
together. Next-Generation Firewalls on PAN-OS enforce policy at network
boundaries. Prisma Access delivers secure access for remote users and branch
sites from the cloud. The Cortex family supports detection, investigation, and
response in the security operations center.

The firewalls sit at internet edges, data-center cores, and segmentation
boundaries. They decide what traffic is allowed by application, by user, and by
content. Prisma Access extends the same policy model to users who are not behind
a physical firewall. Cortex consumes the logs and telemetry these controls
produce.

For a vulnerability-management program, the firewall platform is both a control
and an asset to track. It blocks and inspects traffic. It also runs firmware
that must be patched and management planes that must be guarded.

## Architecture and how it works

PAN-OS is the operating system on the firewalls. It separates a data plane that
inspects traffic from a management plane that handles configuration and
administration. The data plane applies policy at line rate. The management plane
hosts the web interface, the API, and the command-line interface.

App-ID identifies the application inside a traffic flow, independent of port or
protocol. Policy can then permit or deny by application rather than by port
number alone. User-ID maps traffic to a user identity, so policy follows the
person and not only the address. Content-ID inspects allowed traffic for threats
and sensitive data.

Threat Prevention adds intrusion prevention, anti-malware, and command-and-
control detection to allowed sessions. WildFire is a cloud sandbox. It detonates
unknown files and returns a verdict, and that verdict updates protections across
subscribed firewalls.

Panorama is the central management system. It pushes policy, manages device
groups, and aggregates logs from many firewalls. A team running more than a few
devices manages them through Panorama rather than one at a time.

Prisma Access runs the PAN-OS inspection stack as a cloud service. Users and
sites connect to the nearest cloud node. Policy is enforced there before traffic
reaches the internet or private applications.

The Cortex family covers operations. Cortex XDR correlates endpoint, network,
and cloud telemetry for detection and response. Cortex XSIAM is the security
operations platform that centralizes data and automation. Cortex XSOAR handles
orchestration and automated response playbooks. See
`/platforms/cortex-xsoar.md` for the orchestration layer.

## Key capabilities

- Application-aware policy through App-ID, so rules match applications not ports.
- Identity-aware policy through User-ID, so rules follow users and groups.
- Threat inspection through Content-ID and Threat Prevention on allowed flows.
- Cloud sandboxing through WildFire for unknown file verdicts.
- Central management, device grouping, and log aggregation through Panorama.
- Cloud-delivered secure access through Prisma Access for remote users and sites.
- URL filtering, DNS security, and decryption for inspected sessions.
- Detection and response and automation through the Cortex family.

What is in force depends on the licence tier. Subscriptions such as Threat
Prevention, WildFire, URL filtering, and DNS Security are separately licensed.
Confirm which subscriptions are active before assuming a protection is on.

## Deployment and operations

Firewalls deploy as physical appliances, as virtual machines, and as cloud-
native instances. The VM-Series runs in public and private clouds. Form factor
changes throughput and placement, not the policy model.

Day-to-day operations center on policy change, content updates, and firmware
currency. Content updates deliver new application signatures and threat
protections. These install frequently and change what the firewall recognizes.
Firmware updates deliver PAN-OS fixes and features on a slower cadence.

A team should track PAN-OS versions against vendor advisories. Edge devices have
a history of high-severity vulnerabilities in their management interfaces. A firewall
that is behind on firmware is an exposed asset, not only a control. See
`/VULNERABILITY_MANAGEMENT_REFERENCE.md` for how to track such assets.

High availability pairs firewalls so one takes over if another fails. Panorama
templates and device groups keep configuration consistent across a fleet.
Logging forwards to Panorama, to a SIEM, or to both.

## Integrations and data flow

Firewalls and Prisma Access produce traffic logs, threat logs, URL logs, and
WildFire verdicts. These forward to Panorama and onward to a SIEM such as
Splunk for correlation and retention. See `/platforms/splunk.md` for the
analytics destination.

User-ID integrates with directory services and identity providers to map
addresses to users. The firewall reads group membership and login events to
build that mapping. Decryption policy lets the firewall inspect encrypted
sessions, subject to privacy and compliance review.

The PAN-OS XML API and REST API expose configuration and operational data.
Automation reads logs, pushes policy, and queries device state through these
interfaces. Cortex XSOAR drives response actions back into the firewalls through
the same APIs.

WildFire verdicts flow out to the vendor cloud and back as updated protections.
Threat intelligence feeds, including third-party and custom feeds, drive dynamic
block lists that policy can reference.

## Adversary perspective

The firewalls sit at internet edges and often terminate GlobalProtect VPN, so adversaries treat PAN-OS as an appliance to exploit as much as a policy to evade. The steps to lock the platform down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Management-plane exploitation: PAN-OS management-interface flaws have been exploited, and an exposed management plane is a direct route in (ATT&CK T1190, Exploit Public-Facing Application).
- VPN and portal exposure: an internet-facing remote-access portal is a standing target for this device class.
- Inspection gaps: a session that bypasses decryption is not inspected, and App-ID or Threat Prevention can be evaded by encoding, tunneling, or using an allowed application.
- Credential and API abuse: a leaked or hard-coded API key gives the same control as an admin login and lets an attacker rewrite policy (ATT&CK T1685, Disable or Modify Tools).

### Residual risk and own exposure

Internet-facing firewalls and VPN gateways are high-value targets, and an unpatched PAN-OS device is an exposed asset rather than only a control. The firewall enforces only what policy expresses and inspects only what it decrypts, so a decryption exclusion is a blind spot. Firmware currency and the management plane belong in the patch and monitoring scope ([CWE-306](https://cwe.mitre.org/data/definitions/306.html)).

### Why it matters

For a tester, management-plane reachability, portal exposure, and decryption gaps are the first things to probe. For a defender, short-timeline patching, an isolated management plane, and confirmed deny rules keep the control honest. See [the red team reference](/RED_TEAM_REFERENCE.md) and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## Hardening and secure use

Isolate the management plane. The web interface, SSH, and API should not be
reachable from the internet or from general user networks. Management interface
exposure has been the entry point for several past firewall compromises. Restrict
management to a dedicated network and known administrator addresses.

Keep firmware current. Edge devices are high-value targets, and unpatched
PAN-OS management-plane flaws have been exploited. Subscribe to vendor
advisories and patch management-affecting issues on a short timeline.

Use role-based administration. Give each administrator the least privilege the
role needs. Avoid shared superuser accounts. Require multi-factor authentication
for administrative access.

Protect API keys and service credentials. A leaked or hard-coded key gives an
attacker the same control as an admin login, which maps to CWE-798, use of
hard-coded credentials. Store keys in a secret manager, scope them narrowly, and
rotate them. Do not place keys in scripts or configuration pushed to version
control.

Review decryption and inspection policy for coverage and for privacy. Traffic
that bypasses decryption is not inspected. Verify that deny rules deny rather
than only log, and that the implicit final rule matches your intent.

## Where it fits in the program

Palo Alto Networks platforms are enforcement and visibility points in the
program. The firewalls segment the network and inspect traffic. Prisma Access
carries that enforcement to remote users. The Cortex family turns the resulting
telemetry into detection and response.

For vulnerability management, treat every firewall and Panorama instance as a
tracked asset with its own patch state. The control that protects the network is
also an internet-facing device that needs the same discipline as any other. See
`/INTERNET_FACING_SERVICES_REFERENCE.md` for exposure tracking.

## Resources

- PAN-OS Administrator's Guide
- Panorama Administrator's Guide
- Prisma Access Administration documentation
- Cortex XDR Documentation
- Cortex XSIAM Documentation
- PAN-OS and Panorama API documentation
- Palo Alto Networks Security Advisories

## Related pages

- [Security platforms](/platforms/README.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md)
- [Cortex XSOAR](/platforms/cortex-xsoar.md)
- [Prisma Cloud](/platforms/prisma-cloud.md)
- [Splunk Enterprise Security](/platforms/splunk.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Palo Alto Networks entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=palo-alto-networks) · [Palo Alto Networks entries linked to CISA KEV](https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=palo-alto-networks)

<!-- hub-links:end -->
