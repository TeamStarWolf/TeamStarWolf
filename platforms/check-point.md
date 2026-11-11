# Check Point

Check Point is a network and cloud security vendor. Its gateways enforce access policy, inspect traffic, and apply threat prevention across data center, perimeter, and cloud boundaries. This page describes the product line as generally available in 2026. The licence tier an organization holds decides which capabilities are in force.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network security engineers who run, tune or assess Check Point

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,360 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Check Point for network firewalling and threat prevention, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Fortinet](/platforms/fortinet.md), [Citrix NetScaler](/platforms/citrix-netscaler.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Check Point sells security enforcement points and the management plane that controls them. The core enforcement product is the Quantum line of security gateways, which act as firewalls, intrusion prevention sensors, and threat prevention inspection points. Harmony covers endpoint and email protection. CloudGuard extends enforcement and posture checking into public cloud accounts and workloads.

The Infinity architecture is the vendor name for tying these products to one shared policy and threat intelligence model. The intent is that a protection written once can apply at the gateway, the endpoint, and the cloud boundary, and that logs from each flow to one place.

For a network and security team, Check Point sits at the boundary between trust zones. It is where network segmentation is enforced, where inbound and outbound traffic is inspected, and where a network-layer virtual patch can hold a line while a host-level fix is scheduled.

## Architecture and how it works

A Check Point deployment separates the gateway from the management server. The gateway enforces the policy and inspects packets. The management server stores the policy, compiles it, and pushes an installed policy to each gateway. This split means an administrator edits policy centrally and then installs it to selected gateways.

Gateways run a set of inspection functions called blades. A firewall blade handles stateful access control. An IPS blade inspects for known attack patterns. Threat Prevention blades add anti-bot, antivirus, and sandboxing checks. HTTPS inspection decrypts traffic so the inspection blades can read inside an encrypted session.

SmartConsole is the administrator client for editing policy and reviewing configuration. SmartEvent is the log and event analysis component, where security events from gateways are correlated and searched. Policy installation is a deliberate step: a change in SmartConsole does not take effect until it is installed to the gateway.

## Key capabilities

- Access policy: stateful rules that permit or deny traffic by source, destination, service, application, and user identity.
- IPS: signature and protocol-based intrusion prevention. Individual protections can target a specific CVE, which lets a gateway block exploitation of a named vulnerability at the network layer. This is a form of network virtual patching while the affected host is remediated.
- Threat Prevention: anti-bot detection, antivirus scanning, and sandbox analysis of files for unknown threats.
- HTTPS inspection: decryption of outbound and inbound TLS so content inspection can examine the payload rather than only the handshake.
- Suspicious Activity Monitoring: rules that block traffic matching an operator-defined condition without a full policy install, useful for a fast response to an active incident.
- Identity awareness: binding access rules to users and groups rather than only to IP addresses.
- Logging and events: forwarding to SmartEvent and to external log collectors.

Each IPS and Threat Prevention protection carries an action. A protection set to Detect logs a match and allows the traffic. A protection set to Prevent blocks it. Confusing the two is a common gap, so profile action should be verified rather than assumed.

## Deployment and operations

Gateways deploy as physical appliances, virtual machines, or cloud instances. Clusters of two or more gateways provide failover for availability. The management server can be a dedicated appliance, a virtual machine, or a hosted service depending on licence.

Day-to-day work runs through SmartConsole: editing the rule base, assigning IPS and Threat Prevention profiles, and installing policy. Software and signature updates arrive from the vendor and are applied on a schedule. IPS protection updates are frequent because new protections map to newly disclosed vulnerabilities.

Operationally, the team tracks which gateways run which policy version, which IPS profile is assigned to each gateway, and whether protections for current high-risk CVEs are set to Prevent. Change control matters because a policy install affects live traffic.

## Integrations and data flow

Check Point forwards logs to SIEM platforms over syslog or through dedicated log exporters, which supports detection and investigation workflows. Identity sources such as a directory service feed the identity awareness feature. Threat intelligence feeds, both vendor and third party, can supplement the built-in protections.

An API on the management server lets automation read and change policy, add objects, and install policy. This supports infrastructure-as-code patterns and ticket-driven firewall change automation. CloudGuard reads cloud provider APIs to discover assets and assess configuration posture.

Event data from SmartEvent supports the incident response process by giving responders a searchable record of what each gateway blocked or allowed.

## Adversary perspective

Check Point gateways enforce access, inspect traffic, and often terminate remote-access VPN, so adversaries treat them as appliances to compromise as much as policy to evade. The steps to lock the platform down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Edge and VPN exploitation: internet-facing gateways and their remote-access components are a standing target for this device class (ATT&CK T1190, Exploit Public-Facing Application).
- IPS set to Detect: a protection left in Detect logs a match and allows the traffic, so coverage is only apparent, and signatures can be evaded by encoding or fragmentation ([CWE-693](https://cwe.mitre.org/data/definitions/693.html)).
- Inspection gaps: traffic excluded from HTTPS inspection is not examined inside the session.
- Management and API abuse: the management server controls every gateway, so a stolen management credential or API key is high impact (ATT&CK T1685, Disable or Modify Tools).

### Residual risk and own exposure

The management plane compiles and pushes policy to every gateway, so its compromise is a high-impact event, and internet-facing gateways and VPN endpoints are among the most-targeted assets. A gateway only enforces the installed policy and only inspects what it decrypts. Software currency and the management plane belong in the patch and monitoring scope ([CWE-306](https://cwe.mitre.org/data/definitions/306.html)).

### Why it matters

For a tester, gateway exposure, VPN endpoints, and IPS profile actions are the first things to characterize. For a defender, confirming protections are set to Prevent, isolating the management server, and keeping software current are what make the control real. See [the red team reference](/RED_TEAM_REFERENCE.md) and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## Hardening and secure use

- Administrator role separation: grant each operator the least privilege needed. Policy editors, read-only reviewers, and full administrators should hold distinct roles so a single account cannot both change and approve policy.
- API key handling: the management API uses keys and credentials for automation. Do not embed these in scripts, pipelines, or repositories. Hardcoded credentials are a recognized weakness (CWE-798: Use of Hard-coded Credentials). Store them in a secret manager and rotate them.
- Management-plane isolation: restrict access to the management server and SmartConsole to a dedicated administrative network. The management plane controls every gateway, so exposure of it is a high-impact event.
- IPS profile verification: confirm that protections for relevant vulnerabilities are set to Prevent, not Detect. A profile left in Detect gives the appearance of coverage while allowing the traffic through.
- HTTPS inspection governance: decryption exposes session content, so scope it carefully and exclude categories where inspection is inappropriate. Protect the inspection keys.
- Logging assurance: verify that gateways actually forward logs and that SmartEvent is receiving them, so an investigation is not missing records.

## Where it fits in the program

Check Point is a network enforcement and virtual-patching control in the program. When a vulnerability is disclosed and a host patch cannot be applied immediately, a Check Point IPS protection set to Prevent can reduce exposure at the network boundary. This connects vulnerability management to a concrete compensating control.

The gateway logs feed detection and incident response. Access policy supports segmentation goals. CloudGuard posture findings feed cloud security review. The team should track IPS profile state as part of mitigation reporting, because a network virtual patch only counts when it is set to block.

## Resources

- Check Point Quantum Security Gateway Administration Guide
- Check Point IPS Administration Guide
- Check Point Threat Prevention Administration Guide
- Check Point SmartConsole documentation
- Check Point Management API Reference
- Check Point CloudGuard documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Fortinet](/platforms/fortinet.md)
- [Citrix NetScaler](/platforms/citrix-netscaler.md)
- [Zscaler](/platforms/zscaler.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Check Point entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=check-point) · [Check Point entries linked to CISA KEV](https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=check-point)

<!-- hub-links:end -->
