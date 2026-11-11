# Cisco Secure Access

Cisco Secure Access is Cisco's security service edge. It combines several cloud-delivered security functions behind one policy model and one client. It grew in part from the DNS-layer security that Cisco Umbrella provided.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network and cloud security engineers who run, tune or assess Cisco Secure Access

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,264 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Cisco Secure Access for security service edge, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md), [Zscaler](/platforms/zscaler.md), [Cisco ISE](/platforms/cisco-ise.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Cisco Secure Access is a cloud-delivered service that controls how users reach the internet and private applications. It brings together access brokering, web inspection, cloud application control, and DNS-layer filtering into a single service.

The goal is to replace a stack of separate appliances and point products with one cloud service. Policy references user identity and device posture rather than network location, which is the core of a zero-trust approach.

For a security operations and network team, the platform fills two roles:

- An enforcement layer for outbound and private-application traffic.
- A telemetry source covering access decisions, web inspection, and DNS activity.

Because DNS-layer filtering is part of the service, the platform can also give early visibility into where endpoints try to resolve names, which is useful well before a full web session is established.

## Architecture and how it works

Cisco Secure Access is cloud-delivered. Users connect through a unified client on the endpoint, which steers traffic to the service. Sites and data centers can also forward traffic through tunnels where a client is not practical.

Private applications are reached through connectors deployed near the application:

- The connector makes outbound connections to the cloud.
- The application is not published on the public network.
- Users reach it only through a brokered session after policy checks pass.

DNS-layer security intercepts name resolution and can block requests to known-bad or disallowed destinations before a connection is ever made. This is the lineage carried forward from Umbrella. Web traffic that proceeds is handled by the secure web gateway, which can decrypt and inspect sessions.

Policy decisions draw on identity from the identity provider, device posture, destination, and application. The cloud fabric applies these checks close to the user, so enforcement is consistent across office, remote, and roaming devices.

## Key capabilities

The platform groups several functions that once needed separate products:

- Zero-trust network access brokers connections to named private applications. It removes broad network reachability and grants access to specific applications after verifying identity and posture.
- The secure web gateway inspects web and internet-bound traffic. It applies URL filtering, content categories, and threat inspection, and it can decrypt encrypted sessions where policy allows.
- The cloud access security broker governs use of cloud applications. It can discover which applications are in use and apply controls to sanctioned and unsanctioned services.
- DNS-layer security filters at name resolution. It is a lightweight first line that blocks requests to disallowed or malicious destinations early.
- The cloud firewall applies network-layer policy to outbound traffic, including control over ports and protocols.

The unified client ties these functions together on the endpoint so a single agent handles steering, rather than stacking several agents that can conflict.

## Deployment and operations

Deployment typically begins with the unified client on managed endpoints and tunnel forwarding for sites. DNS-layer policy is often the first control enabled because it is simple to roll out and low-risk.

Private-application access requires connectors near each application. Operators keep connectors healthy and sized for the load they broker, and they monitor for connector outages that would break access.

Decryption for the secure web gateway needs a trusted certificate on endpoints. Operators maintain a list of destinations that are not decrypted, for privacy-sensitive or certificate-pinned services.

Policy is authored in the cloud console:

- Access rules reference identity groups and named application objects.
- Web rules reference destination categories and reputations.
- DNS rules block or allow resolution by category and threat data.

The licence tier decides which functions are in force, so operators confirm which capabilities the subscription includes before relying on them in a control or a detection.

## Integrations and data flow

The platform integrates with identity providers through `SAML` and `SCIM` so policy can reference real users and groups. Device posture can use signals from Cisco and third-party endpoint tools.

Logs flow to a SIEM for correlation with endpoint, identity, and network data. Access events, web inspection results, and DNS decisions give a security operations team a record of what each user and device attempted, which supports both detection and investigation.

APIs allow configuration, reporting, and log retrieval to be automated, which supports change review and integration with existing workflows and orchestration.

## Adversary perspective

Cisco Secure Access is an enforcement point for outbound and private-application traffic, so adversaries work to avoid being steered through it or to slip past its filters, and its connectors and admin console are themselves an attack surface. The steps to lock it down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Avoiding the steer (ATT&CK T1685): traffic from an endpoint where the unified client is disabled, removed, or never installed never reaches the service, so the policy is simply not applied.
- Filter and DNS evasion: encrypted DNS to an alternate resolver, domain fronting, fast-flux, and newly registered domains sidestep DNS and web categorization before a session is classified.
- Decryption gaps: destinations on the no-decrypt bypass list pass uninspected, so an attacker who reaches one moves data without content inspection.
- Over-broad allow rules and session theft (T1550): a wide allow rule or a stolen brokered session undermines the zero-trust intent and reaches private applications the attacker should not ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)).

### Residual risk and own exposure

The service filters and brokers but cannot see traffic that never transits it, and identity-aware policy is only as strong as the identity provider behind it. Connectors and the admin tenant are targets, and cloud-edge security services belong in the monitoring and change-control scope.

### Why it matters

A tester checks for un-steered paths, DNS and decryption bypasses, and over-broad rules; a defender alerts on client tamper, policy edits, and connector outages. See [the network protocols security reference](/NETWORK_PROTOCOLS_SECURITY.md) and [the red team reference](/RED_TEAM_REFERENCE.md).

## Hardening and secure use

- Use role-based access for administrators. Assign the smallest role that fits each person's duties and separate policy authoring from audit where possible.
- Protect API credentials and administrator secrets. Credentials embedded in scripts or stored in plain configuration are hardcoded credentials, which maps to `CWE-798` (Use of Hard-coded Credentials). Keep them in a secret manager and rotate them.
- Review policy for overly broad allow rules. A rule that permits a wide user group to reach a wide set of applications or destinations undermines zero trust. Scope rules to specific applications and groups, and record the reason for each exception.
- Audit the decryption bypass list so that encrypted traffic is not left uninspected without cause.
- Enforce strong authentication for the admin console and tie it to the identity provider.
- Monitor admin activity for unexpected changes, and alert on edits to access and decryption policy.

## Where it fits in the program

Cisco Secure Access is an enforcement point and a telemetry source. It narrows the attack surface by removing network reachability to private applications and by filtering outbound traffic at several layers, from DNS up through web content.

Its DNS, web, and access logs support detection and incident response by showing what a user or device tried to reach. The access decisions it records help an investigation reconstruct activity and scope a compromise. Because the service is identity-aware, its events tie network behavior to named users, which speeds triage.

## Resources

- Cisco Secure Access documentation
- Cisco Secure Access user guide
- Cisco Umbrella documentation
- Cisco Secure Client documentation
- Cisco Secure Access API reference

## Related pages

- [Security platforms](/platforms/README.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Zscaler](/platforms/zscaler.md)
- [Cisco ISE](/platforms/cisco-ise.md)
