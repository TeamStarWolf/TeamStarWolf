# Akamai

Akamai is a global edge platform that delivers and protects web applications and APIs from servers close to the user, and its security products run at that same edge: a web application and API firewall, bot management, distributed-denial-of-service protection, and microsegmentation. For a security program, the edge is where the fastest network-plane mitigation lives, because a rule can be enforcing within minutes across all traffic to a property. Products and tiers are described at a product level as generally available in 2026; what is in force depends on the subscription and the configuration.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network, application delivery and web security engineers who run, tune or assess Akamai

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (918 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Akamai for web application and API delivery and protection, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md), [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md), [Check Point](/platforms/check-point.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Traffic to a protected property is proxied through Akamai's edge network, so inspection and controls happen before requests reach the origin. App and API Protector provides the web application firewall and API protections, Bot Manager addresses automated abuse, Prolexic handles volumetric denial-of-service, and Guardicore Segmentation (from the Guardicore acquisition) provides host-based microsegmentation. This makes Akamai a network-plane control in front of the services covered by [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md) and [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).

## Architecture and how it works

A property is onboarded by pointing its hostname at the Akamai edge, usually through a CNAME, so requests resolve to edge servers that apply the configured security policy and then forward allowed traffic to the origin. Policies hold the firewall rules, rate controls, and bot and reputation settings. The firewall's adaptive security engine ships managed rule groups, and custom rules can be written as virtual patches for a specific vulnerability. Rapid Rules push protection for a newly published CVE quickly.

## Key capabilities

- A web application and API firewall with managed rule groups, rate controls, client reputation, and custom rules used as virtual patches.
- Rapid Rules to protect against a published CVE at the edge within minutes.
- API discovery and protection for the API attack surface.
- Bot Manager for automated-traffic abuse, and Account Protector for account-takeover defense.
- Prolexic distributed-denial-of-service protection.
- Guardicore Segmentation for host-based microsegmentation and lateral-movement containment.

## Deployment and operations

Deployment is onboarding properties and assigning a security policy, then tuning. A common pattern is to run a new rule in alert or count mode first to measure false positives, then promote it to deny once it is clean. Operationally, the work is policy tuning, reviewing security events, and writing or pushing rules when a CVE lands.

## Integrations and data flow

Security events stream to a SIEM through the Akamai SIEM connector, so edge detections and blocks land alongside the rest of the telemetry. The firewall also integrates with the vulnerability workflow as the place an emergency virtual-patch rule is written for an internet-facing CVE.

## Adversary perspective

Akamai is a network-plane control in the request path, so adversaries work to slip past its firewall or make it irrelevant, and the edge configuration and management API are themselves an attack surface. The steps to lock the platform down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Signature and normalization gaps: an encoded or fragmented payload, or a parsing difference between the edge and the origin, can read as benign to the managed rules yet execute at the application ([CWE-693](https://cwe.mitre.org/data/definitions/693.html)).
- Reaching the origin directly: if the origin accepts traffic from anywhere, an attacker who learns its address connects straight to it and the firewall, rate controls, and Prolexic never see the request.
- Body and size limits: inspection can skip or truncate very large bodies, so an attack in an oversized request passes.
- Logic and bot abuse: credential stuffing, scraping, and business-logic flaws look like valid traffic no signature matches.
- Disabling the control (ATT&CK T1685, Disable or Modify Tools): a stolen management credential can move a rule from deny back to alert or weaken a policy.

### Residual risk and own exposure

Internet-facing edge and delivery platforms are among the most-targeted assets, and this product class has a history of pre-authentication flaws exploited in the wild. The firewall also only sees traffic routed through it and only blocks what its rules express, so an alert-mode rule is not a control. The edge configuration and its API credentials belong in the patch and monitoring scope.

### Why it matters

For a tester, the edge is a filter to characterize and route around, not a wall. For a defender, it must be paired with a locked origin, rules confirmed in deny, and monitoring of configuration changes. See [the red team reference](/RED_TEAM_REFERENCE.md) and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## Hardening and secure use

The main control integrity concern is that the origin must not be reachable except through Akamai; an origin that accepts direct traffic bypasses every edge control. Lock the origin to Akamai edge addresses, protect the management API credentials in a secret store rather than hardcoding them (CWE-798), apply role-based access in the console, and verify that a firewall rule is actually in deny rather than alert before counting it as a control (treating alert mode as prevention is a common false-assurance gap).

## Where it fits in the program

Akamai is a network-plane preventive and corrective control. For an internet-facing web or API vulnerability it provides the fastest compensating control, a virtual-patch rule in minutes, while the code fix or vendor patch is prepared. It complements, rather than replaces, the scanners that find the vulnerability; see [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md).

## Resources

- The Akamai documentation (Akamai TechDocs), including App and API Protector, Bot Manager, Prolexic, and Guardicore Segmentation.

## Related pages

- [Security platforms](/platforms/README.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [API Security Reference](/API_SECURITY_REFERENCE.md)
- [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md)
- [Check Point](/platforms/check-point.md), [Citrix NetScaler](/platforms/citrix-netscaler.md), [Zscaler](/platforms/zscaler.md)
