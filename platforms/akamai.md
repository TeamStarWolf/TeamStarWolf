# Akamai

Akamai is a global edge platform that delivers and protects web applications and APIs from servers close to the user, and its security products run at that same edge: a web application and API firewall, bot management, distributed-denial-of-service protection, and microsegmentation. For a security program, the edge is where the fastest network-plane mitigation lives, because a rule can be enforcing within minutes across all traffic to a property. Products and tiers are described at a product level as generally available in 2026; what is in force depends on the subscription and the configuration.

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
