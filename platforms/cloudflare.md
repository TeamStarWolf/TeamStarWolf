# Cloudflare

Cloudflare is a global edge and zero-trust platform. It sits in front of
internet-facing applications and proxies their traffic through its network. A
network and security team uses it for content delivery, for web application
protection, for denial-of-service defense, and for secure access through
Cloudflare One.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network, web and zero-trust security engineers who run, tune or assess Cloudflare

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,133 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Cloudflare for edge delivery, web protection and zero-trust access, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Akamai](/platforms/akamai.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Cloudflare runs a large network of points of presence close to users. Traffic to
a protected site passes through the nearest point before reaching the origin.
That position lets Cloudflare cache content, filter requests, and absorb attacks
before they reach the application.

The platform has two broad sides. The application-services side protects and
accelerates public websites and APIs. It includes content delivery, a web
application firewall, and distributed-denial-of-service protection. The zero-
trust side, Cloudflare One, secures how an organization's own users reach
internal and external resources.

For a security team, Cloudflare is an internet-facing control that fronts
exposed assets. It is also an access layer for the workforce. Both sides change
the real attack surface, so both belong in the asset inventory.

## Architecture and how it works

Cloudflare proxies traffic. When a domain uses Cloudflare, its DNS resolves to
Cloudflare addresses rather than to the origin. Requests land on a Cloudflare
point of presence, which inspects and processes them, then forwards allowed
requests to the origin.

Content delivery caches static and cacheable content at the edge. A user is
served from a nearby point instead of the origin, which lowers latency and
offloads the origin. Cache rules decide what is stored and for how long.

The web application firewall inspects HTTP requests against managed rule sets and
custom rules. It blocks common attack patterns such as injection and known
exploit traffic. Rate limiting and bot management reduce automated abuse. See
`/WEB_APPLICATION_SECURITY_REFERENCE.md` for the application-layer attack classes
these rules address.

Distributed-denial-of-service protection absorbs volumetric and application-layer
floods across the network. Because the edge is large and distributed, it can
soak up traffic that would overwhelm a single origin. Protection applies at the
network, transport, and application layers.

Cloudflare One is the zero-trust side. Zero Trust Access controls who can reach
an application and under what conditions. Gateway is a secure web gateway that
filters outbound DNS, HTTP, and network traffic from the organization's users.
Tunnels connect origins to Cloudflare without opening inbound ports.

## Key capabilities

- Content delivery and caching from a global edge network.
- Web application firewall with managed and custom rules.
- Distributed-denial-of-service protection across network and application layers.
- Rate limiting and bot management against automated abuse.
- DNS hosting and management for proxied domains.
- Zero Trust Access that gates application access by identity and device posture.
- Gateway secure web gateway for DNS, HTTP, and network filtering.
- Tunnels that reach origins without inbound firewall openings.

What is active depends on the plan and licence tier. Some firewall, bot, and
zero-trust features are available only on higher tiers. Confirm which features
the plan includes before relying on a protection.

## Deployment and operations

Fronting a site starts with DNS. The domain's authoritative DNS moves to
Cloudflare, and the records to proxy are set to pass through the edge. Records
can also be left unproxied, in which case Cloudflare serves DNS but does not
inspect traffic.

The zero-trust side deploys through a device client, through DNS settings, or
through tunnels from networks and origins. Policies for access and for Gateway
filtering are authored in the Cloudflare dashboard or through the API.

Operations center on rule authoring and on monitoring. A team tunes firewall
rules, cache behavior, rate limits, and access policies. As the vendor runs the
edge, the team does not patch edge infrastructure. It manages configuration,
client versions, and tunnel health.

A key operational risk is origin exposure. If an attacker learns the origin
address, they can connect to it directly and bypass the edge. Protecting the
origin is an ongoing operational task, not a one-time setup step.

## Integrations and data flow

Cloudflare emits logs and analytics for requests, firewall events, and zero-
trust activity. Log delivery can push these to storage or to a SIEM such as
Splunk for correlation and retention. See `/platforms/splunk.md` for the
analytics destination.

Zero Trust Access integrates with identity providers for authentication and with
endpoint signals for device posture. Access decisions combine who the user is
with the state of their device. Gateway integrates with the same identity layer
so filtering follows the user.

The Cloudflare API and infrastructure-as-code tooling expose configuration for
DNS, firewall rules, and zero-trust policy. Automation manages these resources
through tokens scoped to specific permissions. Workers and edge compute can run
custom logic at the edge.

Tunnels create outbound-only connections from origins to Cloudflare. This lets
private applications be reachable through Cloudflare One without inbound firewall
rules on the origin network.

## Hardening and secure use

Lock down the origin so the edge cannot be bypassed. Restrict the origin to
accept connections only from Cloudflare addresses, or use authenticated origin
pulls, or connect the origin by tunnel so it has no public inbound ports. An
origin reachable directly defeats the firewall and denial-of-service protection
in front of it.

Scope API tokens narrowly. A broad or leaked token can change DNS, disable the
firewall, or alter access policy, which maps to CWE-798, use of hard-coded
credentials. Create tokens with the least permission and the narrowest resource
scope, store them in a secret manager, and rotate them. Keep tokens out of
scripts and source control.

Verify that firewall rules deny rather than log. A rule left in log or monitor
mode records attacks without blocking them. Review managed rule set actions and
custom rule actions so that blocking rules actually block.

Protect the Cloudflare account itself. Use role-based administration, give each
member the least access needed, and require multi-factor authentication. The
account controls DNS and the security posture of every fronted site, so its
compromise is high impact.

Review DNS settings for records that are not proxied and for exposed origin
hints. An unproxied subdomain or a historical record can reveal the origin and
undo the edge protection.

## Where it fits in the program

Cloudflare is both an internet-facing control and an access layer. On the
application side, it protects and accelerates exposed sites and APIs and absorbs
denial-of-service attacks. On the zero-trust side, it governs how the workforce
reaches applications.

For the program, every fronted domain and every tunnel is an asset with its own
configuration risk. The firewall reduces web-application exposure, and Zero
Trust Access reduces the need to publish internal applications to the internet.
See `/INTERNET_FACING_SERVICES_REFERENCE.md` for exposure tracking.

## Resources

- Cloudflare Fundamentals documentation
- Cloudflare Web Application Firewall documentation
- Cloudflare DDoS Protection documentation
- Cloudflare One documentation
- Cloudflare Zero Trust documentation
- Cloudflare API documentation

## Related pages

- [Security platforms](/platforms/README.md)
- [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Akamai](/platforms/akamai.md)
- [Citrix NetScaler](/platforms/citrix-netscaler.md)
- [F5](/platforms/f5.md)

<!-- hub-links:start (written by scripts/build_hub_links.py from data/hub/tag_counts.json; do not edit) -->

On the Intelligence Hub: [Cloudflare entries](https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=cloudflare) · [Cloudflare entries linked to CISA KEV](https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=cloudflare)

<!-- hub-links:end -->
