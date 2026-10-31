# Netskope

Netskope is a security service edge vendor. Netskope One delivers web, cloud,
and private-access security from the cloud with inline inspection. A network and
security team uses it to control how users reach the internet, software-as-a-
service applications, and private resources.

## What it is and where it fits

Netskope One is a cloud-delivered platform that sits between users and the
destinations they reach. It inspects traffic inline and applies policy before
the connection completes. The platform combines several controls that were once
separate products.

It covers four core functions. A secure web gateway controls general web
traffic. A cloud access security broker governs use of SaaS and cloud
applications. Zero-trust network access connects users to private applications
without a flat network. Data loss prevention watches for sensitive data moving
where it should not.

For a security team, Netskope replaces or supplements on-premises web proxies
and VPN concentrators. Users route traffic to the Netskope cloud regardless of
location. Policy follows the user rather than the office.

## Architecture and how it works

Traffic reaches Netskope through a client, through proxy configuration, or
through tunnels from network devices. The platform terminates and inspects the
session in its cloud, then forwards allowed traffic to the destination. This
inline position is what lets it enforce policy in real time.

The secure web gateway inspects web and general internet traffic. It applies URL
filtering, threat scanning, and content controls. The cloud access security
broker understands specific SaaS applications and their actions. It can allow
reading a file while blocking uploading one, for example.

Zero-trust network access brokers connections to private applications. A user is
granted access to a named application, not to a network segment. The application
stays hidden from users who have no policy for it. This narrows what a
compromised account or device can reach.

Data loss prevention runs across these channels. It inspects content against
rules for patterns, file types, and classifications. A match can block, alert,
or quarantine depending on policy. Inspection depends on decrypting traffic,
which the platform does under policy you define.

Visibility comes from the platform understanding applications and instances. It
can tell a corporate instance of a SaaS application from a personal one and apply
different policy to each.

## Key capabilities

- Secure web gateway for URL filtering, threat scanning, and content control.
- Cloud access security broker with per-application and per-action policy.
- Zero-trust network access to private applications by name, not by network.
- Data loss prevention across web, cloud, and private-access channels.
- Inline SSL inspection so encrypted traffic can be examined under policy.
- Application and instance awareness that separates corporate from personal use.
- Threat protection including malware scanning and sandboxing of files.
- Reporting and analytics on user activity and policy matches.

What is active depends on the licence tier. Secure web gateway, cloud access
security broker, zero-trust network access, and data loss prevention are
licensed features. Confirm which are enabled before relying on a control.

## Deployment and operations

Users connect through the Netskope client installed on endpoints. Branch sites
and networks can steer traffic through tunnels such as IPsec or GRE. Mobile and
unmanaged scenarios use proxy settings or agentless reverse-proxy methods.

Operations center on policy authoring and tuning. A team builds rules for web
categories, for application actions, and for data patterns. New SaaS
applications appear constantly, so the application catalog and policy need
regular review.

SSL inspection is a core operational decision. Without it, much traffic cannot
be examined, since most web traffic is encrypted. Inspection needs a trusted
certificate on endpoints and a policy that respects privacy and compliance
exclusions.

Because Netskope is cloud-delivered, the team does not patch inspection
infrastructure. The vendor runs the service. The team manages client versions,
steering configuration, and policy. Client health and connectivity become the
operational focus.

## Integrations and data flow

Netskope integrates with identity providers to authenticate users and read group
membership. Policy references those groups so access follows identity. Single
sign-on and multi-factor authentication front the service through the identity
provider.

The platform exports logs and events for activity, threats, and data-loss
matches. These forward to a SIEM such as Splunk for correlation and retention.
See `/platforms/splunk.md` for the analytics destination.

REST APIs expose configuration, events, and administrative actions. Automation
reads events and pushes policy through these interfaces. Integrations with
endpoint and cloud-security tools share threat signals and context.

Data loss prevention can integrate with external classification and key-
management systems. Threat intelligence feeds inform blocking decisions. Private-
access publishers connect the zero-trust service to the networks where private
applications live.

## Hardening and secure use

Use role-based administration. Scope each administrator to the functions and
tenants the role needs. Avoid broad administrative rights for routine work.
Require multi-factor authentication for every administrative login.

Protect API credentials and tokens. A tenant API token that leaks gives an
attacker read and write access to policy and data, which maps to CWE-798, use of
hard-coded credentials. Store tokens in a secret manager, scope them to the least
access needed, and rotate them. Keep them out of scripts and source control.

Review SSL-inspection coverage and exclusions. Traffic that bypasses inspection
is not examined, so a broad exclusion can silently defeat a control. Keep
exclusion lists small, documented, and reviewed. Balance inspection against
privacy and legal requirements.

Review policy regularly. Confirm that deny and block rules block rather than
only log. Check the default action for uncategorized applications and new SaaS
instances. A permissive default undercuts specific rules above it.

Protect the enrollment and steering path. Ensure the client cannot be disabled
by a standard user, and that traffic cannot easily be routed around the service.
Bypass is a common way controls are defeated.

## Where it fits in the program

Netskope is the enforcement and visibility layer for how users reach external
and private destinations. It controls web access, governs cloud application use,
brokers private access, and watches for data loss. It centralizes policy that
once lived in proxies, VPNs, and separate data-loss tools.

For the program, Netskope produces user-activity and data-movement telemetry
that feeds monitoring and investigation. It also reduces the attack surface by
hiding private applications behind per-user grants. See
`/INTERNET_FACING_SERVICES_REFERENCE.md` for how exposure is tracked and
`/WEB_APPLICATION_SECURITY_REFERENCE.md` for application-layer concerns.

## Resources

- Netskope One Platform documentation
- Netskope Secure Web Gateway Administration documentation
- Netskope CASB documentation
- Netskope Zero Trust Network Access documentation
- Netskope Data Loss Prevention documentation
- Netskope REST API documentation

## Related pages

- /platforms/README.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /INTERNET_FACING_SERVICES_REFERENCE.md
- /WEB_APPLICATION_SECURITY_REFERENCE.md
- /platforms/zscaler.md
- /platforms/cisco-secure-access.md
- /platforms/forcepoint.md
