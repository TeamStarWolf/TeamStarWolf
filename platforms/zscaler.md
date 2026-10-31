# Zscaler

Zscaler delivers security as a cloud service that sits between users and the destinations they reach. The platform is branded the Zscaler Zero Trust Exchange. It inspects traffic inline in the cloud rather than on appliances at each site.

## What it is and where it fits

Zscaler is a cloud security service edge. It moves the inspection and access-control functions that once lived in branch firewalls and web proxies into a shared cloud fabric. Users connect to the nearest Zscaler data center, and policy follows the user and the device instead of the network location.

The Zero Trust Exchange is the name for the combined service. It groups several products that address different flows. Each product applies policy before traffic reaches its destination, so there is no implicit trust based on being inside a corporate network.

For a security operations and network team, Zscaler plays two roles:

- An enforcement point that decides which destinations a user or device may reach.
- A telemetry source that records what was allowed, blocked, inspected, or sandboxed.

The split matters. The same deployment that reduces the attack surface also produces the logs a detection and response team relies on. Treating Zscaler only as a gateway, and ignoring its telemetry, leaves value on the table.

## Architecture and how it works

Traffic is forwarded to the Zscaler cloud for inspection. The main forwarding methods are:

- The Zscaler Client Connector, an endpoint agent that steers traffic to the service.
- Tunnels such as `GRE` or `IPSec` from a site router or firewall.
- Proxy configuration, including `PAC` files, that points browsers and systems at the service.

Once traffic reaches a Zscaler data center, the service applies policy. For encrypted sessions, SSL inspection decrypts the traffic, inspects the content, and re-encrypts it before forwarding. Policy decisions use user identity, device posture, destination, and content category.

Private applications are reached through a different path. Lightweight software connectors, called App Connectors, sit next to the application and establish outbound connections to the cloud. The application is never exposed to the public network. The user reaches it only through the brokered session, and only after identity and posture checks pass.

The cloud fabric is distributed across many data centers. This keeps inspection close to the user and avoids backhauling traffic to a central location. Because enforcement is in the cloud, policy is consistent whether the user is in an office, at home, or traveling.

## Key capabilities

Zscaler Internet Access is the secure web gateway. It covers outbound internet traffic and provides:

- Inline inspection of web and internet-bound traffic.
- A cloud firewall for network-layer control over ports and protocols.
- URL and content filtering by category and reputation.
- A sandbox that detonates suspicious files in isolation before delivery.

It applies this policy regardless of where the user sits, so a laptop off the corporate network is inspected the same way as one inside it.

Zscaler Private Access provides zero-trust network access. It removes network reachability to internal applications:

- Users are brokered to a named application, not placed on a network segment.
- Applications stay dark to anyone without an authorized session.
- Access is granted after identity and device-posture checks.

Zscaler Digital Experience monitors the path between the user and the application. It measures latency, loss, and performance across the device, network, and application. This helps a team separate a security block from a performance fault during triage.

Deception plants decoy assets and credentials. When an attacker interacts with a decoy, the activity is high-signal, because legitimate users have no reason to touch it. These signals can feed detection workflows.

## Deployment and operations

Deployment starts with traffic forwarding. Most teams roll out the Zscaler Client Connector to managed endpoints and configure forwarding profiles that decide which traffic goes to the cloud. Branch and data-center forwarding uses tunnels or proxy settings.

SSL inspection requires a trusted certificate on endpoints so the service can decrypt and re-inspect sessions. Operators maintain a bypass list for destinations that must not be decrypted, such as certain banking or health endpoints, and for applications that pin certificates.

Policy is authored in the admin console:

- Internet Access rules reference user groups, destination categories, and device posture.
- Private Access rules name the specific applications a group may reach.
- Firewall rules control ports and protocols for non-web traffic.

Day-to-day operations include reviewing blocked and allowed traffic, tuning categories, keeping App Connectors healthy, and watching for forwarding gaps where traffic escapes inspection. The licence tier decides which products and inspection features are in force, so operators confirm what the subscription includes rather than assuming a capability is active.

## Integrations and data flow

Zscaler integrates with identity providers through `SAML` and `SCIM` so that policy can reference real user and group identity. Device posture can draw on signals from endpoint tools to gate access.

Logging to a SIEM uses the Nanolog Streaming Service. This streams web, firewall, and access logs from the Zscaler cloud to a collector, which forwards them to the SIEM. The stream lets a security operations team correlate Zscaler events with endpoint and identity data, and build detections on blocked destinations, sandbox verdicts, and anomalous access.

APIs allow configuration and reporting to be automated. Administrators can pull policy, read logs, and manage objects programmatically, which supports version control and change review.

## Hardening and secure use

- Restrict administrative access with role-based administration. Give each administrator the narrowest role that fits the job, and separate policy authors from auditors where the tier allows.
- Protect API keys and administrator credentials. API keys embedded in scripts or configuration are a form of hardcoded credential, which maps to `CWE-798` (Use of Hard-coded Credentials). Store them in a secret manager and rotate them on a schedule.
- Review the SSL inspection policy and the bypass list regularly. An overly broad bypass list leaves encrypted traffic uninspected, which defeats the purpose of the gateway. Each bypass entry should have a recorded reason.
- Audit Private Access policy for scope. A rule that grants a broad application group to a broad user group recreates the flat network that zero trust is meant to remove. Name applications narrowly.
- Enforce strong authentication for the admin console and tie it to the identity provider.
- Monitor admin activity logs for unexpected policy changes, and alert on changes to inspection and bypass rules.

## Where it fits in the program

Zscaler is a control point that shapes what users and devices can reach, and a telemetry source that feeds detection. For a network and security operations team, it reduces the attack surface by removing network reachability to private applications and by inspecting outbound traffic inline.

Its logs support incident response by showing what a compromised account or device attempted to reach. Its sandbox and category data support threat detection. The access decisions it records help an investigation reconstruct user activity and scope a compromise. Because enforcement is identity-aware, Zscaler data ties network events back to specific users, which shortens investigations.

## Resources

- Zscaler Help Portal
- Zscaler Internet Access Administration documentation
- Zscaler Private Access Administration documentation
- Nanolog Streaming Service documentation
- Zscaler API reference

## Related pages

- /platforms/README.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /INCIDENT_RESPONSE_REFERENCE.md
- /platforms/cisco-secure-access.md
- /platforms/forcepoint.md
