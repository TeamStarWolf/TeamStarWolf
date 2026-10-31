# Cisco Secure Access

Cisco Secure Access is Cisco's security service edge. It combines several cloud-delivered security functions behind one policy model and one client. It grew in part from the DNS-layer security that Cisco Umbrella provided.

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

- /platforms/README.md
- /INCIDENT_RESPONSE_REFERENCE.md
- /SCANNER_PLATFORMS_REFERENCE.md
- /platforms/zscaler.md
- /platforms/cisco-ise.md
