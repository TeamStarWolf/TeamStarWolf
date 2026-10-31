# Cisco ISE

Cisco Identity Services Engine (ISE) is a network access control platform. It decides whether a device may join the network, what it may reach once admitted, and whether it should be quarantined. This page describes the product as generally available in 2026. The licence tier decides which features are in force.

## What it is and where it fits

Network access control governs admission to the network itself, at the switch port and the wireless connection, before a device reaches application services. Cisco ISE is the policy decision point for this. It authenticates devices and users, evaluates their state, and tells the network device what access to grant.

ISE sits between the directory and identity sources on one side and the network access devices, switches and wireless controllers, on the other. A switch or controller asks ISE whether to admit a connecting device, and ISE answers with an access decision: permit, deny, or a constrained access such as a guest or quarantine profile.

For a network and security team, ISE is where identity and device posture turn into enforced segmentation at the access layer. It is also a lever during incident response, because it can quarantine a device already on the network.

## Architecture and how it works

ISE deploys as a set of nodes with distinct roles. A policy administration node holds configuration. Policy service nodes make the live authentication and authorization decisions for network devices. Monitoring nodes collect logs and reporting data. In a distributed deployment these roles spread across several nodes for scale and availability.

A network access device, such as a switch, sends an authentication request to a policy service node. ISE evaluates the request against its policy set and returns an authorization result. That result can be a permit, a denial, a dynamic VLAN assignment, a downloadable ACL, or a security group tag.

Because ISE speaks to the network devices themselves, enforcement happens at the port and the wireless session, not at a later inspection point. A Change of Authorization message lets ISE change an active session after the fact, which is how a device already connected can be moved to quarantine.

## Key capabilities

- 802.1X access control: standards-based port authentication where the device or user presents credentials or a certificate before the port is opened.
- MAC Authentication Bypass: admission of devices that cannot do 802.1X, such as printers and some IoT devices, by their hardware address, usually with tighter authorization.
- Posture assessment: checking an endpoint's state, such as patch level or agent presence, and granting access according to the result.
- Endpoint profiling: identifying what a connecting device is, by its attributes, so policy can treat a phone differently from a laptop.
- TrustSec security group tags: assigning a tag to a session so downstream enforcement can permit or deny by group rather than by IP address.
- Downloadable ACLs: pushing an access control list to the switch port for a specific session.
- Change of Authorization: changing or terminating an active session, which is the mechanism behind quarantine.
- Adaptive Network Control: operator or automation-driven actions to quarantine, shut, or re-authenticate an endpoint.
- pxGrid context sharing: publishing session and identity context to partner platforms and consuming their input.

## Deployment and operations

ISE runs on dedicated appliances or virtual machines, deployed as policy administration, policy service, and monitoring nodes. Policy service nodes are placed near the network access devices they serve. Redundancy across nodes keeps authentication working if one node fails, which matters because a failed decision point can block legitimate access.

Operational work includes maintaining the policy sets, the identity source connections, and the certificates used for 802.1X and for the administrative interfaces. Certificate expiry is a common operational failure, because an expired certificate breaks authentication for every device that relies on it.

Monitoring nodes hold the live log of authentication and authorization decisions, which the team uses to troubleshoot why a device was admitted, denied, or quarantined.

## Integrations and data flow

ISE integrates with directory and identity sources to authenticate users and with certificate authorities for certificate-based access. pxGrid is the integration bus: partner platforms subscribe to session and identity context, and some can request actions such as quarantine.

ISE forwards logs to SIEM platforms, which supports detection and investigation. A SIEM or SOAR workflow can in turn drive an Adaptive Network Control action through the integration, so a detection can trigger a quarantine.

The data flow during an incident runs both ways: ISE publishes who and what is on the network, and it accepts an instruction to change a session for a device of concern.

## Hardening and secure use

- Administrator role-based access: use distinct administrative roles so operators hold only the privilege they need, and separate those who change policy from those who only read it.
- Certificate and credential handling: ISE relies on certificates for 802.1X and on credentials for identity-source and device connections. Do not hardcode credentials in scripts or integrations. Hardcoded credentials are a recognized weakness (CWE-798: Use of Hard-coded Credentials). Store them in a secret manager, protect private keys, and track certificate expiry.
- Quarantine coverage on both media: verify that quarantine and Change of Authorization policies apply on wired and wireless alike. A quarantine that works only on wired leaves a device free to reconnect over wireless, and the reverse is equally a gap.
- Fail-state behavior: decide and test what happens when a policy service node is unreachable, so a failure neither opens the network nor locks everyone out beyond intent.
- Management isolation: restrict administrative access to the ISE nodes to a dedicated administrative network.
- MAB scoping: because MAC Authentication Bypass trusts a spoofable hardware address, give MAB-admitted devices tightly scoped authorization rather than full access.

## Where it fits in the program

ISE is the access-layer enforcement and quarantine control in the program. It turns identity and posture into admission decisions, which supports network segmentation and a least-access posture. Its profiling data contributes to asset inventory by identifying what is actually connecting.

During incident response, ISE is the control that isolates a compromised endpoint through Change of Authorization and Adaptive Network Control. Posture assessment connects to vulnerability management by gating access on endpoint state. The team confirms that quarantine actually holds across wired and wireless before relying on it in a response plan.

## Resources

- Cisco Identity Services Engine Administrator Guide
- Cisco ISE Installation Guide
- Cisco TrustSec documentation
- Cisco pxGrid documentation
- Cisco ISE Posture documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Cisco Duo](/platforms/cisco-duo.md)
- [Cisco Secure Access](/platforms/cisco-secure-access.md)
- [Entra ID](/platforms/entra-id.md)
