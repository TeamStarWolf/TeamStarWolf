# CyberArk

CyberArk is a privileged access management platform. It vaults and rotates privileged credentials, isolates and records privileged sessions, removes local administrator rights from endpoints, and supplies secrets to applications. Its goal is to reduce standing privilege.

## What it is and where it fits

Privileged accounts hold the keys to infrastructure, directories, databases, and cloud control planes. CyberArk governs those accounts. It stores their credentials in a vault, brokers access to them, and records how they are used.

For an identity and security team, CyberArk is the control point for the most dangerous accounts. It replaces shared passwords and standing administrator rights with checked-out, rotated, and recorded access. It supports the principle that privilege should be requested and time-bound.

A licence tier and module set decide which capabilities are in force. Session management, endpoint privilege, and secrets management are distinct components. Confirm which are deployed before assuming a control is present.

## Architecture and how it works

The Digital Vault stores credentials in an encrypted, hardened store. The Central Policy Manager rotates those credentials on a schedule and after each use, so a password that leaks has a short useful life.

The Privileged Session Manager brokers connections to target systems. A user connects through it rather than holding the credential directly. The session is isolated from the user's workstation and can be recorded for later review.

Endpoint Privilege Manager runs on workstations and servers. It removes local administrator membership and elevates specific actions under policy instead. Conjur provides secrets to applications and pipelines through an API, so code requests a secret at runtime rather than storing it.

## Key capabilities

- The Digital Vault and Central Policy Manager for credential vaulting and scheduled rotation.
- Privileged Session Manager for session isolation, brokered connections, and session recording.
- Endpoint Privilege Manager for removing local administrator rights and elevating by policy.
- Secrets management through Conjur for applications, pipelines, and containers.
- Just-in-time elevation that grants privilege for a bounded window with zero standing privilege as the target.
- Audit records of credential checkout and session activity.

## Deployment and operations

CyberArk is deployed as a set of components around the vault. The vault is hardened and tightly restricted. Policy managers, session managers, and connectors are placed to reach the target systems they serve.

Onboarding is incremental. The most sensitive accounts, domain administrators, root, cloud root, are vaulted first, then the scope widens. Each account type gets a rotation policy and an access policy.

Operations teams monitor vault access, failed checkouts, and session recordings. They test break-glass procedures so a vault outage does not block emergency access. Component patching and vault backup are scheduled and verified.

## Integrations and data flow

CyberArk connects to target systems through connectors: Windows and Linux hosts, directories, databases, network devices, and cloud providers. It rotates and brokers the privileged accounts on each.

Applications retrieve secrets from Conjur or the vault through an API at runtime. This removes credentials from source code and configuration files. Pipelines and containers request short-lived secrets the same way.

Audit events, credential checkouts, session starts, elevation decisions, flow to monitoring and SIEM platforms. See `/platforms/splunk.md` for a downstream consumer. Session recordings support investigation during incident response.

## Hardening and secure use

Harden the vault itself. It is the single most valuable target in the environment. Follow the vendor hardening guidance, restrict network reachability, and limit who can administer it.

Apply least privilege to the platform's own roles. Vault administrators, auditors, and account owners should be separate so no single operator holds unchecked control.

Define and test break-glass procedures. When the vault is unreachable, a documented and access-controlled emergency path must exist, and its use must be alerted on and reviewed afterward.

Deliver application secrets through the vault rather than hardcoding them. Credentials embedded in code or configuration map to CWE-798 Use of Hard-coded Credentials. Applications should request secrets at runtime and never persist them to disk or source control.

## Where it fits in the program

CyberArk shrinks the standing privilege an attacker can inherit from a compromised account. Rotated credentials and brokered sessions mean a stolen password is short-lived and a lateral move is recorded.

Its session recordings and checkout logs are primary evidence during incident response. The attestation it produces, who holds which privileged access and when they used it, supports audit and governance requirements.

## Resources

- CyberArk documentation
- CyberArk Privileged Access Manager documentation
- CyberArk Endpoint Privilege Manager documentation
- CyberArk Conjur documentation

## Related pages

- `/platforms/README.md`
- `/VULNERABILITY_MANAGEMENT_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/SECURE_CODING_REFERENCE.md`
- `/platforms/entra-id.md`
- `/platforms/sailpoint.md`
