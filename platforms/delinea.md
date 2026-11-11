# Delinea

Delinea is a privileged access management platform formed from the combination of
Thycotic and Centrify. It vaults and rotates secrets, manages endpoint privilege, and
offers cloud-delivered privileged access controls.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Identity and privileged access engineers who run, tune or assess Delinea

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,256 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Delinea for privileged access management, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [BeyondTrust](/platforms/beyondtrust.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Delinea addresses the same core risk as other privileged access platforms: the
administrator, service, and application accounts that can change systems are prime
targets, and they tend to sprawl into shared passwords, hardcoded secrets, and standing
admin rights.

The platform brings together lineage from two vendors:

- Secret Server, from the Thycotic side, is the secrets vault with discovery, storage,
  and rotation.
- Privilege Manager handles endpoint privilege, removing local administrator rights and
  granting elevation under policy.
- Cloud PAM delivers privileged access controls as a service, including capability from
  the Centrify side such as privileged access to servers and infrastructure.

For an identity and security team, Delinea is the layer that keeps privileged
credentials in a vault and off endpoints, scripts, and shared notes.

## Architecture and how it works

Secret Server is the center of the platform. It stores secrets, passwords, keys, API
tokens, and other credentials, in an encrypted vault. It discovers privileged and
service accounts across the environment, brings them under management, and rotates
their credentials on a schedule or after each use. Access is requested and, where
policy requires, approved, then granted for a limited window. Credentials can be
injected into a session or launcher so a user never sees the raw value.

Privilege Manager runs an agent on endpoints. It removes standing local administrator
membership and applies policy that raises rights for specific applications or actions.
Allow, deny, and elevation rules let known-good software run with the rights it needs while the
user account stays non-privileged. This reduces what a compromised endpoint account can
do.

Cloud PAM extends these controls as a service. It brokers privileged access to servers
and infrastructure, applies policy centrally, and records activity, which suits
environments that prefer a vendor-run control plane or that span cloud and
on-premises systems.

The components share policy and send activity records to a central point, so secret
use, elevation, and session activity can be reviewed together.

## Key capabilities

- Secrets vaulting and rotation through Secret Server, with discovery of privileged and
  service accounts.
- Session launching and credential injection, so credentials are used without being
  shown to the user.
- Endpoint privilege management through Privilege Manager, removing local admin rights
  and applying application control policy.
- Cloud-delivered privileged access to servers and infrastructure through Cloud PAM.
- Approval workflows and time-bound checkout for high-risk secrets.
- Session recording and auditing of privileged activity.
- An API for programmatic secret retrieval so applications fetch credentials at run
  time.

## Deployment and operations

Delinea is available as self-hosted software and as cloud-delivered services. Secret
Server can run on-premises or in Delinea's cloud, and Privilege Manager pairs with
either.

Operational work includes:

- Onboarding secrets and accounts into Secret Server and setting rotation policy per
  type.
- Deploying the Privilege Manager agent and writing allow, deny, and elevation policy.
- Configuring approval workflows and reviewing checkout and session logs.
- Managing the vault's encryption keys, backups, and, for self-hosted, patching.

Break-glass procedures need planning and testing. There must be a controlled, logged
way to reach critical secrets if the platform is unavailable, and it must resist
casual abuse. Rotation should be piloted before wide rollout, because rotating a
password that is hardcoded in a script or service elsewhere will break that caller. The
goal is to find those hardcoded uses and move them to the vault, retrieved at run time.

## Integrations and data flow

- Secret retrieval. Applications and scripts fetch secrets from Secret Server through
  its API at run time, rather than holding them in files or source.
- Session launching. Launchers and injectors pass credentials into a target session so
  the raw secret is not exposed to the user.
- Directory and identity. The platform integrates with the enterprise directory and an
  identity provider for authentication and MFA on the access path.
- Endpoint policy. Privilege Manager reports elevation and application-control events
  to the platform.
- Logging. Session recordings and privileged activity events can stream to a SIEM for
  correlation and alerting.

Authenticate and scope every retrieval path, and send only the secret a caller needs.

## Adversary perspective

Delinea vaults privileged secrets and brokers privileged access, so an adversary who reaches Secret Server or a launched session inherits broad privilege; the vault is the most sensitive target in the environment. The steps to lock it down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Vault and secret targeting (ATT&CK T1555, Credentials from Password Stores): compromising Secret Server or a stored secret, key, or token yields privileged access across the systems it manages.
- Session-launcher and API abuse (T1078, T1528): a stolen operator session or an over-scoped secret-retrieval API client lets an attacker fetch credentials as a legitimate application would ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).
- Endpoint-elevation bypass: a Privilege Manager allow rule that is too broad, or an application-control gap, lets an attacker gain local elevation the policy was meant to deny.
- Un-vaulted and hardcoded secrets ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): secrets still embedded in scripts and services sit outside the vault and are discovered and reused directly, and aggressive rotation that breaks them signals where they hide.

### Residual risk and own exposure

The vault reduces standing privilege but cannot protect secrets it never onboarded, and its own compromise is catastrophic. Self-hosted Secret Server instances, the Privilege Manager agents, and the encryption and backup keys belong in the patch, backup, and monitoring scope as the environment's most sensitive software.

### Why it matters

A tester hunts for un-vaulted secrets, over-broad elevation rules, and direct retrieval paths; a defender alerts on vault access, failed checkouts, and agent and instance patch state. See [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) and [the red team reference](/RED_TEAM_REFERENCE.md).

## Hardening and secure use

- Harden the vault. Restrict network access to Secret Server, require strong
  authentication and MFA for access, and protect the encryption and backup keys. The
  vault holds the most sensitive credentials and must be defended accordingly.
- Enforce least privilege. Use Privilege Manager to remove standing local administrator
  rights and grant elevation per application. Leaving broad standing rights is weak
  authorization (CWE-862).
- Move application secrets into the vault. Replace passwords, keys, and tokens
  hardcoded in scripts, configuration, and services with run-time retrieval from Secret
  Server. Hardcoded credentials map to CWE-798.
- Plan and test break-glass. Keep the emergency access path controlled, logged, and
  exercised, so it works under pressure and cannot be used quietly.
- Require approval and time limits for high-risk secrets rather than standing access,
  and rotate after each use where feasible.
- Record and review privileged sessions, so misuse can be detected and reconstructed.
- Patch self-hosted Secret Server instances and keep Privilege Manager agents current.

## Where it fits in the program

Delinea is the privileged access layer. It is where an identity and security team
vaults and rotates privileged secrets, removes standing local admin rights, and brokers
privileged access to servers and infrastructure.

For vulnerability management, hardcoded credentials, unmanaged privileged accounts, and
over-privileged local accounts are the findings this platform is meant to close, and
Secret Server discovery surfaces accounts that were not under management. For incident
response, session recordings and privileged activity logs are primary evidence for how
a privileged account or secret was used during an event.

Delinea complements an identity provider, which handles authentication and MFA, and
feeds the SIEM with privileged activity for correlation.

## Resources

- Delinea Secret Server documentation
- Delinea Privilege Manager documentation
- Delinea Platform documentation
- Delinea support portal

## Related pages

- [Platforms index](/platforms/README.md)
- [Identity security reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [BeyondTrust](/platforms/beyondtrust.md)
- [CyberArk](/platforms/cyberark.md)
