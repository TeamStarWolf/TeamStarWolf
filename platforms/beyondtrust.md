# BeyondTrust

BeyondTrust is a privileged access management platform. It vaults and rotates
privileged credentials, controls vendor and administrator sessions, and removes
standing local administrator rights from endpoints.

## What it is and where it fits

Privileged accounts, the administrator and service accounts that can change systems,
are among the most valuable targets in any environment. BeyondTrust exists to shrink
that risk by controlling how those accounts are stored, used, and watched.

The platform covers three main problems:

- Where privileged credentials live and how often they change. Password Safe vaults
  and rotates them.
- How administrators and outside vendors reach systems. Privileged Remote Access
  brokers and records those sessions.
- Whether users carry local administrator rights at all. Endpoint Privilege Management
  removes those rights and grants elevation per action.

For an identity and security team, BeyondTrust is the layer that keeps privileged
access out of standing, shared, or hardcoded form and puts it behind a vault and a
policy.

## Architecture and how it works

Password Safe stores privileged credentials in an encrypted vault. It discovers
privileged and service accounts, brings them under management, and rotates their
passwords and keys on a schedule or after each use. Access is requested, approved
where required, and granted for a limited window. Users can retrieve a credential or
be injected into a session without ever seeing the password.

Privileged Remote Access brokers sessions for administrators and third-party vendors.
Rather than giving a vendor a VPN and a standing account, the platform grants a scoped,
time-bound session that routes through the broker. Sessions can be monitored in real
time and recorded for later review, and credentials can be injected so the vendor never
holds them.

Endpoint Privilege Management runs an agent on Windows, macOS, and Linux endpoints. It
removes local administrator membership from day-to-day accounts and instead grants
elevation to specific applications or actions under policy. This cuts the blast radius of a
compromised user account, because the account no longer carries full local admin.

These components share policy and feed activity records to a central point, so that
credential use, session activity, and elevation events can be reviewed together.

## Key capabilities

- Credential vaulting and rotation through Password Safe, including discovery of
  privileged and service accounts.
- Session brokering for administrators and vendors through Privileged Remote Access,
  with monitoring and recording.
- Credential injection, so a user or vendor runs a session without seeing the
  underlying password.
- Endpoint privilege management, removing local administrator rights and granting
  per-application elevation.
- Approval workflows and time-bound checkout for privileged credentials and sessions.
- Session recording and keystroke logging for audit and investigation.
- Reporting on privileged activity across credentials, sessions, and endpoints.

## Deployment and operations

BeyondTrust is available as a self-hosted appliance and as a cloud-delivered service.
The choice affects who patches the platform, but the operational practices are
similar.

Operational work includes:

- Onboarding accounts into Password Safe and setting rotation policy per account type.
- Configuring session brokering and recording for administrators and vendors.
- Deploying the Endpoint Privilege Management agent and writing elevation policy.
- Managing approver groups and reviewing checkout and session logs.

Break-glass access needs planning. There must be a tested way to reach critical
credentials if the platform itself is unavailable, and that path must be tightly
controlled and logged. Rotation policy should be tested against a pilot set of accounts
before wide rollout, since aggressive rotation can break service accounts that are
hardcoded elsewhere. Those hardcoded uses should be found and moved to the vault.

For self-hosted deployments, the appliance is software and needs patching and backup
on its own schedule.

## Integrations and data flow

- Credential retrieval. Applications and scripts fetch secrets from Password Safe
  through its API, so credentials are pulled at run time rather than stored in files.
- Session routing. Privileged Remote Access sits between the user or vendor and the
  target, injecting credentials and recording the session.
- Directory and identity. The platform integrates with the enterprise directory and
  with an identity provider for authentication and MFA on the access path.
- Endpoint policy. The Endpoint Privilege Management agent reports elevation events to
  the platform.
- Logging. Session recordings and privileged activity events can stream to a SIEM for
  correlation and alerting.

Keep the data minimal and the paths authenticated. Credential retrieval should require
a scoped, authenticated request, not an open endpoint.

## Hardening and secure use

- Harden the vault. Restrict network access to Password Safe, require strong
  authentication and MFA for access, and keep encryption and backup keys protected.
  The vault is the crown jewels and must be treated that way.
- Enforce least privilege. Remove standing local administrator rights with Endpoint
  Privilege Management and grant elevation per action. Leaving broad standing rights is
  weak authorization (CWE-862).
- Move credentials into the vault. Replace passwords hardcoded in scripts,
  configuration files, and service definitions with run-time retrieval from Password
  Safe. Hardcoded credentials map to CWE-798.
- Monitor and record sessions. Record administrator and vendor sessions and review
  them, so misuse of a privileged session can be detected and reconstructed.
- Require approval and time limits. Use checkout windows and approval workflows for
  high-risk credentials and sessions rather than standing access.
- Protect and test break-glass. Keep the emergency path controlled, logged, and
  exercised, so it works when needed and cannot be abused quietly.
- Patch self-hosted appliances and keep the Endpoint Privilege Management agents
  current.

## Where it fits in the program

BeyondTrust is the privileged access layer. It is where an identity and security team
removes standing admin rights, vaults and rotates privileged credentials, and controls
how administrators and vendors reach systems.

For vulnerability management, hardcoded credentials, over-privileged local accounts,
and unmanaged privileged accounts are findings that BeyondTrust is meant to close.
Discovery in Password Safe surfaces privileged and service accounts that were not under
management. For incident response, session recordings and privileged activity logs are
primary evidence for how a privileged account was used during an event.

The platform complements an identity provider, which handles authentication and MFA on
the access path, and feeds the SIEM with privileged activity for correlation.

## Resources

- BeyondTrust Password Safe documentation
- BeyondTrust Privileged Remote Access documentation
- BeyondTrust Endpoint Privilege Management documentation
- BeyondTrust product support portal

## Related pages

- [Platforms index](/platforms/README.md)
- [Identity security reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [CyberArk](/platforms/cyberark.md)
- [Delinea](/platforms/delinea.md)
