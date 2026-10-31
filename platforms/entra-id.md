# Microsoft Entra ID

Microsoft Entra ID is a cloud identity and access management service. It was formerly named Azure Active Directory. It authenticates users and services, issues tokens, and applies access policy for cloud and on-premises applications.

## What it is and where it fits

Entra ID is the identity provider for Microsoft 365 and for applications that federate to it. It holds user accounts, groups, service principals, and application registrations. It sits in front of resources and decides who signs in, under what conditions, and with which roles.

For an identity and security team, Entra ID is the control point for authentication and authorization. Sign-in policy, multi-factor requirements, and privileged role assignment are all expressed here. Its sign-in and audit logs are a primary source for identity monitoring.

A licence tier decides which features are in force. Conditional Access, Identity Protection, and Privileged Identity Management require higher tiers. Confirm the tier before assuming a control is available.

## Architecture and how it works

Entra ID is a multi-tenant directory. Each tenant is an isolated instance with its own users, groups, and application objects. Applications trust the tenant as an identity provider and redirect users to it for sign-in.

Authentication uses industry protocols. Web and mobile applications use OpenID Connect and OAuth 2.0. Older enterprise applications use SAML. After a user authenticates, Entra ID issues signed tokens that the application validates.

Policy is evaluated at sign-in. Conditional Access reads signals such as user, group, device state, location, and risk level. It then grants, blocks, or requires an extra control such as multi-factor authentication. Directory synchronization can import accounts from on-premises Active Directory.

## Key capabilities

- Single sign-on so a user authenticates once and reaches many applications without re-entering credentials.
- Conditional Access, which evaluates sign-in signals and enforces grant, block, or step-up decisions.
- Multi-factor authentication through authenticator app, passkeys, FIDO2 security keys, and other factors.
- Privileged Identity Management for just-in-time activation of privileged roles with approval and time limits.
- Identity Protection risk policies that act on risky users and risky sign-ins.
- Access reviews that ask owners to confirm whether members still need their access.
- Controls to block legacy authentication protocols that cannot carry a second factor.

## Deployment and operations

Entra ID is delivered as a service, so there is no server to install. Operational work is configuration, policy design, and monitoring. Directory synchronization is set up when on-premises accounts must appear in the tenant.

Policy should move through rings. A new Conditional Access policy starts in report-only mode, is measured against sign-in logs, and is then enforced once the effect is understood. Exclusions are documented and reviewed.

Operations teams watch sign-in logs, audit logs, and Identity Protection detections. They forward these logs to a monitoring platform for correlation. Emergency-access accounts are tested on a schedule so they work when normal sign-in paths fail.

## Integrations and data flow

Applications integrate through SAML and OpenID Connect, either from the application gallery or through custom registration. Each application trusts the tenant and relies on it for authentication and claims.

Device compliance state flows in from Microsoft Intune. Conditional Access can then require a compliant or hybrid-joined device before granting access. This ties the identity decision to device posture.

Sign-in and audit logs flow out to monitoring and SIEM platforms. See `/platforms/splunk.md` and `/platforms/servicenow-vr.md` for downstream consumers of identity events. Group membership and role assignment can be driven by an external governance system.

## Hardening and secure use

Enforce Conditional Access rather than leaving policies in report-only mode indefinitely. A report-only policy records intent but blocks nothing.

Require phishing-resistant multi-factor authentication where the application and user population support it. Passkeys and FIDO2 security keys resist the real-time phishing that defeats push and one-time codes.

Use Privileged Identity Management instead of standing privilege. Roles should be eligible and activated just in time, with approval and expiry, so an account is not permanently privileged.

Maintain emergency-access accounts that are excluded from policies which could lock everyone out. Store their credentials securely, monitor their use, and test them regularly.

Govern application registration and consent. Over-broad application roles and unreviewed consent grants are a form of missing authorization, which maps to CWE-862 Missing Authorization. Restrict who can register applications and who can consent to permissions on behalf of others.

## Where it fits in the program

Entra ID is the authentication and authorization boundary for cloud resources. Identity hygiene here, least privilege, strong factors, and no standing admin, reduces the blast radius of a compromised credential.

Its logs feed detection and vulnerability management. A sign-in from an impossible location or a sudden role elevation is an input to incident response. Access reviews support the recurring attestation that governance frameworks expect.

## Resources

- Microsoft Entra documentation
- Microsoft Entra Conditional Access documentation
- Microsoft Entra Privileged Identity Management documentation
- Microsoft Entra ID Protection documentation

## Related pages

- `/platforms/README.md`
- `/VULNERABILITY_MANAGEMENT_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/cisco-duo.md`
- `/platforms/cyberark.md`
- `/platforms/sailpoint.md`
