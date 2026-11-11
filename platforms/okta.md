# Okta

Okta is a cloud identity provider for workforce and customer identity. It federates
access to applications, directories, and APIs so that one account and one set of
policies control sign-in across many services.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Identity and access engineers who run, tune or assess Okta

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,425 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Okta for identity, sign-in and access, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Microsoft Entra ID](/platforms/entra-id.md), [Cisco Duo](/platforms/cisco-duo.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Okta sits between people and the applications they use. Instead of each application
holding its own password store, the application trusts Okta to authenticate the user
and assert who they are. This makes Okta the control point for access decisions
across a tenant.

Two product lines exist. Workforce Identity covers employees, contractors, and
partners. Customer Identity (built on the Auth0 platform) covers the people who use
an organization's own applications. Both share the same idea of a central identity
provider, but the policies and user populations differ.

Because so much access routes through it, the identity provider is a high-value
target. Compromise of an administrator account or a weak factor can expose every
connected application at once. For that reason, phishing-resistant factors and strong
admin protection are not optional extras. They are the baseline.

## Architecture and how it works

Okta runs as a multi-tenant cloud service. Each customer has a tenant, reached at a
tenant-specific domain, that holds users, groups, applications, and policies.

The core building blocks are:

- Universal Directory, the user and group store, with custom attributes and profile
  sourcing from upstream directories.
- Single sign-on, which federates applications through SAML and OpenID Connect so a
  user signs in once and reaches many applications.
- Adaptive multi-factor authentication, which chooses the required factors based on
  signals such as device, network, and risk.
- Lifecycle management, which creates, updates, and deactivates accounts in
  downstream applications as people join, move, and leave.
- API access management, which issues OAuth 2.0 tokens so services can call APIs on a
  user's behalf under scoped grants.

For federation, Okta acts as the identity provider and the application acts as the
service provider or relying party. When a user reaches an application, the
application redirects to Okta, Okta authenticates the user and evaluates policy, then
returns a signed SAML assertion or an OpenID Connect token. The application validates
the signature and reads the claims to establish the session.

Okta can also act as a broker, trusting an upstream identity provider for the actual
authentication while still applying its own policy and routing. Inbound federation
and directory integrations let Okta source users from an existing directory rather
than owning every account directly.

## Key capabilities

- Single sign-on across SAML and OpenID Connect applications, plus password-vaulting
  connectors for applications that do not support those protocols.
- Universal Directory as a flexible profile store with attribute mapping and
  transformation between sources and targets.
- Adaptive multi-factor authentication with factors that include FIDO2 and WebAuthn
  security keys, platform authenticators, Okta Verify push, one-time codes, and
  others. Phishing-resistant factors bind the login to the real domain.
- Lifecycle management and provisioning through SCIM and application connectors, so
  joiner, mover, and leaver events flow automatically.
- API access management, issuing and validating OAuth 2.0 access tokens with scopes
  and custom authorization servers.
- Policy engine for sign-on, password, and authenticator rules, evaluated per
  application and per group.
- Reporting and a system log that records authentication, administration, and policy
  events for review and export.

## Deployment and operations

Okta is delivered as a service, so there is no server software to patch for the core
platform. Operational work centers on configuration, integration agents, and policy.

Common operational components:

- Directory integration agents that run on-premises to sync with an existing
  directory and to delegate authentication to it.
- Provisioning connectors to downstream applications, configured per application.
- Administrator roles, which should be scoped so that each admin holds only the rights
  their job needs.

Day-to-day work includes onboarding applications, writing and testing policies,
reviewing the system log, and rotating API tokens and signing keys. Policy changes
should be tested against a pilot group before they reach the whole tenant, because a
mistaken rule can lock users out or weaken a control for everyone.

Tenant configuration is itself sensitive. Changes to authentication policy, admin
roles, or trusted identity providers should go through change control and be logged.

## Integrations and data flow

The main integration patterns are federation, provisioning, and logging.

- Federation. Applications trust Okta through SAML or OpenID Connect. The data that
  flows is the signed assertion or token containing the user's identifier and claims.
- Provisioning. Okta pushes account create, update, and deactivate operations to
  downstream applications, usually over SCIM. Attributes map from Universal Directory
  to each target schema.
- Directory sourcing. Okta reads users and groups from an upstream directory and can
  delegate authentication back to it.
- Logging. The system log can stream to a SIEM so that identity events sit alongside
  endpoint and network telemetry for correlation and alerting.

Keep the data in these flows minimal. Send only the attributes an application needs,
and avoid placing sensitive personal data in claims that downstream systems do not
require.

## Adversary perspective

Okta is the identity control plane, so adversaries treat it both as the prize and as something to bypass, and its admin console and federation trust are themselves an attack surface. The steps to lock it down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Phishing and MFA fatigue (ATT&CK T1621, T1556): real-time phishing proxies relay a login, and repeated push prompts wear a user into approving. Phishing-resistant factors such as FIDO2 are the counter.
- Session and token theft (T1539, T1550): stealing a live session cookie or OAuth token lets an attacker replay an authenticated session without touching MFA at all.
- Federation and token forging (T1606.002): a stolen signing key or an added trusted identity provider lets an attacker mint or accept assertions in golden-SAML style and impersonate any user ([CWE-287](https://cwe.mitre.org/data/definitions/287.html)).
- Admin and help-desk abuse (T1098): social-engineering a factor reset, or hijacking an admin session, turns the identity provider into a foothold ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).

### Residual risk and own exposure

The identity provider is the keys to the kingdom, so its own compromise is catastrophic: one forged assertion or stolen admin session can reach every connected application. Identity platforms have themselves been targeted through support systems and session theft, so the tenant configuration, admin accounts, and integration agents belong in the patch and monitoring scope.

### Why it matters

Treating the identity provider as trusted by default is the mistake. A tester probes factor downgrade, stale OAuth grants, and recoverable admin paths; a defender watches the system log for factor changes, new trusted providers, and impossible-travel sign-ins. See [the identity security reference](/IDENTITY_SECURITY_REFERENCE.md) and [the red team reference](/RED_TEAM_REFERENCE.md).

## Hardening and secure use

- Separate administrator roles. Grant scoped admin roles rather than super admin, and
  keep the number of super admins small. Over-broad roles are a case of missing or
  weak authorization (CWE-862).
- Require phishing-resistant MFA. FIDO2 and WebAuthn factors bind the login to the
  real domain and resist credential phishing and push fatigue. Weak or bypassable
  authentication paths map to improper authentication (CWE-287).
- Scope API tokens tightly. Issue tokens with the least privilege required, set
  expiry, and rotate them. Treat tokens as secrets and store them in a vault, never in
  source or configuration files. Hardcoded credentials map to CWE-798.
- Apply session and device policy. Set session lifetimes, require re-authentication
  for sensitive actions, and gate access on device posture where available. Loose
  session handling widens the window for a stolen session (CWE-287).
- Protect the admin console with its own strong authentication policy, network
  restrictions where feasible, and alerting on admin-role changes.
- Monitor the system log for factor enrollment changes, policy edits, and new trusted
  identity providers, and send those events to the SIEM.
- Review third-party application grants and remove ones no longer in use, since each
  OAuth grant is standing access.

## Where it fits in the program

Okta is the identity control plane. For an identity and security team it is where
authentication policy, MFA enforcement, and joiner-mover-leaver automation live. It
reduces local password stores and gives one place to enforce access rules.

For vulnerability management, the Okta configuration itself is in scope. Weak MFA
policy, over-privileged admins, and stale application grants are findings even when no
software CVE is involved. For incident response, the system log is a primary source
for reconstructing how an identity was used and which applications were reached.

Okta pairs with privileged access management for high-risk accounts and with endpoint
and SIEM tooling for the signals that feed adaptive policy and investigation.

## Resources

- Okta Help Center
- Okta Developer documentation
- Okta Integration Network catalog
- Okta trust and security documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Identity security reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Entra ID](/platforms/entra-id.md)
- [Cisco Duo](/platforms/cisco-duo.md)
- [Ping Identity](/platforms/ping-identity.md)
