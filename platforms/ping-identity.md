# Ping Identity

Ping Identity is an enterprise identity platform for single sign-on, multi-factor
authentication, and identity orchestration. It spans cloud services and deployable
software, which suits large and hybrid environments.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Identity and access engineers who run, tune or assess Ping Identity

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (1,030 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Ping Identity for identity, sign-in and access, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Okta](/platforms/okta.md), [Microsoft Entra ID](/platforms/entra-id.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Ping Identity provides the components an organization uses to authenticate people and
federate access to applications. It is often chosen where identity must work across a
mix of cloud and on-premises systems, and where existing federation infrastructure
needs to stay in place.

The platform is a set of products rather than a single service:

- PingOne, a set of cloud identity services including sign-on, MFA, and risk signals.
- PingFederate, a federation server that issues and consumes SAML and OpenID Connect,
  deployable on-premises or in a private cloud.
- PingAccess, an access control gateway that enforces policy in front of web
  applications and APIs.

Together these act as the identity control point for the applications they front. As
with any identity provider, the components are high-value targets, so admin
protection, key management, and careful federation trust matter.

## Architecture and how it works

The platform mixes cloud services with software you run yourself, and the two can work
together.

PingFederate is the federation engine. It acts as an identity provider for
applications that trust it, and as a service provider or broker toward upstream
identity providers. It issues signed SAML assertions and OpenID Connect tokens and
validates incoming ones. Adapters and connectors integrate it with directories,
authentication methods, and downstream systems.

PingOne delivers identity as cloud services. It offers sign-on, a directory, MFA, and
risk evaluation that other components and applications can call. PingOne can front
applications directly or work alongside PingFederate in a hybrid design.

PingAccess sits in the request path for web applications and APIs. It intercepts
requests, checks for a valid session or token, and applies access rules before the
request reaches the protected resource. It relies on PingFederate or PingOne for the
actual authentication.

Identity orchestration ties these together into flows. A flow can branch on risk,
step up to a stronger factor, call an external service, and route the user through the
right authentication path without custom code in each application.

## Key capabilities

- Single sign-on across SAML and OpenID Connect, with brokering between multiple
  identity providers.
- Multi-factor authentication, including phishing-resistant factors such as FIDO2 and
  WebAuthn, mobile push, and one-time codes.
- Identity orchestration, building authentication and registration flows with
  branching logic and external calls.
- Access control for web applications and APIs through PingAccess, enforcing policy at
  the gateway.
- Directory services through PingOne and integration with existing enterprise
  directories.
- Risk signals that feed adaptive decisions during a flow.
- Token and session management, issuing scoped OAuth 2.0 tokens and governing session
  lifetime.

## Deployment and operations

Ping Identity supports cloud, on-premises, and hybrid deployments, which is a reason
large organizations select it. The operational model depends on which components are
self-run.

For PingFederate and PingAccess run as software, operational work includes patching
the servers, managing the Java runtime, clustering for availability, and rotating
signing and TLS keys and certificates. Configuration is held in the server and should
be under change control and version tracking where possible.

For PingOne cloud services, the vendor runs the platform and the work is
configuration, connector management, and policy.

Across both, operators onboard applications, build and test orchestration flows,
manage certificates and keys, and review logs. Signing certificate expiry is a common
cause of federation outages, so certificate lifecycle needs tracking. Flows and policy
changes should be tested against a pilot before wide release.

## Integrations and data flow

- Federation. Applications trust PingFederate or PingOne through SAML or OpenID
  Connect. A signed assertion or token carries the user identifier and claims to the
  application, which validates the signature before trusting the contents.
- Brokering. The platform can consume an upstream identity provider and re-assert to
  downstream applications, so one trust fabric spans several sources.
- Access enforcement. PingAccess passes identity and token context to protected
  applications after it validates the session.
- Directory and provisioning. The platform reads from enterprise directories and can
  provision accounts to downstream systems.
- Logging. Server and service logs can stream to a SIEM for correlation with other
  security telemetry.

Send only the claims an application needs, and keep signing keys and client secrets
out of application configuration files.

## Hardening and secure use

- Use role-based administration. Give each administrator only the rights their role
  requires, and keep the set of high-privilege admins small. Over-broad rights are
  missing or weak authorization (CWE-862).
- Manage tokens and keys carefully. Rotate signing keys, set short token lifetimes,
  and store client secrets and API credentials in a vault rather than in files or
  source. Hardcoded credentials map to CWE-798.
- Verify federation trust and signatures. Validate assertion and token signatures,
  pin trusted issuers, and check audience and expiry. Accepting an unverified or
  wrongly scoped assertion is improper authentication (CWE-287).
- Require phishing-resistant MFA for administrators and for high-risk flows, and use
  step-up in orchestration rather than a single static factor.
- Keep self-run servers patched. PingFederate and PingAccess are software with their
  own update cycle, so apply vendor fixes and track end-of-support versions.
- Track certificate expiry for signing and TLS, and alert before certificates lapse.
- Review orchestration flows for branches that skip a factor or accept weak input, and
  test them as part of change control.

## Where it fits in the program

Ping Identity is the identity control plane in environments that are large, hybrid, or
tied to existing federation. It centralizes authentication and access policy and lets
a team build custom flows where off-the-shelf policy is not enough.

For vulnerability management, both the configuration and, for self-run components, the
server software are in scope. Unpatched PingFederate or PingAccess instances, expired
or weak signing keys, and loose federation trust are findings. For incident response,
server and service logs show how identities were authenticated and which resources
PingAccess allowed, which supports reconstruction of an access path.

The platform works with privileged access management for high-risk accounts and with
SIEM and endpoint tooling for the risk signals and investigation data it draws on.

## Resources

- Ping Identity documentation
- PingFederate administration documentation
- PingAccess documentation
- PingOne cloud services documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Identity security reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Okta](/platforms/okta.md)
- [Entra ID](/platforms/entra-id.md)
- [SailPoint](/platforms/sailpoint.md)
