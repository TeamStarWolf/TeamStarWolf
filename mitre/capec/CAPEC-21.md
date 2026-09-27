# CAPEC-21 — Exploitation of Trusted Identifiers

<a id="capec-21"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

An adversary guesses, obtains, or rides a trusted identifier (e.g. session ID, resource ID, cookie, etc.) to perform authorized actions under the guise of an authenticated user or service.

## Mapped ATT&CK techniques (3)

- [T1134 — Access Token Manipulation](/mitre/techniques/T1134.md) — Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls.
- [T1528 — Steal Application Access Token](/mitre/techniques/T1528.md) — Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.
- [T1539 — Steal Web Session Cookie](/mitre/techniques/T1539.md) — An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials.

## Related CWE (9)

- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) — This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html) — The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-539 — Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html) — The web application uses persistent cookies, but the cookies contain sensitive information.
- [CWE-6 — J2EE Misconfiguration: Insufficient Session-ID Length](https://cwe.mitre.org/data/definitions/6.html) — The J2EE application is configured to use an insufficient session ID length.
- [CWE-384 — Session Fixation](https://cwe.mitre.org/data/definitions/384.html) — Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.
- [CWE-664 — Improper Control of a Resource Through its Lifetime](https://cwe.mitre.org/data/definitions/664.html) — The product does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation, use, and release.
- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) — The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.
- [CWE-642 — External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html) — The product stores security-critical state information about its users, or the product itself, in a location that is accessible to unauthorized actors.

## Prerequisites

- Server software must rely on weak identifier proof and/or verification schemes.
- Identifiers must have long lifetimes and potential for reusability.
- Server software must allow concurrent sessions t

## Skills required

- To achieve a direct connection with the weak or non-existent server session access control, and pose as an authorized user:LEVEL:Low

## Mitigations

- Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.
- Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many s

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
