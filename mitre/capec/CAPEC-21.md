# CAPEC-21 — Exploitation of Trusted Identifiers

<a id="capec-21"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

An adversary guesses, obtains, or rides a trusted identifier (e.g. session ID, resource ID, cookie, etc.) to perform authorized actions under the guise of an authenticated user or service.

## Mapped ATT&CK techniques (3)

- [T1134 — Access Token Manipulation](/mitre/techniques/T1134.md)
- [T1528 — Steal Application Access Token](/mitre/techniques/T1528.md)
- [T1539 — Steal Web Session Cookie](/mitre/techniques/T1539.md)

## Related CWE (9)

- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-539 — Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
- [CWE-6 — J2EE Misconfiguration: Insufficient Session-ID Length](https://cwe.mitre.org/data/definitions/6.html)
- [CWE-384 — Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-664 — Improper Control of a Resource Through its Lifetime](https://cwe.mitre.org/data/definitions/664.html)
- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [CWE-642 — External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

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
