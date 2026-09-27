# CAPEC-633 — Token Impersonation

<a id="capec-633"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Stable  

An adversary exploits a weakness in authentication to create an access token (or equivalent) that impersonates a different entity, and then associates a process/thread to that that impersonated token. This action causes a downstream user to make a decision or take action that is based on the assumed identity, and not the response that blocks the adversary.

## Mapped ATT&CK techniques (1)

- [T1134 — Access Token Manipulation](/mitre/techniques/T1134.md)

## Related CWE (2)

- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-1270 — Generation of Incorrect Security Tokens](https://cwe.mitre.org/data/definitions/1270.html)

## Prerequisites

- This pattern of attack is only applicable when a downstream user leverages tokens to verify identity, and then takes action based on that identity.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
