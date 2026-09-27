# CAPEC-196 — Session Credential Falsification through Forging

<a id="capec-196"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An attacker creates a false but functional session credential in order to gain or usurp access to a service. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. If an attacker is able to forge valid session credentials they may be able to by

## Mapped ATT&CK techniques (3)

- [T1134.002 — Create Process with Token](/mitre/techniques/T1134-002.md) — Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.
- [T1134.003 — Make and Impersonate Token](/mitre/techniques/T1134-003.md) — Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls.
- [T1606 — Forge Web Credentials](/mitre/techniques/T1606.md) — Adversaries may forge credential materials that can be used to gain access to web applications or Internet services.

## Related CWE (2)

- [CWE-384 — Session Fixation](https://cwe.mitre.org/data/definitions/384.html) — Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.
- [CWE-664 — Improper Control of a Resource Through its Lifetime](https://cwe.mitre.org/data/definitions/664.html) — The product does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation, use, and release.

## Prerequisites

- The targeted application must use session credentials to identify legitimate users. Session identifiers that remains unchanged when the privilege levels change. Predictable session identifiers.

## Skills required

- Forge the session credential and reply the request.:LEVEL:Medium

## Mitigations

- Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or g

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
