# CAPEC-593 — Session Hijacking

<a id="capec-593"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The adversary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

## Mapped ATT&CK techniques (3)

- [T1185 — Browser Session Hijacking](/mitre/techniques/T1185.md) — Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking…
- [T1550.001 — Application Access Token](/mitre/techniques/T1550-001.md) — Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1563 — Remote Service Session Hijacking](/mitre/techniques/T1563.md) — Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.

## Related CWE (1)

- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) — When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Prerequisites

- An application that leverages sessions to perform authentication.

## Skills required

- Exploiting a poorly protected identity token is a well understood attack with many helpful resources available.:LEVEL:Low

## Mitigations

- Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on y

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
