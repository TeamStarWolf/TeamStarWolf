# CAPEC-593 — Session Hijacking

<a id="capec-593"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The adversary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

## Mapped ATT&CK techniques (3)

- [T1185](/mitre/techniques/T1185.md)
- [T1550.001](/mitre/techniques/T1550-001.md)
- [T1563](/mitre/techniques/T1563.md)

## Related CWE (1)

[CWE-287](/CWE_REFERENCE.md)

**Prerequisites:** ::An application that leverages sessions to perform authentication.::

**Skills required:** ::SKILL:Exploiting a poorly protected identity token is a well understood attack with many helpful resources available.:LEVEL:Low::

**Mitigations:** ::Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on y


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
