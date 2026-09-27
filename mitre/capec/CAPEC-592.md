# CAPEC-592 — Stored XSS

<a id="capec-592"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

An adversary utilizes a form of Cross-site Scripting (XSS) where a malicious script is persistently stored within the data storage of a vulnerable web application as valid input.

## Related CWE (1)

[CWE-79](/CWE_REFERENCE.md)

**Prerequisites:** ::An application that leverages a client-side web browser with scripting enabled.::An application that fails to adequately sanitize or encode untrusted input.::An application that stores information p

**Skills required:** ::SKILL:Requires the ability to write scripts of varying complexity and to inject them through user controlled fields within the application.:LEVEL:Me

**Mitigations:** ::Use browser technologies that do not allow client-side scripting.::Utilize strict type, character, and encoding enforcement.::Ensure that all user-supplied input is validated before being stored.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
