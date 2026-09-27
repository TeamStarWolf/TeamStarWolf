# CAPEC-61 — Session Fixation

<a id="capec-61"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

The attacker induces a client to establish a session with the target software using a session identifier provided by the attacker. Once the user successfully authenticates to the target software, the attacker uses the (now privileged) session identifier in their own transactions. This attack leverages the fact that the target software either relies on client-generated session identifiers or mainta

## Related CWE (3)

[CWE-384](/CWE_REFERENCE.md) [CWE-664](/CWE_REFERENCE.md) [CWE-732](/CWE_REFERENCE.md)

**Prerequisites:** ::Session identifiers that remain unchanged when the privilege levels change.::Permissive session management mechanism that accepts random user-generated session identifiers::Predictable session ident

**Skills required:** ::SKILL:Only basic skills are required to determine and fixate session identifiers in a user's browser. Subsequent attacks may require greater skill l

**Mitigations:** ::Use a strict session management mechanism that only accepts locally generated session identifiers: This prevents attackers from fixating session identifiers of their own choice.::Regenerate and destroy session identifiers when there is a change in 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
