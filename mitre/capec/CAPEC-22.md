# CAPEC-22 — Exploiting Trust in Client

<a id="capec-22"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High

An attack of this type exploits vulnerabilities in client/server communication channel authentication and data integrity. It leverages the implicit trust a server places in the client, or more importantly, that which the server believes is the client. An attacker executes this type of attack by communicating directly with the server where the server believes it is communicating only with a valid c

## Related CWE (5)

[CWE-290](/CWE_REFERENCE.md) [CWE-287](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-200](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md)

**Prerequisites:** ::Server software must rely on client side formatted and validated values, and not reinforce these checks on the server side.::

**Skills required:** ::SKILL:The attacker must have fairly detailed knowledge of the syntax and semantics of client/server communications protocols and grammars:LEVEL:Medi

**Mitigations:** ::Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.::Design: Do not rely on client validation or encoding for security purposes.::Design: Utilize digita


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
