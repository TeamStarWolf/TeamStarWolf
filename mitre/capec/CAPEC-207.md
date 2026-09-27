# CAPEC-207 — Removing Important Client Functionality

<a id="capec-207"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary removes or disables functionality on the client that the server assumes to be present and trustworthy.

## Related CWE (1)

[CWE-602](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted server must assume the client performs important actions to protect the server or the server functionality. For example, the server may assume the client filters outbound traffic or tha

**Skills required:** ::SKILL:To reverse engineer the client-side code to disable/remove the functionality on the client that the server relies on.:LEVEL:High::SKILL:The ad

**Mitigations:** ::Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.::Design: Ship client-side application with integrity checks (code signing) when possible.::Design: Use obfuscation an


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
