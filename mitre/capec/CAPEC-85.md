# CAPEC-85 — AJAX Footprinting

<a id="capec-85"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** High

This attack utilizes the frequent client-server roundtrips in Ajax conversation to scan a system. While Ajax does not open up new vulnerabilities per se, it does optimize them from an attacker point of view. A common first step for an attacker is to footprint the target environment to understand what attacks will work. Since footprinting relies on enumeration, the conversational pattern of rapid,

## Related CWE (9)

[CWE-79](/CWE_REFERENCE.md) [CWE-113](/CWE_REFERENCE.md) [CWE-348](/CWE_REFERENCE.md) [CWE-96](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-116](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-86](/CWE_REFERENCE.md) [CWE-692](/CWE_REFERENCE.md)

**Prerequisites:** ::The user must allow JavaScript to execute in their browser::

**Skills required:** ::SKILL:To land and launch a script on victim's machine with appropriate footprinting logic for enumerating services and vulnerabilities in JavaScript

**Mitigations:** ::Design: Use browser technologies that do not allow client side scripting.::Implementation: Perform input validation for all remote content.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
