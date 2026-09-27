# CAPEC-129 — Pointer Manipulation

<a id="capec-129"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** 

This attack pattern involves an adversary manipulating a pointer within a target application resulting in the application accessing an unintended memory location. This can result in the crashing of the application or, for certain pointer values, access to data that would not normally be possible or the execution of arbitrary code. Since pointers are simply integer variables, Integer Attacks may of

## Related CWE (3)

[CWE-682](/CWE_REFERENCE.md) [CWE-822](/CWE_REFERENCE.md) [CWE-823](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must have a pointer variable that the attacker can influence to hold an arbitrary value.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
