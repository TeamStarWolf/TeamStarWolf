# CAPEC-129 — Pointer Manipulation

<a id="capec-129"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Status:** Draft  

This attack pattern involves an adversary manipulating a pointer within a target application resulting in the application accessing an unintended memory location. This can result in the crashing of the application or, for certain pointer values, access to data that would not normally be possible or the execution of arbitrary code. Since pointers are simply integer variables, Integer Attacks may of

## Related CWE (3)

- [CWE-682 — Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html) — The product performs a calculation that generates incorrect or unintended results that are later used in security-critical decisions or resource management.
- [CWE-822 — Untrusted Pointer Dereference](https://cwe.mitre.org/data/definitions/822.html) — The product obtains a value from an untrusted source, converts this value to a pointer, and dereferences the resulting pointer.
- [CWE-823 — Use of Out-of-range Pointer Offset](https://cwe.mitre.org/data/definitions/823.html) — The product performs pointer arithmetic on a valid pointer, but it uses an offset that can point outside of the intended range of valid memory locations for the resulting pointer.

## Prerequisites

- The target application must have a pointer variable that the attacker can influence to hold an arbitrary value.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
