# CAPEC-100 — Overflow Buffers

<a id="capec-100"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

Buffer Overflow attacks target improper or missing bounds checking on buffer operations, typically triggered by input injected by an adversary. As a consequence, an adversary is able to write past the boundaries of allocated buffer regions in memory, causing a program crash or potentially redirection of execution as per the adversaries' choice.

## Related CWE (6)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-131 — Incorrect Calculation of Buffer Size](https://cwe.mitre.org/data/definitions/131.html)
- [CWE-129 — Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)
- [CWE-805 — Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html)
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)

## Prerequisites

- Targeted software performs buffer operations.
- Targeted software inadequately performs bounds-checking on buffer operations.
- Adversary has the capability to influence the input to buffer operations

## Skills required

- In most cases, overflowing a buffer does not require advanced skills beyond the ability to notice an overflow and stuff an input variable with

## Mitigations

- Use a language or compiler that performs automatic bounds checking.
- Use secure functions not vulnerable to buffer overflow.
- If you have to use dangerous functions, make sure that you do boundary checking.
- Compiler-based canary mechanisms such as

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
