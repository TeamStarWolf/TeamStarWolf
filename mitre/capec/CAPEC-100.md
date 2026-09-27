# CAPEC-100 — Overflow Buffers

<a id="capec-100"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

Buffer Overflow attacks target improper or missing bounds checking on buffer operations, typically triggered by input injected by an adversary. As a consequence, an adversary is able to write past the boundaries of allocated buffer regions in memory, causing a program crash or potentially redirection of execution as per the adversaries' choice.

## Related CWE (6)

[CWE-120](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-131](/CWE_REFERENCE.md) [CWE-129](/CWE_REFERENCE.md) [CWE-805](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md)

**Prerequisites:** ::Targeted software performs buffer operations.::Targeted software inadequately performs bounds-checking on buffer operations.::Adversary has the capability to influence the input to buffer operations

**Skills required:** ::SKILL:In most cases, overflowing a buffer does not require advanced skills beyond the ability to notice an overflow and stuff an input variable with

**Mitigations:** ::Use a language or compiler that performs automatic bounds checking.::Use secure functions not vulnerable to buffer overflow.::If you have to use dangerous functions, make sure that you do boundary checking.::Compiler-based canary mechanisms such as


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
