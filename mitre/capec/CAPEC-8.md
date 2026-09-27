# CAPEC-8 — Buffer Overflow in an API Call

<a id="capec-8"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack targets libraries or shared code modules which are vulnerable to buffer overflow attacks. An adversary who has knowledge of known vulnerable libraries or shared code can easily target software that makes use of these libraries. All clients that make use of the code library thus become vulnerable by association. This has a very broad effect on security across a system, usually affecting

## Related CWE (8)

[CWE-120](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-733](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The target host exposes an API to the user.::One or more API functions exposed by the target host has a buffer overflow vulnerability.::

**Skills required:** ::SKILL:An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

**Mitigations:** ::Use a language or compiler that performs automatic bounds checking.::Use secure functions not vulnerable to buffer overflow.::If you have to use dangerous functions, make sure that you do boundary checking.::Compiler-based canary mechanisms such as


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
