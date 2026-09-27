# CAPEC-46 — Overflow Variables and Tags

<a id="capec-46"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This type of attack leverages the use of tags or variables from a formatted configuration data to cause buffer overflow. The adversary crafts a malicious HTML page or configuration file that includes oversized strings, thus causing an overflow.

## Related CWE (8)

[CWE-120](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-733](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The target program consumes user-controllable data in the form of tags or variables.::The target program does not perform sufficient boundary checking.::

**Skills required:** ::SKILL:An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

**Mitigations:** ::Use a language or compiler that performs automatic bounds checking.::Use an abstraction library to abstract away risky APIs. Not a complete solution.::Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /G


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
