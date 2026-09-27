# CAPEC-47 — Buffer Overflow via Parameter Expansion

<a id="capec-47"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

In this attack, the target software is given input that the adversary knows will be modified and expanded in size during processing. This attack relies on the target software failing to anticipate that the expanded data may exceed some internal limit, thereby creating a buffer overflow.

## Related CWE (9)

[CWE-120](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-130](/CWE_REFERENCE.md) [CWE-131](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The program expands one of the parameters passed to a function with input controlled by the user, but a later function making use of the expanded parameter erroneously considers the original, not th

**Skills required:** ::SKILL:Finding this particular buffer overflow may not be trivial. Also, stack and especially heap based buffer overflows require a lot of knowledge 

**Mitigations:** ::Ensure that when parameter expansion happens in the code that the assumptions used to determine the resulting size of the parameter are accurate and that the new size of the parameter is visible to the whole system::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
