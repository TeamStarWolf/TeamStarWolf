# CAPEC-24 — Filter Failure through Buffer Overflow

<a id="capec-24"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

In this attack, the idea is to cause an active filter to fail by causing an oversized transaction. An attacker may try to feed overly long input strings to the program in an attempt to overwhelm the filter (by causing a buffer overflow) and hoping that the filter does not fail securely (i.e. the user input is let into the system unfiltered).

## Related CWE (8)

[CWE-120](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-733](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::Ability to control the length of data passed to an active filter.::

**Skills required:** ::SKILL:An attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vector. The result can be a DoS.:LEV

**Mitigations:** ::Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.::Pre-design: Use a langua


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
