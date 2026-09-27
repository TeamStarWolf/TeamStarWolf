# CAPEC-92 — Forced Integer Overflow

<a id="capec-92"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack forces an integer variable to go out of range. The integer variable is often used as an offset such as size of memory allocation or similarly. The attacker would typically control the value of such variable and try to get it out of range. For instance the integer in question is incremented past the maximum possible value, it may wrap to become a very small, or negative number, therefor

## Related CWE (7)

[CWE-190](/CWE_REFERENCE.md) [CWE-128](/CWE_REFERENCE.md) [CWE-120](/CWE_REFERENCE.md) [CWE-122](/CWE_REFERENCE.md) [CWE-196](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker can manipulate the value of an integer variable utilized by the target host.::The target host does not do proper range checking on the variable before utilizing it.::When the integer va

**Skills required:** ::SKILL:An attacker can simply overflow an integer by inserting an out of range value.:LEVEL:Low::SKILL:Exploiting a buffer overflow by injecting mali

**Mitigations:** ::Use a language or compiler that performs automatic bounds checking.::Carefully review the service's implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as integ


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
