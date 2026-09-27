# CAPEC-92 — Forced Integer Overflow

<a id="capec-92"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack forces an integer variable to go out of range. The integer variable is often used as an offset such as size of memory allocation or similarly. The attacker would typically control the value of such variable and try to get it out of range. For instance the integer in question is incremented past the maximum possible value, it may wrap to become a very small, or negative number, therefor

## Related CWE (7)

- [CWE-190 — Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-128 — Wrap-around Error](https://cwe.mitre.org/data/definitions/128.html)
- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-122 — Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- [CWE-196 — Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html)
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- The attacker can manipulate the value of an integer variable utilized by the target host.
- The target host does not do proper range checking on the variable before utilizing it.
- When the integer va

## Skills required

- An attacker can simply overflow an integer by inserting an out of range value.:LEVEL:Low
- Exploiting a buffer overflow by injecting mali

## Mitigations

- Use a language or compiler that performs automatic bounds checking.
- Carefully review the service's implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as integ

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
