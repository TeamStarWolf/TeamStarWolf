# CAPEC-92 — Forced Integer Overflow

<a id="capec-92"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack forces an integer variable to go out of range. The integer variable is often used as an offset such as size of memory allocation or similarly. The attacker would typically control the value of such variable and try to get it out of range. For instance the integer in question is incremented past the maximum possible value, it may wrap to become a very small, or negative number, therefor

## Related CWE (7)

- [CWE-190 — Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html) — The product performs a calculation that can produce an integer overflow or wraparound when the logic assumes that the resulting value will always be larger than the original value.
- [CWE-128 — Wrap-around Error](https://cwe.mitre.org/data/definitions/128.html) — Wrap around errors occur whenever a value is incremented past the maximum value for its type and therefore wraps around to a very small, negative, or undefined value.
- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html) — The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-122 — Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html) — A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine such as malloc().
- [CWE-196 — Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html) — The product uses an unsigned primitive and performs a cast to a signed primitive, which can produce an unexpected value if the value of the unsigned primitive can not be represented using a signed primitive.
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html) — The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.

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
