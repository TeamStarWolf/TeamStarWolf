# CAPEC-8 — Buffer Overflow in an API Call

<a id="capec-8"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets libraries or shared code modules which are vulnerable to buffer overflow attacks. An adversary who has knowledge of known vulnerable libraries or shared code can easily target software that makes use of these libraries. All clients that make use of the code library thus become vulnerable by association. This has a very broad effect on security across a system, usually affecting

## Related CWE (8)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-118 — Incorrect Access of Indexable Resource ('Range Error')](https://cwe.mitre.org/data/definitions/118.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- [CWE-733 — Compiler Optimization Removal or Modification of Security-critical Code](https://cwe.mitre.org/data/definitions/733.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- The target host exposes an API to the user.
- One or more API functions exposed by the target host has a buffer overflow vulnerability.

## Skills required

- An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

## Mitigations

- Use a language or compiler that performs automatic bounds checking.
- Use secure functions not vulnerable to buffer overflow.
- If you have to use dangerous functions, make sure that you do boundary checking.
- Compiler-based canary mechanisms such as

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
