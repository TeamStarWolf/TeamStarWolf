# CAPEC-46 — Overflow Variables and Tags

<a id="capec-46"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This type of attack leverages the use of tags or variables from a formatted configuration data to cause buffer overflow. The adversary crafts a malicious HTML page or configuration file that includes oversized strings, thus causing an overflow.

## Related CWE (8)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-118 — Incorrect Access of Indexable Resource ('Range Error')](https://cwe.mitre.org/data/definitions/118.html)
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- [CWE-733 — Compiler Optimization Removal or Modification of Security-critical Code](https://cwe.mitre.org/data/definitions/733.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- The target program consumes user-controllable data in the form of tags or variables.
- The target program does not perform sufficient boundary checking.

## Skills required

- An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

## Mitigations

- Use a language or compiler that performs automatic bounds checking.
- Use an abstraction library to abstract away risky APIs. Not a complete solution.
- Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /G

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
