# CAPEC-10 — Buffer Overflow via Environment Variables

<a id="capec-10"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack pattern involves causing a buffer overflow through manipulation of environment variables. Once the adversary finds that they can modify an environment variable, they may try to overflow associated buffers. This attack leverages implicit trust often placed in environment variables.

## Related CWE (10)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-118 — Incorrect Access of Indexable Resource ('Range Error')](https://cwe.mitre.org/data/definitions/118.html)
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-99 — Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- [CWE-733 — Compiler Optimization Removal or Modification of Security-critical Code](https://cwe.mitre.org/data/definitions/733.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- The application uses environment variables.
- An environment variable exposed to the user is vulnerable to a buffer overflow.
- The vulnerable environment variable uses untrusted data.
- Tainted data u

## Skills required

- An attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vector. The result can be a DoS.:LEV

## Mitigations

- Do not expose environment variable to the user.
- Do not use untrusted data in your environment variables.
- Use a language or compiler that performs automatic bounds checking
- There are tools such as Sharefuzz [REF-2] which is an environment variabl

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
