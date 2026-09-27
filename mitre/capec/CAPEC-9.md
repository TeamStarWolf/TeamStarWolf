# CAPEC-9 — Buffer Overflow in Local Command-Line Utilities

<a id="capec-9"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets command-line utilities available in a number of shells. An adversary can leverage a vulnerability found in a command-line utility to escalate privilege to root.

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

- The target host exposes a command-line utility to the user.
- The command-line utility exposed by the target host has a buffer overflow vulnerability that can be exploited.

## Skills required

- An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

## Mitigations

- Carefully review the service's implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as buffer overflow.
- Use a language or compiler that performs automatic bound

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
