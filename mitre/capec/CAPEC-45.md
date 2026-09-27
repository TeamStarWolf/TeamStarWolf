# CAPEC-45 — Buffer Overflow via Symbolic Links

<a id="capec-45"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This type of attack leverages the use of symbolic links to cause buffer overflows. An adversary can try to create or manipulate a symbolic link file such that its contents result in out of bounds data. When the target software processes the symbolic link file, it could potentially overflow internal buffers with insufficient bounds checking.

## Related CWE (9)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-118 — Incorrect Access of Indexable Resource ('Range Error')](https://cwe.mitre.org/data/definitions/118.html)
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- The adversary can create symbolic link on the target host.
- The target host does not perform correct boundary checking while consuming data from a resources.

## Skills required

- An adversary can simply overflow a buffer by inserting a long string into an adversary-modifiable injection vector. The result can be a DoS.:L

## Mitigations

- Pay attention to the fact that the resource you read from can be a replaced by a Symbolic link. You can do a Symlink check before reading the file and decide that this is not a legitimate way of accessing the resource.
- Because Symlink can be modif

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
