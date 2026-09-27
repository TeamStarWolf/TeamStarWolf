# CAPEC-52 — Embedding NULL Bytes

<a id="capec-52"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary embeds one or more null bytes in input to the target software. This attack relies on the usage of a null-valued byte as a string terminator in many environments. The goal is for certain components of the target software to stop processing the input when it encounters the null byte(s).

## Related CWE (7)

- [CWE-158 — Improper Neutralization of Null Byte or NUL Character](https://cwe.mitre.org/data/definitions/158.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)

## Prerequisites

- The program does not properly handle postfix NULL terminators

## Skills required

- Directory traversal:LEVEL:Medium
- Execution of arbitrary code:LEVEL:High

## Mitigations

- Properly handle the NULL characters supplied as part of user input prior to doing anything with the data.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
