# CAPEC-120 — Double Encoding

<a id="capec-120"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low  
**Status:** Draft  

The adversary utilizes a repeating of the encoding process for a set of characters (that is, character encoding a character encoding of a character) to obfuscate the payload of a particular request. This may allow the adversary to bypass filters that attempt to detect illegal characters or strings, such as those that might be used in traversal or injection attacks. Filters may be able to catch ill

## Related CWE (10)

- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-177 — Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html)
- [CWE-181 — Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html)
- [CWE-183 — Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CWE-692 — Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html)

## Prerequisites

- The target's filters must fail to detect that a character has been doubly encoded but its interpreting engine must still be able to convert a doubly encoded character to an un-encoded character.
- Th

## Mitigations

- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
