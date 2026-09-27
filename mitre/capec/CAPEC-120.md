# CAPEC-120 — Double Encoding

<a id="capec-120"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low  
**Status:** Draft  

The adversary utilizes a repeating of the encoding process for a set of characters (that is, character encoding a character encoding of a character) to obfuscate the payload of a particular request. This may allow the adversary to bypass filters that attempt to detect illegal characters or strings, such as those that might be used in traversal or injection attacks. Filters may be able to catch ill

## Related CWE (10)

- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html) — The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html) — The product does not properly encode or decode the data, resulting in unexpected values.
- [CWE-177 — Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html) — The product does not properly handle when all or part of an input has been URL encoded.
- [CWE-181 — Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html) — The product validates data before it has been filtered, which prevents the product from detecting data that becomes invalid after the filtering step.
- [CWE-183 — Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html) — The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are explicitly allowed by policy because the inputs are assumed to be safe, but the list is too permissive -…
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html) — The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes…
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-692 — Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html) — The product uses a denylist-based protection mechanism to defend against XSS attacks, but the denylist is incomplete, allowing XSS variants to succeed.

## Prerequisites

- The target's filters must fail to detect that a character has been doubly encoded but its interpreting engine must still be able to convert a doubly encoded character to an un-encoded character.
- Th

## Mitigations

- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
