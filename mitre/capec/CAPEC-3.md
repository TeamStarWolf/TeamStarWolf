# CAPEC-3 — Using Leading 'Ghost' Character Sequences to Bypass Input Filters

<a id="capec-3"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

Some APIs will strip certain leading characters from a string of parameters. An adversary can intentionally introduce leading "ghost" characters (extra characters that don't affect the validity of the request at the API layer) that enable the input to pass the filters and therefore process the adversary's input. This occurs when the targeted API will accept input data in several syntactic forms and interpret it in the equivalent semantic way, while the filter does not take into account the full spectrum of the syntactic forms acceptable to the targeted API.

## Related CWE (12)

- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html) — The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-41 — Improper Resolution of Path Equivalence](https://cwe.mitre.org/data/definitions/41.html) — The product is vulnerable to file system contents disclosure through path equivalence.
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html) — The product does not properly encode or decode the data, resulting in unexpected values.
- [CWE-179 — Incorrect Behavior Order: Early Validation](https://cwe.mitre.org/data/definitions/179.html) — The product validates input before applying protection mechanisms that modify the input, which could allow an attacker to bypass the validation via dangerous inputs that only arise after the modification.
- [CWE-180 — Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html) — The product validates input before it is canonicalized, which prevents the product from detecting data that becomes invalid after the canonicalization step.
- [CWE-181 — Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html) — The product validates data before it has been filtered, which prevents the product from detecting data that becomes invalid after the filtering step.
- [CWE-183 — Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html) — The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are explicitly allowed by policy because the inputs are assumed to be safe, but the list is too permissive - that is, it allows an input that is unsafe, leading to resultant weaknesses.
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html) — The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes place, but the list is incomplete.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html) — The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being read from an upstream component or sent to a downstream component.

## Prerequisites

- The targeted API must ignore the leading ghost characters that are used to get past the filters for the semantics to be the same.

## Skills required

- [Medium] The ability to make an API request, and knowledge of "ghost" characters that will not be filtered by any input validation. These "ghost" characters must be known to not affect the way in which the request will be interpreted.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Integrity / Modify Data

## Mitigations

- Use an allowlist rather than a denylist input validation.
- Canonicalize all data prior to validation.
- Take an iterative approach to input validation (defense in depth).

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
