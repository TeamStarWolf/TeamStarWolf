# CAPEC-53 — Postfix, Null Terminate, and Backslash

<a id="capec-53"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

If a string is passed through a filter of some kind, then a terminal NULL may not be valid. Using alternate representation of NULL allows an adversary to embed the NULL mid-string while postfixing the proper data so that the filter is avoided. One example is a filter that looks for a trailing slash character. If a string insertion is possible, but the slash must exist, an alternate encoding of NULL in mid-string may be used.

## Related CWE (7)

- [CWE-158 — Improper Neutralization of Null Byte or NUL Character](https://cwe.mitre.org/data/definitions/158.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes NUL characters or null bytes when they are sent to a downstream component.
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html) — The product does not properly encode or decode the data, resulting in unexpected values.
- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html) — The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html) — The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being read from an upstream component or sent to a downstream component.

## Prerequisites

- Null terminators are not properly handled by the filter.

## Skills required

- [Medium] An adversary needs to understand alternate encodings, what the filter looks for and the data format acceptable to the target API

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Properly handle Null characters. Make sure canonicalization is properly applied. Do not pass Null characters to the underlying APIs.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
