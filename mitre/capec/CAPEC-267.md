# CAPEC-267: Leverage Alternate Encoding

<a id="capec-267"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

An adversary leverages the possibility to encode potentially harmful input or content used by applications such that the applications are ineffective at validating this encoding standard.

## Mapped ATT&CK techniques (1)

- [T1027: Obfuscated Files or Information](/mitre/techniques/T1027.md): Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.

## Related CWE (9)

- [CWE-173: Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html): The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-172: Improper Encoding or Decoding of Data](https://cwe.mitre.org/data/definitions/172.html): The product does not properly encode or decode data, resulting in unexpected values that are not equivalent to the original data.
- [CWE-180: Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html): The product validates input before it is canonicalized.
- [CWE-181: Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html): The product validates data before it has been filtered, which prevents the product from detecting data that becomes invalid after the filtering step.
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html): The product allows user input to control or influence paths or file names that are used in filesystem operations.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-692: Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html): The product uses a denylist-based protection mechanism to defend against XSS attacks, but the denylist is incomplete.

## Prerequisites

- The application's decoder accepts and interprets encoded characters. Data canonicalization, input filtering and validating is not done properly leaving the door open to harmful characters for the target host.

## Skills required

- [Low] An adversary can inject different representation of a filtered character in a different encoding.
- [Medium] An adversary may craft subtle encoding of input data by using the knowledge that they have gathered about the target host.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Authorization / Execute Unauthorized Commands
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism
- Availability / Unreliable Execution, Resource Consumption

## Mitigations

- Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test your decoding process against malicious input.

## Related pages

- [CAPEC-80: Using UTF-8 Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-80.md), also related to CWE-20, CWE-73 and 7 more
- [CAPEC-78: Using Escaped Slashes in Alternate Encoding](/mitre/capec/CAPEC-78.md), also related to CWE-20, CWE-73 and 6 more
- [CAPEC-71: Using Unicode Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-71.md), also related to CWE-20, CWE-74 and 5 more
- [CAPEC-120: Double Encoding](/mitre/capec/CAPEC-120.md), also related to CWE-20, CWE-74 and 5 more
- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20, CWE-74 and 5 more
- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-20, CWE-73 and 5 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
