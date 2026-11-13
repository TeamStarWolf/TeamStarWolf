# CAPEC-71: Using Unicode Encoding to Bypass Validation Logic

<a id="capec-71"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An attacker may provide a Unicode string to a system component that is not Unicode aware and use that to circumvent the filter or cause the classifying mechanism to fail to properly understanding the request. That may allow the attacker to slip malicious data past the content filter and/or possibly cause the application to route the request incorrectly.

## Related CWE (11)

- [CWE-176: Improper Handling of Unicode Encoding](https://cwe.mitre.org/data/definitions/176.html): The product does not properly handle when an input contains Unicode encoding.
- [CWE-179: Incorrect Behavior Order: Early Validation](https://cwe.mitre.org/data/definitions/179.html): The product validates input before applying protection mechanisms that modify the input.
- [CWE-180: Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html): The product validates input before it is canonicalized.
- [CWE-173: Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html): The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-172: Improper Encoding or Decoding of Data](https://cwe.mitre.org/data/definitions/172.html): The product does not properly encode or decode data, resulting in unexpected values that are not equivalent to the original data.
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html): The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes place, but the list is incomplete.
- [CWE-183: Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html): The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are explicitly allowed by policy because the inputs are assumed to be safe, but the list is too permissive - that is, it allows an input that is unsafe, leading to resultant weaknesses.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-692: Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html): The product uses a denylist-based protection mechanism to defend against XSS attacks, but the denylist is incomplete.

## Prerequisites

- Filtering is performed on data that has not be properly canonicalized.

## Skills required

- [Medium] An attacker needs to understand Unicode encodings and have an idea (or be able to find out) what system components may not be Unicode aware.

## Consequences

- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data
- Availability / Unreliable Execution

## Mitigations

- Ensure that the system is Unicode aware and can properly process Unicode data. Do not make an assumption that data will be in ASCII.
- Ensure that filtering or input validation is applied to canonical data.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system.

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20, CWE-74 and 7 more
- [CAPEC-120: Double Encoding](/mitre/capec/CAPEC-120.md), also related to CWE-20, CWE-74 and 6 more
- [CAPEC-80: Using UTF-8 Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-80.md), also related to CWE-20, CWE-74 and 5 more
- [CAPEC-267: Leverage Alternate Encoding](/mitre/capec/CAPEC-267.md), also related to CWE-20, CWE-74 and 5 more
- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-20, CWE-74 and 4 more
- [CAPEC-78: Using Escaped Slashes in Alternate Encoding](/mitre/capec/CAPEC-78.md), also related to CWE-20, CWE-74 and 4 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The Year 2000 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2000.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
