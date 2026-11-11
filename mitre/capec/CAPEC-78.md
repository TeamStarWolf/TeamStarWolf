# CAPEC-78: Using Escaped Slashes in Alternate Encoding

<a id="capec-78"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

This attack targets the use of the backslash in alternate encoding. An adversary can provide a backslash as a leading character and causes a parser to believe that the next character is special. This is called an escape. By using that trick, the adversary tries to exploit alternate ways to encode the same character which leads to filter problems and opens avenues to attack.

## Related CWE (10)

- [CWE-180: Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html): The product validates input before it is canonicalized.
- [CWE-181: Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html): The product validates data before it has been filtered, which prevents the product from detecting data that becomes invalid after the filtering step.
- [CWE-173: Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html): The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-172: Improper Encoding or Decoding of Data](https://cwe.mitre.org/data/definitions/172.html): The product does not properly encode or decode data, resulting in unexpected values that are not equivalent to the original data.
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html): The product allows user input to control or influence paths or file names that are used in filesystem operations.
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html): The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-707: Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html): The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being used when received from an upstream component, or before being sent to a downstream component.

## Prerequisites

- The application accepts the backlash character as escape character.
- The application server does incomplete input data decoding, filtering and validation.

## Skills required

- [Low] The adversary can naively try backslash character and discover that the target host uses it as escape character.
- [Medium] The adversary may need deep understanding of the host target in order to exploit the vulnerability. The adversary may also use automated tools to probe for this vulnerability.

## Consequences

- Confidentiality / Read Data
- Availability / Resource Consumption
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Verify that the user-supplied data does not use backslash character to escape malicious characters.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system.
- Be aware of the threat of alternative method of data encoding.
- Regular expressions can be used to filter out backslash. Make sure you decode before filtering and validating the untrusted input data.
- In the case of path traversals, use the principle of least privilege when determining access rights to file systems. Do not allow users to access directories/files that they should not access.
- Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.
- Avoid making decisions based on names of resources (e.g. files) if those resources can have alternate names.

## Related pages

- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-20, CWE-22 and 7 more
- [CAPEC-64: Using Slashes and URL Encoding Combined to Bypass Validation Logic](/mitre/capec/CAPEC-64.md), also related to CWE-20, CWE-22 and 6 more
- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20, CWE-74 and 6 more
- [CAPEC-80: Using UTF-8 Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-80.md), also related to CWE-20, CWE-73 and 6 more
- [CAPEC-267: Leverage Alternate Encoding](/mitre/capec/CAPEC-267.md), also related to CWE-20, CWE-73 and 6 more
- [CAPEC-71: Using Unicode Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-71.md), also related to CWE-20, CWE-74 and 4 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
