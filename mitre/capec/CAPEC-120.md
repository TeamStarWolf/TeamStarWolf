# CAPEC-120: Double Encoding

<a id="capec-120"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: Low  
Status: Draft  

The adversary utilizes a repeating of the encoding process for a set of characters (that is, character encoding a character encoding of a character) to obfuscate the payload of a particular request. This may allow the adversary to bypass filters that attempt to detect illegal characters or strings, such as those that might be used in traversal or injection attacks. Filters may be able to catch illegal encoded strings, but may not catch doubly encoded strings. For example, a dot (.), often used in path traversal attacks and therefore often blocked by filters, could be URL encoded as %2E. However, many filters recognize this encoding and would still block the request. In a double encoding, the % in the above URL encoding would be encoded again as %25, resulting in %252E which some filters might not catch, but which could still be interpreted as a dot (.) by interpreters on the target.

## Related CWE (10)

- [CWE-173: Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html): The product does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.
- [CWE-172: Improper Encoding or Decoding of Data](https://cwe.mitre.org/data/definitions/172.html): The product does not properly encode or decode data, resulting in unexpected values that are not equivalent to the original data.
- [CWE-177: Improper Handling of URL Encoding (Hex Encoding)](https://cwe.mitre.org/data/definitions/177.html): The product does not properly handle when all or part of an input has been URL encoded.
- [CWE-181: Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html): The product validates data before it has been filtered, which prevents the product from detecting data that becomes invalid after the filtering step.
- [CWE-183: Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html): The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are explicitly allowed by policy because the inputs are assumed to be safe, but the list is too permissive - that is, it allows an input that is unsafe, leading to resultant weaknesses.
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html): The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes place, but the list is incomplete.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-692: Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html): The product uses a denylist-based protection mechanism to defend against XSS attacks, but the denylist is incomplete.

## Prerequisites

- The target's filters must fail to detect that a character has been doubly encoded but its interpreting engine must still be able to convert a doubly encoded character to an un-encoded character.
- The application accepts and decodes URL string request.
- The application performs insufficient filtering/canonicalization on the URLs.

## Mitigations

- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. Input that does not match against the allowlist should not be permitted to enter into the system. Test your decoding process against malicious input.
- Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding.
- When client input is required from web-based forms, avoid using the "GET" method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the "POST method whenever possible.
- Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.
- Refer to the RFCs to safely decode URL.
- Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive.
- There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20, CWE-74 and 6 more
- [CAPEC-71: Using Unicode Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-71.md), also related to CWE-20, CWE-74 and 6 more
- [CAPEC-80: Using UTF-8 Encoding to Bypass Validation Logic](/mitre/capec/CAPEC-80.md), also related to CWE-20, CWE-74 and 5 more
- [CAPEC-267: Leverage Alternate Encoding](/mitre/capec/CAPEC-267.md), also related to CWE-20, CWE-74 and 5 more
- [CAPEC-43: Exploiting Multiple Input Interpretation Layers](/mitre/capec/CAPEC-43.md), also related to CWE-20, CWE-74 and 4 more
- [CAPEC-64: Using Slashes and URL Encoding Combined to Bypass Validation Logic](/mitre/capec/CAPEC-64.md), also related to CWE-20, CWE-74 and 4 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
