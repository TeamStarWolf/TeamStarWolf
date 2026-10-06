# CAPEC-240: Resource Injection

<a id="capec-240"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: High  
Status: Stable  

An adversary exploits weaknesses in input validation by manipulating resource identifiers enabling the unintended modification or specification of a resource.

## Related CWE (1)

- [CWE-99: Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html): The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.

## Prerequisites

- The target application allows the user to both specify the identifier used to access a system resource. Through this permission, the user gains the capability to perform actions on that resource (e.g., overwrite the file)

## Consequences

- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Ensure all input content that is delivered to client is sanitized against an acceptable content specification.
- Perform input validation for all content.
- Enforce regular patching of software.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
