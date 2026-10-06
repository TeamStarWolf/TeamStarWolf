# CAPEC-135: Format String Injection

<a id="capec-135"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

An adversary includes formatting characters in a string input field on the target application. Most applications assume that users will provide static text and may respond unpredictably to the presence of formatting character. For example, in certain functions of the C programming languages such as printf, the formatting character %s will print the contents of a memory location expecting this location to identify a string and the formatting character %n prints the number of DWORD written in the memory. An adversary can use this to read or write to memory locations or files, or simply to manipulate the value of the resulting text in unexpected ways. Reading or writing memory may result in program crashes and writing memory could result in the execution of arbitrary code if the adversary can write to the program stack.

## Related CWE (3)

- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html): The product uses a function that accepts a format string as an argument, but the format string originates from an external source.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.

## Prerequisites

- The target application must accept a strings as user input, fail to sanitize string formatting characters in the user input, and process this string using functions that interpret string formatting characters.

## Skills required

- [High] In order to discover format string vulnerabilities it takes only low skill, however, converting this discovery into a working exploit requires advanced knowledge on the part of the adversary.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Access Control / Gain Privileges
- Integrity / Execute Unauthorized Commands
- Access Control / Bypass Protection Mechanism

## Mitigations

- Limit the usage of formatting string functions.
- Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
