# CAPEC-75: Manipulating Writeable Configuration Files

<a id="capec-75"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

Generally these are manually edited files that are not in the preview of the system administrators, any ability on the attackers' behalf to modify these files, for example in a CVS repository, gives unauthorized access directly to the application, the same as authorized users.

## Related CWE (6)

- [CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data](https://cwe.mitre.org/data/definitions/349.html): The product, when processing trusted data, accepts any untrusted data that is also included with the trusted data, treating the untrusted data as if it were trusted.
- [CWE-99: Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html): The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.
- [CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html): The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html): The product does not properly verify that the source of data or communication is valid.
- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html): The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.
- [CWE-354: Improper Validation of Integrity Check Value](https://cwe.mitre.org/data/definitions/354.html): The product does not validate or incorrectly validates the integrity check values or checksums of a message.

## Prerequisites

- Configuration files must be modifiable by the attacker

## Skills required

- [Medium] To identify vulnerable configuration files, and understand how to manipulate servers and erase forensic evidence

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Design: Enforce principle of least privilege
- Design: Backup copies of all configuration files
- Implementation: Integrity monitoring for configuration files
- Implementation: Enforce audit logging on code and configuration promotion procedures.
- Implementation: Load configuration from separate process and memory space, for example a separate physical device like a CD

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
