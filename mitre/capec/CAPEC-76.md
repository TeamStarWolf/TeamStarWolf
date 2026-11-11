# CAPEC-76: Manipulating Web Input to File System Calls

<a id="capec-76"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An attacker manipulates inputs to the target software which the target software passes to file system calls in the OS. The goal is to gain access to, and perhaps modify, areas of the file system that the target software did not intend to be accessible.

## Related CWE (11)

- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html): The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that directory.
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html): The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html): The product allows user input to control or influence paths or file names that are used in filesystem operations.
- [CWE-77: Improper Neutralization of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html): The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html): The product does not properly verify that the source of data or communication is valid.
- [CWE-348: Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html): The product has two different sources of the same data or information, but it uses the source that has less support for verification, is less trusted, or is less resistant to attack.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-272: Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html): The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html): The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html): One or more system settings or configuration elements can be externally controlled by a user.

## Prerequisites

- Program must allow for user controlled variables to be applied directly to the filesystem

## Skills required

- [Low] To identify file system entry point and execute against an over-privileged system interface

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Integrity / Modify Data

## Mitigations

- Design: Enforce principle of least privilege.
- Design: Ensure all input is validated, and does not contain file system commands
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Design: For interactive user applications, consider if direct file system interface is necessary, instead consider having the application proxy communication.
- Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.

## Related pages

- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-15, CWE-73 and 2 more
- [CAPEC-17: Using Malicious Files](/mitre/capec/CAPEC-17.md), also related to CWE-59, CWE-272 and 1 more
- [CAPEC-64: Using Slashes and URL Encoding Combined to Bypass Validation Logic](/mitre/capec/CAPEC-64.md), also related to CWE-22, CWE-73 and 1 more
- [CAPEC-78: Using Escaped Slashes in Alternate Encoding](/mitre/capec/CAPEC-78.md), also related to CWE-22, CWE-73 and 1 more
- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-22, CWE-73 and 1 more
- [CAPEC-35: Leverage Executable Code in Non-Executable Files](/mitre/capec/CAPEC-35.md), also related to CWE-59 and CWE-272
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
