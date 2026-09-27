# CAPEC-76 — Manipulating Web Input to File System Calls

<a id="capec-76"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attacker manipulates inputs to the target software which the target software passes to file system calls in the OS. The goal is to gain access to, and perhaps modify, areas of the file system that the target software did not intend to be accessible.

## Related CWE (11)

- [CWE-23 — Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html) — The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ..
- [CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html) — The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special…
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html) — The product allows user input to control or influence paths or file names that are used in filesystem operations.
- [CWE-77 — Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html) — The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command…
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-348 — Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html) — The product has two different sources of the same data or information, but it uses the source that has less support for verification, is less trusted, or is less resistant to attack.
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-272 — Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html) — The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.
- [CWE-59 — Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html) — The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-15 — External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html) — One or more system settings or configuration elements can be externally controlled by a user.

## Prerequisites

- Program must allow for user controlled variables to be applied directly to the filesystem

## Skills required

- To identify file system entry point and execute against an over-privileged system interface:LEVEL:Low

## Mitigations

- Design: Enforce principle of least privilege.
- Design: Ensure all input is validated, and does not contain file system commands
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
