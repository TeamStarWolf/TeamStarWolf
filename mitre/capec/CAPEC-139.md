# CAPEC-139: Relative Path Traversal

<a id="capec-139"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attacker exploits a weakness in input validation on the target by supplying a specially constructed path utilizing dot and slash characters for the purpose of obtaining access to arbitrary files or resources. An attacker modifies a known path on the target in order to reach material that is not available through intended channels. These attacks normally involve adding additional path separators (/ or \) and/or dots (.), or encodings thereof, in various combinations in order to reach parent directories or entirely separate trees of the target's directory structure.

## Related CWE (1)

- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html): The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ..

## Prerequisites

- The target application must accept a string as user input, fail to sanitize combinations of characters in the input that have a special meaning in the context of path navigation, and insert the user-supplied string into path navigation commands.

## Skills required

- [Low] To inject the malicious payload in a web page
- [High] To bypass non trivial filters in the application

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Access Control / Bypass Protection Mechanism
- Availability / Unreliable Execution

## Mitigations

- Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement
- Implementation: Perform input validation for all remote content, including remote and user-generated content.
- Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- using an allowlist approach.
- Implementation: Prefer working without user input when using file system calls
- Implementation: Use indirect references rather than actual file names.
- Implementation: Use possible permissions on file access when developing and deploying web applications.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
