# CAPEC-597: Absolute Path Traversal

<a id="capec-597"></a>

Abstraction: Detailed  
Status: Draft  

An adversary with access to file system resources, either directly or via application logic, will use various file absolute paths and navigation mechanisms such as ".." to extend their range of access to inappropriate areas of the file system. The goal of the adversary is to access directories and files that are intended to be restricted from their access.

## Related CWE (1)

- [CWE-36: Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html): The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as /abs/path that can resolve to a location that is outside of that directory.

## Prerequisites

- The target must leverage and access an underlying file system.

## Skills required

- [Low] Simple command line attacks.
- [Medium] Programming attacks.

## Consequences

- Integrity, Confidentiality, Availability / Execute Unauthorized Commands
- Integrity / Modify Data
- Confidentiality / Read Data
- Availability / Unreliable Execution

## Mitigations

- Design: Configure the access control correctly.
- Design: Enforce principle of least privilege.
- Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.
- Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement.
- Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.
- Implementation: Perform input validation for all remote content, including remote and user-generated content.
- Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.
- Implementation: Use indirect references rather than actual file names.
- Implementation: Use possible permissions on file access when developing and deploying web applications.
- Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification using an allowlist approach.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
