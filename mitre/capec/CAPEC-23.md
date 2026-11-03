# CAPEC-23: File Content Injection

<a id="capec-23"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An adversary poisons files with a malicious payload (targeting the file systems accessible by the target software), which may be passed through by standard channels such as via email, and standard web content like PDF and multimedia files. The adversary exploits known vulnerabilities or handling routines in the target processes, in order to exploit the host's trust in executing remote content, including binary files.

## Related CWE (1)

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- The target software must consume files.
- The adversary must have access to modify files that the target software will consume.

## Skills required

- [Medium] How to poison a file with malicious payload that will exploit a vulnerability when the file is opened. The adversary must also know how to place the file onto a system where it will be opened by an unsuspecting party, or force the file to be opened.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Design: Enforce principle of least privilege
- Design: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)
- Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.
- Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.
- Implementation: Virus scanning on host
- Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20
- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-20
- [CAPEC-8: Buffer Overflow in an API Call](/mitre/capec/CAPEC-8.md), also related to CWE-20
- [CAPEC-9: Buffer Overflow in Local Command-Line Utilities](/mitre/capec/CAPEC-9.md), also related to CWE-20
- [CAPEC-10: Buffer Overflow via Environment Variables](/mitre/capec/CAPEC-10.md), also related to CWE-20
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-20
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
