# CAPEC-44: Overflow Binary Resource File

<a id="capec-44"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An attack of this type exploits a buffer overflow vulnerability in the handling of binary resources. Binary resources may include music files like MP3, image files like JPEG files, and any other binary file. These attacks may pass unnoticed to the client machine through normal usage of files, such as a browser loading a seemingly innocent JPEG file. This can allow the adversary access to the execution stack and execute arbitrary code in the target process.

## Related CWE (3)

- [CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html): The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html): The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- Target software processes binary resource files.
- Target software contains a buffer overflow vulnerability reachable through input from a user-controllable binary resource file.

## Skills required

- [Medium] To modify file, deceive client into downloading, locate and exploit remote stack or heap vulnerability

## Consequences

- Availability / Unreliable Execution
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Perform appropriate bounds checking on all buffers.
- Design: Enforce principle of least privilege
- Design: Static code analysis
- Implementation: Execute program in less trusted process space environment, do not allow lower integrity processes to write to higher integrity processes
- Implementation: Keep software patched to ensure that known vulnerabilities are not available for adversaries to target on host.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
