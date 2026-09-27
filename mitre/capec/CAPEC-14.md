# CAPEC-14 — Client-side Injection-induced Buffer Overflow

<a id="capec-14"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

This type of attack exploits a buffer overflow vulnerability in targeted client software through injection of malicious content from a custom-built hostile service. This hostile service is created to deliver the correct content to the client software. For example, if the client-side application is a browser, the service will host a webpage that the browser loads.

## Related CWE (8)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html) — The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html) — The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.
- [CWE-118 — Incorrect Access of Indexable Resource ('Range Error')](https://cwe.mitre.org/data/definitions/118.html) — The product does not restrict or incorrectly restricts operations within the boundaries of a resource that is accessed using an index or pointer, such as memory or files.
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html) — The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html) — The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- The targeted client software communicates with an external server.
- The targeted client software has a buffer overflow vulnerability.

## Skills required

- [Low] To achieve a denial of service, an attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vector.
- [High] Exploiting a buffer overflow to inject malicious code into the stack of a software system or even the heap requires a more in-depth knowledge and higher skill level.

## Consequences

- Confidentiality / Read Data
- Integrity / Modify Data
- Availability / Resource Consumption
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- The client software should not install untrusted code from a non-authenticated server.
- The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers.
- Perform input validation for length of buffer inputs.
- Use a language or compiler that performs automatic bounds checking.
- Use an abstraction library to abstract away risky APIs. Not a complete solution.
- Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.
- Ensure all buffer uses are consistently bounds-checked.
- Use OS-level preventative functionality. Not a complete solution.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
