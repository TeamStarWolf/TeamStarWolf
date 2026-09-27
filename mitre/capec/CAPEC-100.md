# CAPEC-100 — Overflow Buffers

<a id="capec-100"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

Buffer Overflow attacks target improper or missing bounds checking on buffer operations, typically triggered by input injected by an adversary. As a consequence, an adversary is able to write past the boundaries of allocated buffer regions in memory, causing a program crash or potentially redirection of execution as per the adversaries' choice.

## Related CWE (6)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html) — The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html) — The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary.
- [CWE-131 — Incorrect Calculation of Buffer Size](https://cwe.mitre.org/data/definitions/131.html) — The product does not correctly calculate the size to be used when allocating a buffer, which could lead to a buffer overflow.
- [CWE-129 — Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html) — The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position within the array.
- [CWE-805 — Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html) — The product uses a sequential operation to read or write a buffer, but it uses an incorrect length value that causes it to access memory that is outside of the bounds of the buffer.
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html) — The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.

## Prerequisites

- Targeted software performs buffer operations.
- Targeted software inadequately performs bounds-checking on buffer operations.
- Adversary has the capability to influence the input to buffer operations.

## Skills required

- [Low] In most cases, overflowing a buffer does not require advanced skills beyond the ability to notice an overflow and stuff an input variable with content.
- [High] In cases of directed overflows, where the motive is to divert the flow of the program or application as per the adversaries' bidding, high level skills are required. This may involve detailed knowledge of the target system architecture and kernel.

## Consequences

- Availability / Unreliable Execution
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Use a language or compiler that performs automatic bounds checking.
- Use secure functions not vulnerable to buffer overflow.
- If you have to use dangerous functions, make sure that you do boundary checking.
- Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.
- Use OS-level preventative functionality. Not a complete solution.
- Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
