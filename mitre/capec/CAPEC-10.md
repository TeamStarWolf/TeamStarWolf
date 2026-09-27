# CAPEC-10 — Buffer Overflow via Environment Variables

<a id="capec-10"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack pattern involves causing a buffer overflow through manipulation of environment variables. Once the adversary finds that they can modify an environment variable, they may try to overflow associated buffers. This attack leverages implicit trust often placed in environment variables.

## Related CWE (10)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html) — The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html) — The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.
- [CWE-118 — Incorrect Access of Indexable Resource ('Range Error')](https://cwe.mitre.org/data/definitions/118.html) — The product does not restrict or incorrectly restricts operations within the boundaries of a resource that is accessed using an index or pointer, such as memory or files.
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html) — The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-99 — Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html) — The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html) — The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.
- [CWE-733 — Compiler Optimization Removal or Modification of Security-critical Code](https://cwe.mitre.org/data/definitions/733.html) — The developer builds a security-critical protection mechanism into the software, but the compiler optimizes the program such that the mechanism is removed or modified.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- The application uses environment variables.
- An environment variable exposed to the user is vulnerable to a buffer overflow.
- The vulnerable environment variable uses untrusted data.
- Tainted data used in the environment variables is not properly validated. For instance boundary checking is not done before copying the input data to a buffer.

## Skills required

- [Low] An attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vector. The result can be a DoS.
- [High] Exploiting a buffer overflow to inject malicious code into the stack of a software system or even the heap can require a higher skill level.

## Consequences

- Availability / Unreliable Execution
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality / Read Data
- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Do not expose environment variable to the user.
- Do not use untrusted data in your environment variables.
- Use a language or compiler that performs automatic bounds checking
- There are tools such as Sharefuzz [REF-2] which is an environment variable fuzzer for Unix that support loading a shared library. You can use Sharefuzz to determine if you are exposing an environment variable vulnerable to buffer overflow.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
