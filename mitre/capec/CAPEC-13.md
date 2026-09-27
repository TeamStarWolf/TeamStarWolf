# CAPEC-13 — Subverting Environment Variable Values

<a id="capec-13"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

The adversary directly or indirectly modifies environment variables used by or controlling the target software. The adversary's goal is to cause the target software to deviate from its expected operation in a manner that benefits the adversary.

## Mapped ATT&CK techniques (3)

- [T1562.003 — Impair Command History Logging](/mitre/techniques/T1562-003.md) — Adversaries may impair command history logging to hide commands they run on a compromised system.
- [T1574.006 — Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md) — Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries.
- [T1574.007 — Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md) — Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries.

## Related CWE (8)

- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html) — The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html) — The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-15 — External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html) — One or more system settings or configuration elements can be externally controlled by a user.
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html) — The product allows user input to control or influence paths or file names that are used in filesystem operations.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- An environment variable is accessible to the user.
- An environment variable used by the application can be tainted with user supplied data.
- Input data used in an environment variable is not validat

## Skills required

- In a web based scenario, the client controls the data that it submitted to the server. So anybody can try to send malicious data and try to by

## Mitigations

- Protect environment variables against unauthorized read and write access.
- Protect the configuration files which contain environment variables against illegitimate read and write access.
- Assume all input is malicious. Create an allowlist that defi

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
