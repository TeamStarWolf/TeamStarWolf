# CAPEC-13 — Subverting Environment Variable Values

<a id="capec-13"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

The adversary directly or indirectly modifies environment variables used by or controlling the target software. The adversary's goal is to cause the target software to deviate from its expected operation in a manner that benefits the adversary.

## Mapped ATT&CK techniques (3)

- [T1562.003 — Impair Command History Logging](/mitre/techniques/T1562-003.md)
- [T1574.006 — Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md)
- [T1574.007 — Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md)

## Related CWE (8)

- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-15 — External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

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
