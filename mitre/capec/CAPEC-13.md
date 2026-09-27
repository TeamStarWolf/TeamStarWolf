# CAPEC-13 — Subverting Environment Variable Values

<a id="capec-13"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

The adversary directly or indirectly modifies environment variables used by or controlling the target software. The adversary's goal is to cause the target software to deviate from its expected operation in a manner that benefits the adversary.

## Mapped ATT&CK techniques (3)

- [T1562.003](/mitre/techniques/T1562-003.md)
- [T1574.006](/mitre/techniques/T1574-006.md)
- [T1574.007](/mitre/techniques/T1574-007.md)

## Related CWE (8)

[CWE-353](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-302](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-15](/CWE_REFERENCE.md) [CWE-73](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::An environment variable is accessible to the user.::An environment variable used by the application can be tainted with user supplied data.::Input data used in an environment variable is not validat

**Skills required:** ::SKILL:In a web based scenario, the client controls the data that it submitted to the server. So anybody can try to send malicious data and try to by

**Mitigations:** ::Protect environment variables against unauthorized read and write access.::Protect the configuration files which contain environment variables against illegitimate read and write access.::Assume all input is malicious. Create an allowlist that defi


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
