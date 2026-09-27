# CAPEC-479 — Malicious Root Certificate

<a id="capec-479"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Low

An adversary exploits a weakness in authorization and installs a new root certificate on a compromised system. Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security

## Mapped ATT&CK techniques (1)

- [T1553.004](/mitre/techniques/T1553-004.md)

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have the ability to create a new root certificate.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
