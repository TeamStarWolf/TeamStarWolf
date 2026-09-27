# CAPEC-253 — Remote Code Inclusion

<a id="capec-253"></a>

**Abstraction:** Standard  
**Status:** Draft  

The attacker forces an application to load arbitrary code files from a remote location. The attacker could use this to try to load old versions of library files that have known vulnerabilities, to load malicious files that the attacker placed on the remote machine, or to otherwise change the functionality of the targeted application in unexpected ways.

## Related CWE (1)

- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) — The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- Target application server must allow remote files to be included.The malicious file must be placed on the remote machine previously.

## Mitigations

- Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
