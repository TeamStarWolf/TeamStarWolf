# CAPEC-479 — Malicious Root Certificate

<a id="capec-479"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Stable  

An adversary exploits a weakness in authorization and installs a new root certificate on a compromised system. Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website. Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials.

## Mapped ATT&CK techniques (1)

- [T1553.004 — Install Root Certificate](/mitre/techniques/T1553-004.md) — Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.

## Related CWE (1)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) — The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Prerequisites

- The adversary must have the ability to create a new root certificate.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
