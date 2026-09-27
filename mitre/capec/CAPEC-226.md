# CAPEC-226 — Session Credential Falsification through Manipulation

<a id="capec-226"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker manipulates an existing credential in order to gain access to a target application. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. An attacker may be able to manipulate a credential sniffed from an existing connection in order to gain access to a target server.

## Related CWE (2)

- [CWE-565 — Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html) — The product relies on the existence or values of cookies when performing security-critical operations, but it does not properly ensure that the setting is valid for the associated user.
- [CWE-472 — External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html) — The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields.

## Prerequisites

- The targeted application must use session credentials to identify legitimate users.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
