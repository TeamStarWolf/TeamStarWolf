# CAPEC-226 — Session Credential Falsification through Manipulation

<a id="capec-226"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An attacker manipulates an existing credential in order to gain access to a target application. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. An attacker may be able to manipulate a credential sniffed from an existing connection in ord

## Related CWE (2)

[CWE-565](/CWE_REFERENCE.md) [CWE-472](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application must use session credentials to identify legitimate users.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
