# CAPEC-59 — Session Credential Falsification through Prediction

<a id="capec-59"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.

## Related CWE (11)

- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [CWE-330 — Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-331 — Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-488 — Exposure of Data Element to Wrong Session](https://cwe.mitre.org/data/definitions/488.html)
- [CWE-539 — Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-6 — J2EE Misconfiguration: Insufficient Session-ID Length](https://cwe.mitre.org/data/definitions/6.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-384 — Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Prerequisites

- The target host uses session IDs to keep track of the users.
- Session IDs are used to control access to resources.
- The session IDs used by the target host are predictable. For example, the session

## Skills required

- There are tools to brute force session ID. Those tools require a low level of knowledge.:LEVEL:Low
- Predicting Session ID may require mo

## Mitigations

- Use a strong source of randomness to generate a session ID.
- Use adequate length session IDs
- Do not use information available to the user in order to generate session ID (e.g., time).
- Ideas for creating random numbers are offered by Eastlake [RFC

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
