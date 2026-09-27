# CAPEC-60 — Reusing Session IDs (aka Session Replay)

<a id="capec-60"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.

## Mapped ATT&CK techniques (2)

- [T1134.001 — Token Impersonation/Theft](/mitre/techniques/T1134-001.md)
- [T1550.004 — Web Session Cookie](/mitre/techniques/T1550-004.md)

## Related CWE (10)

- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-384 — Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-488 — Exposure of Data Element to Wrong Session](https://cwe.mitre.org/data/definitions/488.html)
- [CWE-539 — Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-664 — Improper Control of a Resource Through its Lifetime](https://cwe.mitre.org/data/definitions/664.html)
- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

## Prerequisites

- The target host uses session IDs to keep track of the users.
- Session IDs are used to control access to resources.
- The session IDs used by the target host are not well protected from session theft.

## Skills required

- If an attacker can steal a valid session ID, they can then try to be authenticated with that stolen session ID.:LEVEL:Low
- More sophisti

## Mitigations

- Always invalidate a session ID after the user logout.
- Setup a session time out for the session IDs.
- Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate adversary in the middle attacks (

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
