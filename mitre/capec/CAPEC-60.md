# CAPEC-60 — Reusing Session IDs (aka Session Replay)

<a id="capec-60"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.

## Mapped ATT&CK techniques (2)

- [T1134.001 — Token Impersonation/Theft](/mitre/techniques/T1134-001.md) — Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls.
- [T1550.004 — Web Session Cookie](/mitre/techniques/T1550-004.md) — Adversaries can use stolen session cookies to authenticate to web applications and services.

## Related CWE (10)

- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html) — A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the…
- [CWE-290 — Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) — This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-384 — Session Fixation](https://cwe.mitre.org/data/definitions/384.html) — Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.
- [CWE-488 — Exposure of Data Element to Wrong Session](https://cwe.mitre.org/data/definitions/488.html) — The product does not sufficiently enforce boundaries between the states of different sessions, causing data to be provided to, or used by, the wrong session.
- [CWE-539 — Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html) — The web application uses persistent cookies, but the cookies contain sensitive information.
- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-664 — Improper Control of a Resource Through its Lifetime](https://cwe.mitre.org/data/definitions/664.html) — The product does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation, use, and release.
- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html) — The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.

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
