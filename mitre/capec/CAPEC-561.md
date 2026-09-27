# CAPEC-561 — Windows Admin Shares with Stolen Credentials

<a id="capec-561"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary guesses or obtains (i.e. steals or purchases) legitimate Windows administrator credentials (e.g. userID/password) to access Windows Admin Shares on a local machine or within a Windows domain.

## Mapped ATT&CK techniques (1)

- [T1021.002 — SMB/Windows Admin Shares](/mitre/techniques/T1021-002.md) — Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB).

## Related CWE (7)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) — The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html) — The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html) — The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html) — A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the…
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html) — The product supports password aging, but the expiration period is too long.
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html) — The product does not have a mechanism in place for managing password aging.
- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html) — The product does not require that users should have strong passwords.

## Prerequisites

- The system/application is connected to the Windows domain.
- The target administrative share allows remote use of local admin credentials to log into domain systems.
- The adversary possesses a list of known Windows administrator credentials that exist on the target domain.

## Skills required

- [Low] Once an adversary obtains a known Windows credential, leveraging it is trivial.

## Consequences

- Confidentiality, Access Control, Authentication / Gain Privileges
- Confidentiality, Authorization / Read Data
- Integrity / Modify Data

## Mitigations

- Do not reuse local administrator account credentials across systems.
- Deny remote use of local admin credentials to log into domain systems.
- Do not allow accounts to be a local administrator on more than one system.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
