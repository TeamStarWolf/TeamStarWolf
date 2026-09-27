# CAPEC-560 — Use of Known Domain Credentials

<a id="capec-560"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

An adversary guesses or obtains (i.e. steals or purchases) legitimate credentials (e.g. userID/password) to achieve authentication and to perform authorized actions under the guise of an authenticated user or service.

## Mapped ATT&CK techniques (1)

- [T1078 — Valid Accounts](/mitre/techniques/T1078.md) — Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

## Related CWE (8)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) — The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) — The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html) — The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html) — The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html) — The product does not have a mechanism in place for managing password aging.
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html) — The product supports password aging, but the expiration period is too long.
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html) — A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted…
- [CWE-1273 — Device Unlock Credential Sharing](https://cwe.mitre.org/data/definitions/1273.html) — The credentials necessary for unlocking a device are shared across multiple parties and may expose sensitive information.

## Prerequisites

- The system/application uses one factor password based authentication, SSO, and/or cloud-based authentication.
- The system/application does not have a sound password policy that is being enforced.
- The system/application does not implement an effective password throttling mechanism.
- The adversary possesses a list of known user accounts and corresponding passwords that may exist on the target.

## Skills required

- [Low] Once an adversary obtains a known credential, leveraging it is trivial.

## Consequences

- Confidentiality, Access Control, Authentication / Gain Privileges
- Confidentiality, Authorization / Read Data
- Integrity / Modify Data

## Mitigations

- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.
- Create a strong password policy and ensure that your system enforces this policy.
- Ensure users are not reusing username/password combinations for multiple systems, applications, or services.
- Do not reuse local administrator account credentials across systems.
- Deny remote use of local admin credentials to log into domain systems.
- Do not allow accounts to be a local administrator on more than one system.
- Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-2.
- Monitor system and domain logs for abnormal credential access.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
