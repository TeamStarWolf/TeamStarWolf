# CAPEC-652 — Use of Known Kerberos Credentials

<a id="capec-652"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary obtains (i.e. steals or purchases) legitimate Kerberos credentials (e.g. Kerberos service account userID/password or Kerberos Tickets) with the goal of achieving authenticated access to additional systems, applications, or services within the domain.

## Mapped ATT&CK techniques (1)

- [T1558 — Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md) — Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket.

## Related CWE (9)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) — The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) — The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html) — The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html) — The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html) — The product does not have a mechanism in place for managing password aging.
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html) — The product supports password aging, but the expiration period is too long.
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html) — A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted…
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html) — A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the…
- [CWE-836 — Use of Password Hash Instead of Password for Authentication](https://cwe.mitre.org/data/definitions/836.html) — The product records password hashes in a data store, receives a hash of a password from a client, and compares the supplied hash to the hash obtained from the data store.

## Prerequisites

- The system/application leverages Kerberos authentication.
- The system/application uses one factor password-based authentication, SSO, and/or cloud-based authentication for Kerberos service accounts.
- The system/application does not have a sound password policy that is being enforced for Kerberos service accounts.
- The system/application does not implement an effective password throttling mechanism for authenticating to Kerberos service accounts.
- The targeted network allows for network sniffing attacks to succeed.

## Skills required

- [Low] Once an adversary obtains a known Kerberos credential, leveraging it is trivial.

## Consequences

- Confidentiality, Access Control, Authentication / Gain Privileges
- Confidentiality, Authorization / Read Data
- Integrity / Modify Data

## Mitigations

- Create a strong password policy and ensure that your system enforces this policy for Kerberos service accounts.
- Ensure Kerberos service accounts are not reusing username/password combinations for multiple systems, applications, or services.
- Do not reuse Kerberos service account credentials across systems.
- Deny remote use of Kerberos service account credentials to log into domain systems.
- Do not allow Kerberos service accounts to be a local administrator on more than one system.
- Enable at least AES Kerberos encryption for tickets.
- Monitor system and domain logs for abnormal credential access.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
