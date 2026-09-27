# D3FEND: Password Authentication

<a id="password-authentication"></a>

**D3FEND tactic:** Harden  
**Digital artifacts:** Password  

Password authentication is a security mechanism used to verify the identity of a user or entity attempting to access a system or resource by requiring the input of a secret string of characters, known as a password, that is associated with the user or entity.

## ATT&CK techniques countered (4)

- [T0812](https://attack.mitre.org/techniques/T0812) — uses
- [T1110.001 — Password Guessing](/mitre/techniques/T1110-001.md) — uses. Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
- [T1110.002 — Password Cracking](/mitre/techniques/T1110-002.md) — uses. Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained.
- [T1110.003 — Password Spraying](/mitre/techniques/T1110-003.md) — uses. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
