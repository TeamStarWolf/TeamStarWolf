# D3FEND: One-time Password

<a id="one-time-password"></a>

D3FEND tactic: Harden  
Digital artifacts: Password  

A one-time password is valid for only one user authentication.

## ATT&CK techniques countered (4)

- [T1110.001: Password Guessing](/mitre/techniques/T1110-001.md): use-limits. Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
- [T1110.002: Password Cracking](/mitre/techniques/T1110-002.md): use-limits. Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): use-limits. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1694.001: Default Credentials](https://attack.mitre.org/techniques/T1694/001): use-limits (D3FEND maps the revoked predecessor T0812)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
