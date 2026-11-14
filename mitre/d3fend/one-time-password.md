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

## Related pages

- [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md), which also counters 4 of these techniques
- [Change Default Password](/mitre/d3fend/change-default-password.md), which also counters 4 of these techniques
- [Credential Compromise Scope Analysis](/mitre/d3fend/credential-compromise-scope-analysis.md), which also counters 4 of these techniques
- [Credential Hardening](/mitre/d3fend/credential-hardening.md), which also counters 4 of these techniques
- [Credential Revocation](/mitre/d3fend/credential-revocation.md), which also counters 4 of these techniques
- [Credential Rotation](/mitre/d3fend/credential-rotation.md), which also counters 4 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)
- [The Year 2011 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2011.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
