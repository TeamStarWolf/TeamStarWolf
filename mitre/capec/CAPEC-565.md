# CAPEC-565: Password Spraying

<a id="capec-565"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

In a Password Spraying attack, an adversary tries a small list (e.g. 3-5) of common or expected passwords, often matching the target's complexity policy, against a known list of user accounts to gain valid credentials. The adversary tries a particular password for each user account, before moving onto the next password in the list. This approach assists the adversary in remaining undetected by avoiding rapid or frequent account lockouts. The adversary may then reattempt the process with additional passwords, once enough time has passed to prevent inducing a lockout.

## Mapped ATT&CK techniques (1)

- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.

## Related CWE (7)

- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html): The product does not require that users should have strong passwords.
- [CWE-262: Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html): The product does not have a mechanism in place for managing password aging.
- [CWE-263: Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html): The product supports password aging, but the expiration period is too long.
- [CWE-654: Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html): A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted resources or functionality.
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html): The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html): The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309: Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html): The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

## Prerequisites

- The system/application uses one factor password based authentication.
- The system/application does not have a sound password policy that is being enforced.
- The system/application does not implement an effective password throttling mechanism.
- The adversary possesses a list of known user accounts on the target system/application.

## Skills required

- [Low] A Password Spraying attack is very straightforward. A variety of password cracking tools are widely available.

## Consequences

- Confidentiality, Access Control, Authentication / Gain Privileges
- Confidentiality, Authorization / Read Data
- Integrity / Modify Data

## Mitigations

- Create a strong password policy and ensure that your system enforces this policy.
- Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-2.
- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.

## Related pages

- [CAPEC-16: Dictionary-based Password Attack](/mitre/capec/CAPEC-16.md), also related to CWE-262, CWE-263 and 5 more
- [CAPEC-49: Password Brute Forcing](/mitre/capec/CAPEC-49.md), also related to CWE-262, CWE-263 and 5 more
- [CAPEC-560: Use of Known Domain Credentials](/mitre/capec/CAPEC-560.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-600: Credential Stuffing](/mitre/capec/CAPEC-600.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-652: Use of Known Kerberos Credentials](/mitre/capec/CAPEC-652.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-653: Use of Known Operating System Credentials](/mitre/capec/CAPEC-653.md), also related to CWE-262, CWE-263 and 4 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md)
- [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
