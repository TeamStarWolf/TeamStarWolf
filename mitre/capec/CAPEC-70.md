# CAPEC-70: Try Common or Default Usernames and Passwords

<a id="capec-70"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary may try certain common or default usernames and passwords to gain access into the system and perform unauthorized actions. An adversary may try an intelligent brute force using empty passwords, known vendor default credentials, as well as a dictionary of common usernames and passwords. Many vendor products come preconfigured with default (and thus well-known) usernames and passwords that should be deleted prior to usage in a production environment. It is a common mistake to forget to remove these default login credentials. Another problem is that users would pick very simple (common) passwords (e.g. "secret" or "password") that make it easier for the attacker to gain access to the system compared to using a brute force attack or even a dictionary attack using a full dictionary.

## Mapped ATT&CK techniques (1)

- [T1078.001: Default Accounts](/mitre/techniques/T1078-001.md): Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

## Related CWE (7)

- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html): The product does not require that users should have strong passwords.
- [CWE-262: Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html): The product does not have a mechanism in place for managing password aging.
- [CWE-263: Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html): The product supports password aging, but the expiration period is too long.
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html): The product contains hard-coded credentials, such as a password or cryptographic key.
- [CWE-654: Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html): A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted resources or functionality.
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html): The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309: Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html): The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

## Prerequisites

- The system uses one factor password based authentication.The adversary has the means to interact with the system.

## Skills required

- [Low] An adversary just needs to gain access to common default usernames/passwords specific to the technologies used by the system. Additionally, a brute force attack leveraging common passwords can be easily realized if the user name is known.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Delete all default account credentials that may be put in by the product vendor.
- Implement a password throttling mechanism. This mechanism should take into account both the IP address and the log in name of the user.
- Put together a strong password policy and make sure that all user created passwords comply with it. Alternatively automatically generate strong passwords for users.
- Passwords need to be recycled to prevent aging, that is every once in a while a new password must be chosen.

## Related pages

- [CAPEC-16: Dictionary-based Password Attack](/mitre/capec/CAPEC-16.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-49: Password Brute Forcing](/mitre/capec/CAPEC-49.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-55: Rainbow Table Password Cracking](/mitre/capec/CAPEC-55.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-565: Password Spraying](/mitre/capec/CAPEC-565.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-509: Kerberoasting](/mitre/capec/CAPEC-509.md), also related to CWE-262, CWE-263 and 3 more
- [CAPEC-555: Remote Services with Stolen Credentials](/mitre/capec/CAPEC-555.md), also related to CWE-262, CWE-263 and 3 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study](/case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [Stuxnet: The Case Study](/case-studies/STUXNET.md)
- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)
- [The Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769): A Case Study](/case-studies/DELL_RECOVERPOINT_CVE_2026_22769.md)
- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
