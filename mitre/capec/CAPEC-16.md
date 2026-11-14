# CAPEC-16: Dictionary-based Password Attack

<a id="capec-16"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An attacker tries each of the words in a dictionary as passwords to gain access to the system via some user's account. If the password chosen by the user was a word within the dictionary, this attack will be successful (in the absence of other mitigations). This is a specific instance of the password brute forcing attack pattern. Dictionary Attacks differ from similar attacks such as Password Spraying (CAPEC-565) and Credential Stuffing (CAPEC-600), since they leverage unknown username/password combinations and don't care about inducing account lockouts.

## Related CWE (7)

- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html): The product does not require that users should have strong passwords.
- [CWE-262: Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html): The product does not have a mechanism in place for managing password aging.
- [CWE-263: Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html): The product supports password aging, but the expiration period is too long.
- [CWE-654: Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html): A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted resources or functionality.
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html): The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html): The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309: Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html): The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

## Prerequisites

- The system uses one factor password based authentication.
- The system does not have a sound password policy that is being enforced.
- The system does not implement an effective password throttling mechanism.

## Skills required

- [Low] A variety of password cracking tools and dictionaries are available to launch this type of an attack.

## Consequences

- Confidentiality, Access Control, Authentication / Gain Privileges
- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Create a strong password policy and ensure that your system enforces this policy.
- Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-2.
- Leverage multi-factor authentication for all authentication services.

## Related pages

- [CAPEC-565: Password Spraying](/mitre/capec/CAPEC-565.md), named in the description above
- [CAPEC-600: Credential Stuffing](/mitre/capec/CAPEC-600.md), named in the description above
- [CAPEC-49: Password Brute Forcing](/mitre/capec/CAPEC-49.md), also related to CWE-262, CWE-263 and 5 more
- [CAPEC-560: Use of Known Domain Credentials](/mitre/capec/CAPEC-560.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-652: Use of Known Kerberos Credentials](/mitre/capec/CAPEC-652.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-653: Use of Known Operating System Credentials](/mitre/capec/CAPEC-653.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-55: Rainbow Table Password Cracking](/mitre/capec/CAPEC-55.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-70: Try Common or Default Usernames and Passwords](/mitre/capec/CAPEC-70.md), also related to CWE-262, CWE-263 and 4 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Water and Wastewater Networks: The Control Systems, the Chemistry and the Attacks on Them](/case-studies/WATER_TREATMENT_NETWORKS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
