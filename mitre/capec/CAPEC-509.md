# CAPEC-509: Kerberoasting

<a id="capec-509"></a>

Abstraction: Detailed  
Typical severity: High  
Status: Stable  

Through the exploitation of how service accounts leverage Kerberos authentication with Service Principal Names (SPNs), the adversary obtains and subsequently cracks the hashed credentials of a service account target to exploit its privileges. The Kerberos authentication protocol centers around a ticketing system which is used to request/grant access to services and to then access the requested services. As an authenticated user, the adversary may request Active Directory and obtain a service ticket with portions encrypted via RC4 with the private key of the authenticated account. By extracting the local ticket and saving it disk, the adversary can brute force the hashed value to reveal the target account credentials.

## Mapped ATT&CK techniques (1)

- [T1558.003: Kerberoasting](/mitre/techniques/T1558-003.md): Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110).

## Related CWE (7)

- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html): The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html): The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309: Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html): The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.
- [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html): A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the original message (or with minor changes).
- [CWE-263: Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html): The product supports password aging, but the expiration period is too long.
- [CWE-262: Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html): The product does not have a mechanism in place for managing password aging.
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html): The product does not require that users should have strong passwords.

## Prerequisites

- The adversary requires access as an authenticated user on the system. This attack pattern relates to elevating privileges.
- The adversary requires use of a third-party credential harvesting tool (e.g., Mimikatz).
- The adversary requires a brute force tool.

## Skills required

- [Medium]

## Consequences

- Confidentiality / Gain Privileges

## Mitigations

- Monitor system and domain logs for abnormal access.
- Employ a robust password policy for service accounts. Passwords should be of adequate length and complexity, and they should expire after a period of time.
- Employ the principle of least privilege: limit service accounts privileges to what is required for functionality and no more.
- Enable AES Kerberos encryption (or another stronger encryption algorithm), rather than RC4, where possible.

## Related pages

- [CAPEC-555: Remote Services with Stolen Credentials](/mitre/capec/CAPEC-555.md), also related to CWE-262, CWE-263 and 5 more
- [CAPEC-561: Windows Admin Shares with Stolen Credentials](/mitre/capec/CAPEC-561.md), also related to CWE-262, CWE-263 and 5 more
- [CAPEC-652: Use of Known Kerberos Credentials](/mitre/capec/CAPEC-652.md), also related to CWE-262, CWE-263 and 4 more
- [CAPEC-16: Dictionary-based Password Attack](/mitre/capec/CAPEC-16.md), also related to CWE-262, CWE-263 and 3 more
- [CAPEC-49: Password Brute Forcing](/mitre/capec/CAPEC-49.md), also related to CWE-262, CWE-263 and 3 more
- [CAPEC-55: Rainbow Table Password Cracking](/mitre/capec/CAPEC-55.md), also related to CWE-262, CWE-263 and 3 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
