# CAPEC-644: Use of Captured Hashes (Pass The Hash)

<a id="capec-644"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary obtains (i.e. steals or purchases) legitimate Windows domain credential hash values to access systems within the domain that leverage the Lan Man (LM) and/or NT Lan Man (NTLM) authentication protocols.

## Mapped ATT&CK techniques (1)

- [T1550.002: Pass the Hash](/mitre/techniques/T1550-002.md): Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls.

## Related CWE (5)

- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html): The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.
- [CWE-836: Use of Password Hash Instead of Password for Authentication](https://cwe.mitre.org/data/definitions/836.html): The product includes a client that computes a hash of a password and sends the hash to another component, which compares the supplied hash to the hash obtained from a data store of password hashes.
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html): The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html): A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the original message (or with minor changes).
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html): The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.

## Prerequisites

- The system/application is connected to the Windows domain.
- The system/application leverages the Lan Man (LM) and/or NT Lan Man (NTLM) authentication protocols.
- The adversary possesses known Windows credential hash value pairs that exist on the target domain.

## Skills required

- [Low] Once an adversary obtains a known Windows credential hash value pair, leveraging it is trivial.

## Consequences

- Confidentiality, Access Control, Authentication / Gain Privileges
- Confidentiality, Authorization / Read Data
- Integrity / Modify Data

## Mitigations

- Prevent the use of Lan Man and NT Lan Man authentication on severs and apply patch KB2871997 to Windows 7 and higher systems.
- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.
- Monitor system and domain logs for abnormal credential access.
- Create a strong password policy and ensure that your system enforces this policy.
- Leverage system penetration testing and other defense in depth methods to determine vulnerable systems within a domain.

## Related pages

- [CAPEC-652: Use of Known Kerberos Credentials](/mitre/capec/CAPEC-652.md), also related to CWE-294, CWE-308 and 3 more
- [CAPEC-509: Kerberoasting](/mitre/capec/CAPEC-509.md), also related to CWE-294, CWE-308 and 2 more
- [CAPEC-555: Remote Services with Stolen Credentials](/mitre/capec/CAPEC-555.md), also related to CWE-294, CWE-308 and 2 more
- [CAPEC-561: Windows Admin Shares with Stolen Credentials](/mitre/capec/CAPEC-561.md), also related to CWE-294, CWE-308 and 2 more
- [CAPEC-645: Use of Captured Tickets (Pass The Ticket)](/mitre/capec/CAPEC-645.md), also related to CWE-294, CWE-308 and 2 more
- [CAPEC-560: Use of Known Domain Credentials](/mitre/capec/CAPEC-560.md), also related to CWE-308, CWE-308 and 1 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2009 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2009.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)
- [The Year 2011 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2011.md)
- [The Year 2013 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2013.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
