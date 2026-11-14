# CAPEC-191: Read Sensitive Constants Within an Executable

<a id="capec-191"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An adversary engages in activities to discover any sensitive constants present within the compiled code of an executable. These constants may include literal ASCII strings within the file itself, or possibly strings hard-coded into particular routines that can be revealed by code refactoring methods including static and dynamic analysis.

## Mapped ATT&CK techniques (1)

- [T1552.001: Credentials In Files](/mitre/techniques/T1552-001.md): Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.

## Related CWE (1)

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html): The product contains hard-coded credentials, such as a password or cryptographic key.

## Prerequisites

- Access to a binary or executable such that it can be analyzed by various utilities.

## Related pages

- [CAPEC-70: Try Common or Default Usernames and Passwords](/mitre/capec/CAPEC-70.md), also related to CWE-798
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [Stuxnet: The Case Study](/case-studies/STUXNET.md)
- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)
- [The Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769): A Case Study](/case-studies/DELL_RECOVERPOINT_CVE_2026_22769.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
