# CAPEC-115: Authentication Bypass

<a id="capec-115"></a>

Abstraction: Meta  
Typical severity: Medium  
Status: Draft  

An attacker gains access to application, service, or device with the privileges of an authorized or privileged user by evading or circumventing an authentication mechanism. The attacker is therefore able to access protected data without authentication ever having taken place.

## Mapped ATT&CK techniques (1)

- [T1548: Abuse Elevation Control Mechanism](/mitre/techniques/T1548.md): Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions.

## Related CWE (1)

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Prerequisites

- An authentication mechanism or subsystem implementing some form of authentication such as passwords, digest authentication, security certificates, etc.

## Related pages

- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-287
- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-287
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-287
- [CAPEC-114: Authentication Abuse](/mitre/capec/CAPEC-114.md), also related to CWE-287
- [CAPEC-151: Identity Spoofing](/mitre/capec/CAPEC-151.md), also related to CWE-287
- [CAPEC-194: Fake the Source of Data](/mitre/capec/CAPEC-194.md), also related to CWE-287
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [E-Commerce Threats: The Public Record, 1999 to 2026](/case-studies/ECOMMERCE_THREATS.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study](/case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md)
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)
- [The Year 2024 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2024.md)
- [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
