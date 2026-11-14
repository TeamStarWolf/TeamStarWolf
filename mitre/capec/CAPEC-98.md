# CAPEC-98: Phishing

<a id="capec-98"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

Phishing is a social engineering technique where an attacker masquerades as a legitimate entity with which the victim might do business in order to prompt the user to reveal some confidential information (very frequently authentication credentials) that can later be used by an attacker. Phishing is essentially a form of information gathering or "fishing" for information.

## Mapped ATT&CK techniques (2)

- [T1566: Phishing](/mitre/techniques/T1566.md): Adversaries may send phishing messages to gain access to victim systems.
- [T1598: Phishing for Information](/mitre/techniques/T1598.md): Adversaries may send phishing messages to elicit sensitive information that can be used during targeting.

## Related CWE (1)

- [CWE-451: User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html): The user interface (UI) does not properly represent critical information to the user, allowing the information - or its source - to be obscured or spoofed.

## Prerequisites

- An attacker needs to have a way to initiate contact with the victim. Typically that will happen through e-mail.
- An attacker needs to correctly guess the entity with which the victim does business and impersonate it. Most of the time phishers just use the most popular banks/services and send out their "hooks" to many potential victims.
- An attacker needs to have a sufficiently compelling call to action to prompt the user to take action.
- The replicated website needs to look extremely similar to the original website and the URL used to get to that website needs to look like the real URL of the said business entity.

## Skills required

- [Medium] Basic knowledge about websites: obtaining them, designing and implementing them, etc.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also be to type the URL of your bank in the browser directly and only then log in. Also, never reply to any e-mails that ask you to provide sensitive information of any kind.

## Related pages

- [CAPEC-154: Resource Location Spoofing](/mitre/capec/CAPEC-154.md), also related to CWE-451
- [CAPEC-163: Spear Phishing](/mitre/capec/CAPEC-163.md), also related to CWE-451
- [CAPEC-164: Mobile Phishing](/mitre/capec/CAPEC-164.md), also related to CWE-451
- [CAPEC-173: Action Spoofing](/mitre/capec/CAPEC-173.md), also related to CWE-451
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [The DentaQuest Health-Data Breach of May 2026: A Case Study](/case-studies/DENTAQUEST_BREACH_2026.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Stryker Device-Wipe Attack of March 2026: A Case Study](/case-studies/STRYKER_HANDALA_WIPER_2026.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 2004 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2004.md)
- [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
