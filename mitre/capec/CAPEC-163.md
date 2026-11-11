# CAPEC-163: Spear Phishing

<a id="capec-163"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

An adversary targets a specific user or group with a Phishing (CAPEC-98) attack tailored to a category of users in order to have maximum relevance and deceptive capability. Spear Phishing is an enhanced version of the Phishing attack targeted to a specific user or group. The quality of the targeted email is usually enhanced by appearing to come from a known or trusted entity. If the email account of some trusted entity has been compromised the message may be digitally signed. The message will contain information specific to the targeted users that will enhance the probability that they will follow the URL to the compromised site. For example, the message may indicate knowledge of the targets employment, residence, interests, or other information that suggests familiarity. As soon as the user follows the instructions in the message, the attack proceeds as a standard Phishing attack.

## Mapped ATT&CK techniques (7)

- [T1534: Internal Spearphishing](/mitre/techniques/T1534.md): After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.
- [T1566.001: Spearphishing Attachment](/mitre/techniques/T1566-001.md): Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002: Spearphishing Link](/mitre/techniques/T1566-002.md): Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.
- [T1566.003: Spearphishing via Service](/mitre/techniques/T1566-003.md): Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems.
- [T1598.001: Spearphishing Service](/mitre/techniques/T1598-001.md): Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting.
- [T1598.002: Spearphishing Attachment](/mitre/techniques/T1598-002.md): Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting.
- [T1598.003: Spearphishing Link](/mitre/techniques/T1598-003.md): Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting.

## Related CWE (1)

- [CWE-451: User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html): The user interface (UI) does not properly represent critical information to the user, allowing the information - or its source - to be obscured or spoofed.

## Prerequisites

- None. Any user can be targeted by a Spear Phishing attack.

## Skills required

- [Medium] Spear phishing attacks require specific knowledge of the victims being targeted, such as which bank is being used by the victims, or websites they commonly log into (Google, Facebook, etc).

## Consequences

- Confidentiality / Read Data
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Integrity / Modify Data

## Mitigations

- Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also be to type the URL of your bank in the browser directly and only then log in. Also, never reply to any e-mails that ask you to provide sensitive information of any kind.

## Related pages

- [CAPEC-98: Phishing](/mitre/capec/CAPEC-98.md), named in the description above
- [CAPEC-154: Resource Location Spoofing](/mitre/capec/CAPEC-154.md), also related to CWE-451
- [CAPEC-164: Mobile Phishing](/mitre/capec/CAPEC-164.md), also related to CWE-451
- [CAPEC-173: Action Spoofing](/mitre/capec/CAPEC-173.md), also related to CWE-451
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
