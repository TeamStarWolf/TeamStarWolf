# CAPEC-186: Malicious Software Update

<a id="capec-186"></a>

Abstraction: Standard  
Typical severity: High  
Status: Draft  

An adversary uses deceptive methods to cause a user or an automated process to download and install dangerous code believed to be a valid update that originates from an adversary controlled source.

## Mapped ATT&CK techniques (1)

- [T1195.002: Compromise Software Supply Chain](/mitre/techniques/T1195-002.md): Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.

## Related CWE (1)

- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html): The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

## Skills required

- [High] This attack requires advanced cyber capabilities

## Consequences

- Access Control, Availability, Confidentiality / Execute Unauthorized Commands

## Mitigations

- Validate software updates before installing.

## Related pages

- [CAPEC-184: Software Integrity Attack](/mitre/capec/CAPEC-184.md), also related to CWE-494
- [CAPEC-185: Malicious Software Download](/mitre/capec/CAPEC-185.md), also related to CWE-494
- [CAPEC-187: Malicious Automated Software Update via Redirection](/mitre/capec/CAPEC-187.md), also related to CWE-494
- [CAPEC-533: Malicious Manual Software Update](/mitre/capec/CAPEC-533.md), also related to CWE-494
- [CAPEC-538: Open-Source Library Manipulation](/mitre/capec/CAPEC-538.md), also related to CWE-494
- [CAPEC-657: Malicious Automated Software Update via Spoofing](/mitre/capec/CAPEC-657.md), also related to CWE-494
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
