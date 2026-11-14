# CAPEC-206: Signing Malicious Code

<a id="capec-206"></a>

Abstraction: Detailed  
Typical severity: Very High  
Status: Draft  

The adversary extracts credentials used for code signing from a production environment and then uses these credentials to sign malicious content with the developer's key. Many developers use signing keys to sign code or hashes of code. When users or applications verify the signatures are accurate they are led to believe that the code came from the owner of the signing key and that the code has not been modified since the signature was applied. If the adversary has extracted the signing credentials then they can use those credentials to sign their own code bundles. Users or tools that verify the signatures attached to the code will likely assume the code came from the legitimate developer and install or run the code, effectively allowing the adversary to execute arbitrary code on the victim's computer. This differs from CAPEC-673, because the adversary is performing the code signing.

## Mapped ATT&CK techniques (1)

- [T1553.002: Code Signing](/mitre/techniques/T1553-002.md): Adversaries may create, acquire, or steal code signing materials to sign their malware or tools.

## Related CWE (1)

- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html): The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.

## Prerequisites

- The targeted developer must use a signing key to sign code bundles. (Note that not doing this is not a defense - it only means that the adversary does not need to steal the signing key before forging code bundles in the developer's name.)

## Mitigations

- Ensure digital certificates are protected and inaccessible by unauthorized uses.
- If a digital certificate has been compromised it should be revoked and regenerated.
- Even if a piece of software has a valid and trusted digital signature, it should be assessed for any weaknesses and vulnerabilities.

## Related pages

- [CAPEC-673: Developer Signing Maliciously Altered Software](/mitre/capec/CAPEC-673.md), named in the description above
- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](/mitre/capec/CAPEC-1.md), also related to CWE-732
- [CAPEC-17: Using Malicious Files](/mitre/capec/CAPEC-17.md), also related to CWE-732
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-732
- [CAPEC-61: Session Fixation](/mitre/capec/CAPEC-61.md), also related to CWE-732
- [CAPEC-62: Cross Site Request Forgery](/mitre/capec/CAPEC-62.md), also related to CWE-732
- [CAPEC-122: Privilege Abuse](/mitre/capec/CAPEC-122.md), also related to CWE-732
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md)
- [Stuxnet: The Case Study](/case-studies/STUXNET.md)
- [The FireEye Mandiant Intrusion of 2020: The Public Record](/case-studies/MANDIANT_INTRUSION_2020.md)
- [The Year 2001 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2001.md)
- [The Year 2011 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2011.md)
- [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)
- [The Year 2013 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2013.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)
- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
