# CAPEC-187: Malicious Automated Software Update via Redirection

<a id="capec-187"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attacker exploits two layers of weaknesses in server or client software for automated update mechanisms to undermine the integrity of the target code-base. The first weakness involves a failure to properly authenticate a server as a source of update or patch content. This type of weakness typically results from authentication mechanisms which can be defeated, allowing a hostile server to satisfy the criteria that establish a trust relationship. The second weakness is a systemic failure to validate the identity and integrity of code downloaded from a remote location, hence the inability to distinguish malicious code from a legitimate update.

## Mapped ATT&CK techniques (1)

- [T1072: Software Deployment Tools](/mitre/techniques/T1072.md): Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network.

## Related CWE (1)

- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html): The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

## Consequences

- Access Control, Availability, Confidentiality / Execute Unauthorized Commands

## Related pages

- [CAPEC-184: Software Integrity Attack](/mitre/capec/CAPEC-184.md), also related to CWE-494
- [CAPEC-185: Malicious Software Download](/mitre/capec/CAPEC-185.md), also related to CWE-494
- [CAPEC-186: Malicious Software Update](/mitre/capec/CAPEC-186.md), also related to CWE-494
- [CAPEC-533: Malicious Manual Software Update](/mitre/capec/CAPEC-533.md), also related to CWE-494
- [CAPEC-538: Open-Source Library Manipulation](/mitre/capec/CAPEC-538.md), also related to CWE-494
- [CAPEC-657: Malicious Automated Software Update via Spoofing](/mitre/capec/CAPEC-657.md), also related to CWE-494
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
