# CAPEC-538: Open-Source Library Manipulation

<a id="capec-538"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Stable  

Adversaries implant malicious code in open source software (OSS) libraries to have it widely distributed, as OSS is commonly downloaded by developers and other users to incorporate into software development projects. The adversary can have a particular system in mind to target, or the implantation can be the first stage of follow-on attacks on many systems.

## Mapped ATT&CK techniques (1)

- [T1195.001: Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md): Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise.

## Related CWE (2)

- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html): The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- Access to the open source code base being used by the manufacturer in a system being developed or currently deployed at a victim location.

## Skills required

- [High] Advanced knowledge about the inclusion and specific usage of an open source code project within system being targeted for infiltration.

## Related pages

- [CAPEC-695: Repo Jacking](/mitre/capec/CAPEC-695.md), also related to CWE-494 and CWE-829
- [CAPEC-184: Software Integrity Attack](/mitre/capec/CAPEC-184.md), also related to CWE-494
- [CAPEC-185: Malicious Software Download](/mitre/capec/CAPEC-185.md), also related to CWE-494
- [CAPEC-186: Malicious Software Update](/mitre/capec/CAPEC-186.md), also related to CWE-494
- [CAPEC-187: Malicious Automated Software Update via Redirection](/mitre/capec/CAPEC-187.md), also related to CWE-494
- [CAPEC-533: Malicious Manual Software Update](/mitre/capec/CAPEC-533.md), also related to CWE-494
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [npm Supply-Chain Attacks, 2018 to 2026: The Record and the Defenses](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
