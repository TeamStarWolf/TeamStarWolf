# CAPEC-695: Repo Jacking

<a id="capec-695"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary takes advantage of the redirect property of directly linked Version Control System (VCS) repositories to trick users into incorporating malicious code into their applications.

## Mapped ATT&CK techniques (1)

- [T1195.001: Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md): Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise.

## Related CWE (2)

- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html): The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- Identification of a popular repository that may be directly referenced in numerous software applications
- A repository owner/maintainer who has recently changed their username or deleted their account

## Skills required

- [Low] Ability to create an account on a VCS hosting site and recreate an existing directory structure.
- [Low] Ability to create malware that can exploit various software applications.

## Consequences

- Integrity / Read Data, Modify Data
- Access Control, Authorization / Execute Unauthorized Commands, Alter Execution Logic, Gain Privileges

## Mitigations

- Leverage dedicated package managers instead of directly linking to VCS repositories.
- Utilize version pinning and lock files to prevent use of maliciously modified repositories.
- Implement "vendoring" (i.e., including third-party dependencies locally) and leverage automated testing techniques (e.g., static analysis) to determine if the software behaves maliciously.
- Leverage automated tools, such as Checkmarx's "ChainJacking" tool, to determine susceptibility to Repo Jacking attacks.

## Related pages

- [CAPEC-538: Open-Source Library Manipulation](/mitre/capec/CAPEC-538.md), also related to CWE-494 and CWE-829
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
- [Hugging Face as an AI Supply-Chain Attack Surface: A 2021 to 2026 Case Study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md)
- [npm Supply-Chain Attacks, 2018 to 2026: The Record and the Defenses](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
