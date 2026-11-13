# CAPEC-643: Identify Shared Files/Directories on System

<a id="capec-643"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: Medium  
Status: Draft  

An adversary discovers connections between systems by exploiting the target system's standard practice of revealing them in searchable, common areas. Through the identification of shared folders/drives between systems, the adversary may further their goals of locating and collecting sensitive information/files, or map potential routes for lateral movement within the network.

## Mapped ATT&CK techniques (1)

- [T1135: Network Share Discovery](/mitre/techniques/T1135.md): Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement.

## Related CWE (2)

- [CWE-267: Privilege Defined With Unsafe Actions](https://cwe.mitre.org/data/definitions/267.html): A particular privilege, role, capability, or right can be used to perform unsafe actions that were not intended, even when it is assigned to the correct entity.
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary must have obtained logical access to the system by some means (e.g., via obtained credentials or planting malware on the system).

## Skills required

- [Low] Once the adversary has logical access (which can potentially require high knowledge and skill level), the adversary needs only the capability and facility to navigate the system through the OS graphical user interface or the command line. The adversary, or their malware, can simply employ a set of commands that search for shared drives on the system (e.g., net view \\remote system or net share).

## Consequences

- Confidentiality / Read Data

## Mitigations

- Identify unnecessary system utilities or potentially malicious software that may contain functionality to identify network share information, and audit and/or block them by using allowlist tools.

## Related pages

- [CAPEC-58: Restful Privilege Elevation](/mitre/capec/CAPEC-58.md), also related to CWE-267
- [CAPEC-634: Probe Audio and Video Peripherals](/mitre/capec/CAPEC-634.md), also related to CWE-267
- [CAPEC-637: Collect Data from Clipboard](/mitre/capec/CAPEC-637.md), also related to CWE-267
- [CAPEC-648: Collect Data from Screen Capture](/mitre/capec/CAPEC-648.md), also related to CWE-267
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-200
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-200
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
