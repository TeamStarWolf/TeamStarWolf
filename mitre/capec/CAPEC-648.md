# CAPEC-648: Collect Data from Screen Capture

<a id="capec-648"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: Medium  
Status: Draft  

An adversary gathers sensitive information by exploiting the system's screen capture functionality. Through screenshots, the adversary aims to see what happens on the screen over the course of an operation. The adversary can leverage information gathered in order to carry out further attacks.

## Mapped ATT&CK techniques (2)

- [T1113: Screen Capture](/mitre/techniques/T1113.md): Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.
- `T1513`

## Related CWE (1)

- [CWE-267: Privilege Defined With Unsafe Actions](https://cwe.mitre.org/data/definitions/267.html): A particular privilege, role, capability, or right can be used to perform unsafe actions that were not intended, even when it is assigned to the correct entity.

## Prerequisites

- The adversary must have obtained logical access to the system by some means (e.g., via obtained credentials or planting malware on the system).

## Skills required

- [Low] Once the adversary has logical access (which can potentially require high knowledge and skill level), the adversary needs only to leverage the relevant command for screen capture.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Identify potentially malicious software that may have functionality to acquire screen captures, and audit and/or block it by using allowlist tools.
- While screen capture is a legitimate and practical function, certain situations and context may require the disabling of this feature.

## Related pages

- [CAPEC-58: Restful Privilege Elevation](/mitre/capec/CAPEC-58.md), also related to CWE-267
- [CAPEC-634: Probe Audio and Video Peripherals](/mitre/capec/CAPEC-634.md), also related to CWE-267
- [CAPEC-637: Collect Data from Clipboard](/mitre/capec/CAPEC-637.md), also related to CWE-267
- [CAPEC-643: Identify Shared Files/Directories on System](/mitre/capec/CAPEC-643.md), also related to CWE-267
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
