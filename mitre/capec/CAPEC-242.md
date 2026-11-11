# CAPEC-242: Code Injection

<a id="capec-242"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: High  
Status: Stable  

An adversary exploits a weakness in input validation on the target to inject new code into that which is currently executing. This differs from code inclusion in that code inclusion involves the addition or replacement of a reference to a code file, which is subsequently loaded by the target and used as part of the code of some application.

## Related CWE (1)

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html): The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

## Prerequisites

- The target software does not validate user-controlled input such that the execution of a process may be altered by sending code in through legitimate data channels, using no other mechanism.

## Consequences

- Confidentiality, Integrity, Availability / Other

## Mitigations

- Utilize strict type, character, and encoding enforcement
- Ensure all input content that is delivered to client is sanitized against an acceptable content specification.
- Perform input validation for all content.
- Enforce regular patching of software.

## Related pages

- [CAPEC-35: Leverage Executable Code in Non-Executable Files](/mitre/capec/CAPEC-35.md), also related to CWE-94
- [CAPEC-77: Manipulating User-Controlled Variables](/mitre/capec/CAPEC-77.md), also related to CWE-94
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
