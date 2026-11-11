# CAPEC-577: Owner Footprinting

<a id="capec-577"></a>

Abstraction: Standard  
Typical severity: Low  
Likelihood: Low  
Status: Draft  

An adversary exploits functionality meant to identify information about the primary users on the target system to an authorized user. They may do this, for example, by reviewing logins or file modification times. By knowing what owners use the target system, the adversary can inform further and more targeted malicious behavior. An example Windows command that may accomplish this is "dir /A ntuser.dat". Which will display the last modified time of a user's ntuser.dat file when run within the root folder of a user. This time is synonymous with the last time that user was logged in.

## Mapped ATT&CK techniques (1)

- [T1033: System Owner/User Discovery](/mitre/techniques/T1033.md): Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary must have gained access to the target system via physical or logical means in order to carry out this attack.
- Administrator permissions are required to view the home folder of other users.

## Consequences

- Confidentiality / Other
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

## Mitigations

- Ensure that proper permissions on files and folders are enacted to limit accessibility.

## Related pages

- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-200
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-200
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-200
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-200
- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-200
- [CAPEC-116: Excavation](/mitre/capec/CAPEC-116.md), also related to CWE-200
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
