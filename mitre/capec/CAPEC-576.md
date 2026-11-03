# CAPEC-576: Group Permission Footprinting

<a id="capec-576"></a>

Abstraction: Standard  
Typical severity: Low  
Likelihood: Low  
Status: Stable  

An adversary exploits functionality meant to identify information about user groups and their permissions on the target system to an authorized user. By knowing what users/permissions are registered on the target system, the adversary can inform further and more targeted malicious behavior. An example Windows command which can list local groups is "net localgroup".

## Mapped ATT&CK techniques (2)

- [T1069: Permission Groups Discovery](/mitre/techniques/T1069.md): Adversaries may attempt to discover group and permission settings.
- [T1615: Group Policy Discovery](/mitre/techniques/T1615.md): Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary must have gained access to the target system via physical or logical means in order to carry out this attack.

## Consequences

- Confidentiality / Other
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

## Mitigations

- Identify programs (such as "net") that may be used to enumerate local group permissions and block them by using a software restriction Policy or tools that restrict program execution by using a process allowlist.

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

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
