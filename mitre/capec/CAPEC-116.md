# CAPEC-116: Excavation

<a id="capec-116"></a>

Abstraction: Meta  
Typical severity: Medium  
Likelihood: High  
Status: Stable  

An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes.

## Related CWE (2)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- [CWE-1243: Sensitive Non-Volatile Information Not Protected During Debug](https://cwe.mitre.org/data/definitions/1243.html): Access to security-sensitive information stored in fuses is not limited during debug.

## Prerequisites

- An adversary requires some way of interacting with the system.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Minimize error/response output to only what is necessary for functional use or corrective language.
- Remove potentially sensitive information that is not necessary for the application's functionality.

## Related pages

- [CAPEC-545: Pull Data from System Resources](/mitre/capec/CAPEC-545.md), also related to CWE-1243
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-200
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-200
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-200
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-200
- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-200
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
