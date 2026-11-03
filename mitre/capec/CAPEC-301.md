# CAPEC-301: TCP Connect Scan

<a id="capec-301"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Stable  

An adversary uses full TCP connection attempts to determine if a port is open on the target system. The scanning process involves completing a 'three-way handshake' with a remote port, and reports the port as closed if the full handshake cannot be established. An advantage of TCP connect scanning is that it works against any TCP/IP stack.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary requires logical access to the target network. The TCP connect Scan requires the ability to connect to an available port and complete a 'three-way-handshake' This scanning technique does not require any special privileges in order to perform. This type of scan works against all TCP/IP stack implementations.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Employ a robust network defense posture that includes an IDS/IPS system.

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

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
