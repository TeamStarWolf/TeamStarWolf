# CAPEC-317: IP ID Sequencing Probe

<a id="capec-317"></a>

Abstraction: Detailed  
Typical severity: Low  
Likelihood: Medium  
Status: Stable  

This OS fingerprinting probe analyzes the IP 'ID' field sequence number generation algorithm of a remote host. Operating systems generate IP 'ID' numbers differently, allowing an attacker to identify the operating system of the host by examining how is assigns ID numbers when generating response packets. RFC 791 does not specify how ID numbers are chosen or their ranges, so ID sequence generation differs from implementation to implementation. There are two kinds of IP 'ID' sequence number analysis - IP 'ID' Sequencing: analyzing the IP 'ID' sequence generation algorithm for one protocol used by a host and Shared IP 'ID' Sequencing: analyzing the packet ordering via IP 'ID' values spanning multiple protocols, such as between ICMP and TCP.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

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
