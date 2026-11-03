# CAPEC-308: UDP Scan

<a id="capec-308"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Stable  

An adversary engages in UDP scanning to gather information about UDP port status on the target system. UDP scanning methods involve sending a UDP datagram to the target port and looking for evidence that the port is closed. Open UDP ports usually do not respond to UDP datagrams as there is no stateful mechanism within the protocol that requires building or establishing a session. Responses to UDP datagrams are therefore application specific and cannot be relied upon as a method of detecting an open port. UDP scanning relies heavily upon ICMP diagnostic messages in order to determine the status of a remote port.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The ability to send UDP datagrams to a host and receive ICMP error messages from that host. In cases where particular types of ICMP messaging is disallowed, the reliability of UDP scanning drops off sharply.

## Consequences

- Confidentiality / Other
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

## Mitigations

- Firewalls or ACLs which block egress ICMP error types effectively prevent UDP scans from returning any useful information.
- UDP scanning is complicated by rate limiting mechanisms governing ICMP error messages.

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
