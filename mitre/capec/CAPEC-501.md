# CAPEC-501: Android Activity Hijack

<a id="capec-501"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An adversary intercepts an implicit intent sent to launch a Android-based trusted activity and instead launches a counterfeit activity in its place. The malicious activity is then used to mimic the trusted activity's user interface and prompt the target to enter sensitive data as if they were interacting with the trusted activity.

## Related CWE (1)

- [CWE-923: Improper Restriction of Communication Channel to Intended Endpoints](https://cwe.mitre.org/data/definitions/923.html): The product establishes a communication channel to (or from) an endpoint for privileged or protected operations, but it does not properly ensure that it is communicating with the correct endpoint.

## Prerequisites

- The adversary must have previously installed the malicious application onto the Android device that will run in place of the trusted activity.

## Skills required

- [High] The adversary must typically overcome network and host defenses in order to place malware on the system.

## Consequences

- Confidentiality / Read Data

## Mitigations

- To mitigate this type of an attack, explicit intents should be used whenever sensitive data is being sent. An 'explicit intent' is delivered to a specific application as declared within the intent, whereas an 'implicit intent' is directed to an application as defined by the Android operating system. If an implicit intent must be used, then it should be assumed that the intent will be received by an unknown application and any response should be treated accordingly (i.e., with appropriate security controls).
- Never use implicit intents for inter-application communication.

## Related pages

- [CAPEC-161: Infrastructure Manipulation](/mitre/capec/CAPEC-161.md), also related to CWE-923
- [CAPEC-481: Contradictory Destinations in Traffic Routing Schemes](/mitre/capec/CAPEC-481.md), also related to CWE-923
- [CAPEC-697: DHCP Spoofing](/mitre/capec/CAPEC-697.md), also related to CWE-923
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
