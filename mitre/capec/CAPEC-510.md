# CAPEC-510: SaaS User Request Forgery

<a id="capec-510"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An adversary, through a previously installed malicious application, performs malicious actions against a third-party Software as a Service (SaaS) application (also known as a cloud based application) by leveraging the persistent and implicit trust placed on a trusted user's session. This attack is executed after a trusted user is authenticated into a cloud service, "piggy-backing" on the authenticated session, and exploiting the fact that the cloud service believes it is only interacting with the trusted user. If successful, the actions embedded in the malicious application will be processed and accepted by the targeted SaaS application and executed at the trusted user's privilege level.

## Related CWE (1)

- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html): The product does not properly verify that the source of data or communication is valid.

## Prerequisites

- An adversary must be able install a purpose built malicious application onto the trusted user's system and convince the user to execute it while authenticated to the SaaS application.

## Skills required

- [Medium] This attack pattern often requires the technical ability to modify a malicious software package (e.g. Zeus) to spider a targeted site and a way to trick a user into a malicious software download.

## Mitigations

- To limit one's exposure to this type of attack, tunnel communications through a secure proxy service.
- Detection of this type of attack can be done through heuristic analysis of behavioral anomalies (a la credit card fraud detection) which can be used to identify inhuman behavioral patterns. (e.g., spidering)

## Related pages

- [CAPEC-21: Exploitation of Trusted Identifiers](/mitre/capec/CAPEC-21.md), also related to CWE-346
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-346
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-346
- [CAPEC-75: Manipulating Writeable Configuration Files](/mitre/capec/CAPEC-75.md), also related to CWE-346
- [CAPEC-76: Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md), also related to CWE-346
- [CAPEC-89: Pharming](/mitre/capec/CAPEC-89.md), also related to CWE-346
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
