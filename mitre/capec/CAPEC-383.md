# CAPEC-383: Harvesting Information via API Event Monitoring

<a id="capec-383"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An adversary hosts an event within an application framework and then monitors the data exchanged during the course of the event for the purpose of harvesting any important data leaked during the transactions. One example could be harvesting lists of usernames or userIDs for the purpose of sending spam messages to those users. One example of this type of attack involves the adversary creating an event within the sub-application. Assume the adversary hosts a "virtual sale" of rare items. As other users enter the event, the attacker records via AiTM (CAPEC-94) proxy the user_ids and usernames of everyone who attends. The adversary would then be able to spam those users within the application using an automated script.

## Mapped ATT&CK techniques (1)

- [T1056.004: Credential API Hooking](/mitre/techniques/T1056-004.md): Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials.

## Related CWE (4)

- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html): The product does not encrypt sensitive or critical information before storage or transmission.
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html): The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.
- [CWE-419: Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html): The product uses a primary channel for administration or restricted functionality, but it does not properly protect the channel.
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html): The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

## Prerequisites

- The target software is utilizing application framework APIs

## Consequences

- Confidentiality / Read Data

## Mitigations

- Leverage encryption techniques during information transactions so as to protect them from attack patterns of this kind.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
