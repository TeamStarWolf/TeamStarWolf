# CAPEC-65: Sniff Application Code

<a id="capec-65"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An adversary passively sniffs network communications and captures application code bound for an authorized client. Once obtained, they can use it as-is, or through reverse-engineering glean sensitive information or exploit the trust relationship between the client and server. Such code may belong to a dynamic update to the client, a patch being applied to a client component or any such interaction where the client is authorized to communicate with the server.

## Mapped ATT&CK techniques (1)

- [T1040: Network Sniffing](/mitre/techniques/T1040.md): Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.

## Related CWE (4)

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html): The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html): The product does not encrypt sensitive or critical information before storage or transmission.
- [CWE-318: Cleartext Storage of Sensitive Information in Executable](https://cwe.mitre.org/data/definitions/318.html): The product stores sensitive information in cleartext in an executable.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- The attacker must have the ability to place themself in the communication path between the client and server.
- The targeted application must receive some application code from the server; for example, dynamic updates, patches, applets or scripts.
- The attacker must be able to employ a sniffer on the network without being detected.

## Skills required

- [Medium] The attacker needs to setup a sniffer for a sufficient period of time so as to capture meaningful quantities of code. The presence of the sniffer should not be detected on the network. Also if the attacker plans to employ an adversary-in-the-middle attack (CAPEC-94), the client or server must not realize this. Finally, the attacker needs to regenerate source code from binary code if the need be.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Design: Encrypt all communication between the client and server.
- Implementation: Use SSL, SSH, SCP.
- Operation: Use "ifconfig/ipconfig" or other tools to detect the sniffer installed in the network.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
