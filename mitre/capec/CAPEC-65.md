# CAPEC-65 — Sniff Application Code

<a id="capec-65"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary passively sniffs network communications and captures application code bound for an authorized client. Once obtained, they can use it as-is, or through reverse-engineering glean sensitive information or exploit the trust relationship between the client and server. Such code may belong to a dynamic update to the client, a patch being applied to a client component or any such interaction

## Mapped ATT&CK techniques (1)

- [T1040 — Network Sniffing](/mitre/techniques/T1040.md)

## Related CWE (4)

- [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-318 — Cleartext Storage of Sensitive Information in Executable](https://cwe.mitre.org/data/definitions/318.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Prerequisites

- The attacker must have the ability to place themself in the communication path between the client and server.
- The targeted application must receive some application code from the server; for exampl

## Skills required

- The attacker needs to setup a sniffer for a sufficient period of time so as to capture meaningful quantities of code. The presence of the snif

## Mitigations

- Design: Encrypt all communication between the client and server.
- Implementation: Use SSL, SSH, SCP.
- Operation: Use ifconfig/ipconfig or other tools to detect the sniffer installed in the network.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
