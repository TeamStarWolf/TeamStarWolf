# CAPEC-158 — Sniffing Network Traffic

<a id="capec-158"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

In this attack pattern, the adversary monitors network traffic between nodes of a public or multicast network in an attempt to capture sensitive information at the protocol level. Network sniffing applications can reveal TCP/IP, DNS, Ethernet, and other low-level network communication information. The adversary takes a passive role in this attack pattern and simply observes and analyzes the traffi

## Mapped ATT&CK techniques (2)

- [T1040 — Network Sniffing](/mitre/techniques/T1040.md)
- [T1111 — Multi-Factor Authentication Interception](/mitre/techniques/T1111.md)

## Related CWE (1)

- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

## Prerequisites

- The target must be communicating on a network protocol visible by a network sniffing application.
- The adversary must obtain a logical position on the network from intercepting target network traffi

## Skills required

- Adversaries can obtain and set up open-source network sniffing tools easily.:LEVEL:Low

## Mitigations

- Obfuscate network traffic through encryption to prevent its readability by network sniffers.
- Employ appropriate levels of segmentation to your network in accordance with best practices.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
