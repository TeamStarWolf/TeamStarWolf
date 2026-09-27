# CAPEC-158 — Sniffing Network Traffic

<a id="capec-158"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

In this attack pattern, the adversary monitors network traffic between nodes of a public or multicast network in an attempt to capture sensitive information at the protocol level. Network sniffing applications can reveal TCP/IP, DNS, Ethernet, and other low-level network communication information. The adversary takes a passive role in this attack pattern and simply observes and analyzes the traffic. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the target information.

## Mapped ATT&CK techniques (2)

- [T1040 — Network Sniffing](/mitre/techniques/T1040.md) — Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.
- [T1111 — Multi-Factor Authentication Interception](/mitre/techniques/T1111.md) — Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources.

## Related CWE (1)

- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html) — The product does not encrypt sensitive or critical information before storage or transmission.

## Prerequisites

- The target must be communicating on a network protocol visible by a network sniffing application.
- The adversary must obtain a logical position on the network from intercepting target network traffic is possible. Depending on the network topology, traffic sniffing may be simple or challenging. If both the target sender and target recipient are members of a single subnet, the adversary must also be on that subnet in order to see their traffic communication.

## Skills required

- [Low] Adversaries can obtain and set up open-source network sniffing tools easily.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Obfuscate network traffic through encryption to prevent its readability by network sniffers.
- Employ appropriate levels of segmentation to your network in accordance with best practices.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
