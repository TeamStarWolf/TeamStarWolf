# CAPEC-609 — Cellular Traffic Intercept

<a id="capec-609"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

Cellular traffic for voice and data from mobile devices and retransmission devices can be intercepted via numerous methods. Malicious actors can deploy their own cellular tower equipment and intercept cellular traffic surreptitiously. Additionally, government agencies of adversaries and malicious actors can intercept cellular traffic via the telecommunications backbone over which mobile traffic is transmitted.

## Mapped ATT&CK techniques (1)

- [T1111 — Multi-Factor Authentication Interception](/mitre/techniques/T1111.md) — Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources.

## Related CWE (1)

- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html) — The product does not encrypt sensitive or critical information before storage or transmission.

## Skills required

- [Medium] Adversaries can purchase hardware and software solutions, or create their own solutions, to capture/intercept cellular radio traffic. The cost of a basic Base Transceiver Station (BTS) to broadcast to local mobile cellular radios in mobile devices has dropped to very affordable costs. The ability of commercial cellular providers to monitor for "rogue" BTS stations is poor in many areas and it is assumed that "rogue" BTS stations exist in urban areas.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Encryption of all data packets emanating from the smartphone to a retransmission device via two encrypted tunnels with Suite B cryptography, all the way to the VPN gateway at the datacenter.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
