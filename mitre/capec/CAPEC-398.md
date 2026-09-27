# CAPEC-398 — Magnetic Strip Card Brute Force Attacks

<a id="capec-398"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary analyzes the data on two or more magnetic strip cards and is able to generate new cards containing valid sequences that allow unauthorized access and/or impersonation of individuals.

## Prerequisites

- The ability to calculate a card checksum and write out a valid checksum value. Some cards are protected by a checksum calculation, therefore it is necessary to determine what algorithm is being used to calculate the checksum and to employ that algorithm to calculate and write a new valid checksum for the card being created.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
