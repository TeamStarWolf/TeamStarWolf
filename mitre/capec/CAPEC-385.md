# CAPEC-385 — Transaction or Event Tampering via Application API Manipulation

<a id="capec-385"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker hosts or joins an event or transaction within an application framework in order to change the content of messages or items that are being exchanged. Performing this attack allows the attacker to manipulate content in such a way as to produce messages or content that look authentic but may contain deceptive links, substitute one item or another, spoof an existing item and conduct a false exchange, or otherwise change the amounts or identity of what is being exchanged. The techniques require use of specialized software that allow the attacker to man-in-the-middle communications between the web browser and the remote system in order to change the content of various application elements. Often, items exchanged in game can be monetized via sales for coin, virtual dollars, etc. The purpose of the attack is for the attack to scam the victim by trapping the data packets involved the exchange and altering the integrity of the transfer process.

## Related CWE (5)

- [CWE-471 — Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html) — The product does not properly protect an assumed-immutable element from being modified by an attacker.
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) — The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) — The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html) — The product does not encrypt sensitive or critical information before storage or transmission.

## Prerequisites

- Targeted software is utilizing application framework APIs

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
