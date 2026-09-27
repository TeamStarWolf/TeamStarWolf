# CAPEC-606 — Weakening of Cellular Encryption

<a id="capec-606"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Status:** Draft  

An attacker, with control of a Cellular Rogue Base Station or through cooperation with a Malicious Mobile Network Operator can force the mobile device (e.g., the retransmission device) to use no encryption (A5/0 mode) or to use easily breakable encryption (A5/1 or A5/2 mode).

## Related CWE (1)

- [CWE-757 — Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html) — A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication, but it…

## Prerequisites

- Cellular devices that allow negotiating security modes to facilitate backwards compatibility and roaming on legacy networks.

## Skills required

- [Medium] Adversaries can purchase and implement rogue BTS stations at a cost effective rate, and can push a mobile device to downgrade to a non-secure cellular protocol like 2G over GSM or CDMA.

## Consequences

- Confidentiality / Other

## Mitigations

- Use of hardened baseband firmware on retransmission device to detect and prevent the use of weak cellular encryption.
- Monitor cellular RF interface to detect the usage of weaker-than-expected cellular encryption.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
