# CAPEC-606 — Weakening of Cellular Encryption

<a id="capec-606"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** 

An attacker, with control of a Cellular Rogue Base Station or through cooperation with a Malicious Mobile Network Operator can force the mobile device (e.g., the retransmission device) to use no encryption (A5/0 mode) or to use easily breakable encryption (A5/1 or A5/2 mode).

## Related CWE (1)

[CWE-757](/CWE_REFERENCE.md)

**Prerequisites:** ::Cellular devices that allow negotiating security modes to facilitate backwards compatibility and roaming on legacy networks.::

**Skills required:** ::SKILL:Adversaries can purchase and implement rogue BTS stations at a cost effective rate, and can push a mobile device to downgrade to a non-secure 

**Mitigations:** ::Use of hardened baseband firmware on retransmission device to detect and prevent the use of weak cellular encryption.::Monitor cellular RF interface to detect the usage of weaker-than-expected cellular encryption.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
