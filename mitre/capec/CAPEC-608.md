# CAPEC-608 — Cryptanalysis of Cellular Encryption

<a id="capec-608"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Status:** Draft  

The use of cryptanalytic techniques to derive cryptographic keys or otherwise effectively defeat cellular encryption to reveal traffic content. Some cellular encryption algorithms such as A5/1 and A5/2 (specified for GSM use) are known to be vulnerable to such attacks and commercial tools are available to execute these attacks and decrypt mobile phone conversations in real-time. Newer encryption algorithms in use by UMTS and LTE are stronger and currently believed to be less vulnerable to these types of attacks. Note, however, that an attacker with a Cellular Rogue Base Station can force the use of weak cellular encryption even by newer mobile devices.

## Related CWE (1)

- [CWE-327 — Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) — The product uses a broken or risky cryptographic algorithm or protocol.

## Prerequisites

- None

## Skills required

- [Medium] Adversaries can rent commercial supercomputer time globally to conduct cryptanalysis on encrypted data captured from mobile devices. Foreign governments have their own cryptanalysis technology and capabilities. Commercial cellular standards for encryption (GSM and CDMA) are also subject to adversary cryptanalysis.

## Consequences

- Confidentiality / Other

## Mitigations

- Use of hardened baseband firmware on retransmission device to detect and prevent the use of weak cellular encryption.
- Monitor cellular RF interface to detect the usage of weaker-than-expected cellular encryption.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
