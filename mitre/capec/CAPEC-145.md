# CAPEC-145 — Checksum Spoofing

<a id="capec-145"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An adversary spoofs a checksum message for the purpose of making a payload appear to have a valid corresponding checksum. Checksums are used to verify message integrity. They consist of some value based on the value of the message they are protecting. Hash codes are a common checksum mechanism. Both the sender and recipient are able to compute the checksum based on the contents of the message. If the message contents change between the sender and recipient, the sender and recipient will compute different checksum values. Since the sender's checksum value is transmitted with the message, the recipient would know that a modification occurred. In checksum spoofing an adversary modifies the message body and then modifies the corresponding checksum so that the recipient's checksum calculation will match the checksum (created by the adversary) in the message. This would prevent the recipient from realizing that a change occurred.

## Related CWE (1)

- [CWE-354 — Improper Validation of Integrity Check Value](https://cwe.mitre.org/data/definitions/354.html) — The product does not validate or incorrectly validates the integrity check values or checksums of a message.

## Prerequisites

- The adversary must be able to intercept a message from the sender (keeping the recipient from getting it), modify it, and send the modified message to the recipient.
- The sender and recipient must use a checksum to protect the integrity of their message and transmit this checksum in a manner where the adversary can intercept and modify it.
- The checksum value must be computable using information known to the adversary. A cryptographic checksum, which uses a key known only to the sender and recipient, would thwart this attack.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
