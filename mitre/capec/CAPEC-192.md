# CAPEC-192 — Protocol Analysis

<a id="capec-192"></a>

**Abstraction:** Meta  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Stable  

An adversary engages in activities to decipher and/or decode protocol information for a network or application communication protocol used for transmitting information between interconnected nodes or systems on a packet-switched data network. While this type of analysis involves the analysis of a networking protocol inherently, it does not require the presence of an actual or physical network.

## Related CWE (1)

- [CWE-326 — Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html) — The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.

## Prerequisites

- Access to a binary executable.
- The ability to observe and interact with a communication channel between communicating processes.

## Skills required

- [High] Knowlegde of the Open Systems Interconnection model (OSI model), and famililarity with Wireshark or some other packet analyzer.

## Consequences

- Confidentiality / Read Data
- Integrity / Modify Data

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
