# CAPEC-318 — IP 'ID' Echoed Byte-Order Probe

<a id="capec-318"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium  
**Status:** Stable  

This OS fingerprinting probe tests to determine if the remote host echoes back the IP 'ID' value from the probe packet. An attacker sends a UDP datagram with an arbitrary IP 'ID' value to a closed port on the remote host to observe the manner in which this bit is echoed back in the ICMP error message. The identification field (ID) is typically utilized for reassembling a fragmented packet. Some operating systems or router firmware reverse the bit order of the ID field when echoing the IP Header portion of the original datagram within an ICMP error message.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
