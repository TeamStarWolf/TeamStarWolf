# CAPEC-318 — IP 'ID' Echoed Byte-Order Probe

<a id="capec-318"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium

This OS fingerprinting probe tests to determine if the remote host echoes back the IP 'ID' value from the probe packet. An attacker sends a UDP datagram with an arbitrary IP 'ID' value to a closed port on the remote host to observe the manner in which this bit is echoed back in the ICMP error message. The identification field (ID) is typically utilized for reassembling a fragmented packet. Some op

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
