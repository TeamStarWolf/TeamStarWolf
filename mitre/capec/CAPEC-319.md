# CAPEC-319 — IP (DF) 'Don't Fragment Bit' Echoing Probe

<a id="capec-319"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium

This OS fingerprinting probe tests to determine if the remote host echoes back the IP 'DF' (Don't Fragment) bit in a response packet. An attacker sends a UDP datagram with the DF bit set to a closed port on the remote host to observe whether the 'DF' bit is set in the response packet. Some operating systems will echo the bit in the ICMP error message while others will zero out the bit in the respo

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
