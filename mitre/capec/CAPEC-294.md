# CAPEC-294 — ICMP Address Mask Request

<a id="capec-294"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An adversary sends an ICMP Type 17 Address Mask Request to gather information about a target's networking configuration. ICMP Address Mask Requests are defined by RFC-950, Internet Standard Subnetting Procedure. An Address Mask Request is an ICMP type 17 message that triggers a remote system to respond with a list of its related subnets, as well as its default gateway and broadcast address via an

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The ability to send an ICMP type 17 query (Address Mask Request) to a remote target and receive an ICMP type 18 message (ICMP Address Mask Reply) in response. Generally, modern operating systems wil


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
