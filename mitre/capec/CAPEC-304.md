# CAPEC-304 — TCP Null Scan

<a id="capec-304"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An adversary uses a TCP NULL scan to determine if ports are closed on the target machine. This scan type is accomplished by sending TCP segments with no flags in the packet header, generating packets that are illegal based on RFC 793. The RFC 793 expected behavior is that any TCP segment with an out-of-state Flag sent to an open port is discarded, whereas segments with out-of-state flags sent to c

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary requires logical access to the target network. NULL scanning requires the use of raw sockets, and thus cannot be performed from some Windows systems (Windows XP SP 2, for example). On 

**Mitigations:** ::Employ a robust network defensive posture that includes a managed IDS/IPS.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
