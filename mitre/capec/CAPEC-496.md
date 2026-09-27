# CAPEC-496 — ICMP Fragmentation

<a id="capec-496"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** 

An attacker may execute a ICMP Fragmentation attack against a target with the intention of consuming resources or causing a crash. The attacker crafts a large number of identical fragmented IP packets containing a portion of a fragmented ICMP message. The attacker these sends these messages to a target host which causes the host to become non-responsive. Another vector may be sending a fragmented

## Related CWE (2)

[CWE-770](/CWE_REFERENCE.md) [CWE-404](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of an attack requires the target system to be running a vulnerable implementation of IP, and the attacker needs to ability to send arbitrary sized ICMP packets to the target.::

**Mitigations:** ::This attack may be mitigated through egress filtering based on ICMP payload so a network is a good neighbor to other networks. Bad IP implementations become patched, so using the proper version of a browser or OS is recommended.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
