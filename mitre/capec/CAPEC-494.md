# CAPEC-494 — TCP Fragmentation

<a id="capec-494"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** 

An adversary may execute a TCP Fragmentation attack against a target with the intention of avoiding filtering rules of network controls, by attempting to fragment the TCP packet such that the headers flag field is pushed into the second fragment which typically is not filtered.

## Related CWE (2)

[CWE-770](/CWE_REFERENCE.md) [CWE-404](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of an attack requires the target system to be running a vulnerable implementation of IP, and the adversary needs to ability to send TCP packets of arbitrary size with crafted data.::

**Mitigations:** ::This attack may be mitigated by enforcing rules at the router following the guidance of RFC1858. The essential part of the guidance is creating the following rule IF FO=1 and PROTOCOL=TCP then DROP PACKET as this mitigated both tiny fragment and ov


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
