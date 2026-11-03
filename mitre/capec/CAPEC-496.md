# CAPEC-496: ICMP Fragmentation

<a id="capec-496"></a>

Abstraction: Standard  
Status: Draft  

An attacker may execute a ICMP Fragmentation attack against a target with the intention of consuming resources or causing a crash. The attacker crafts a large number of identical fragmented IP packets containing a portion of a fragmented ICMP message. The attacker these sends these messages to a target host which causes the host to become non-responsive. Another vector may be sending a fragmented ICMP message to a target host with incorrect sizes in the header which causes the host to hang.

## Related CWE (2)

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.
- [CWE-404: Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html): The product does not release or incorrectly releases a resource before it is made available for re-use.

## Prerequisites

- This type of an attack requires the target system to be running a vulnerable implementation of IP, and the attacker needs to ability to send arbitrary sized ICMP packets to the target.

## Mitigations

- This attack may be mitigated through egress filtering based on ICMP payload so a network is a "good neighbor" to other networks. Bad IP implementations become patched, so using the proper version of a browser or OS is recommended.

## Related pages

- [CAPEC-125: Flooding](/mitre/capec/CAPEC-125.md), also related to CWE-404 and CWE-770
- [CAPEC-130: Excessive Allocation](/mitre/capec/CAPEC-130.md), also related to CWE-404 and CWE-770
- [CAPEC-494: TCP Fragmentation](/mitre/capec/CAPEC-494.md), also related to CWE-404 and CWE-770
- [CAPEC-495: UDP Fragmentation](/mitre/capec/CAPEC-495.md), also related to CWE-404 and CWE-770
- [CAPEC-131: Resource Leak Exposure](/mitre/capec/CAPEC-131.md), also related to CWE-404
- [CAPEC-666: BlueSmacking](/mitre/capec/CAPEC-666.md), also related to CWE-404
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
