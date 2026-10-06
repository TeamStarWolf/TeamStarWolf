# CAPEC-309: Network Topology Mapping

<a id="capec-309"></a>

Abstraction: Standard  
Typical severity: Low  
Status: Draft  

An adversary engages in scanning activities to map network nodes, hosts, devices, and routes. Adversaries usually perform this type of network reconnaissance during the early stages of attack against an external network. Many types of scanning utilities are typically employed, including ICMP tools, network mappers, port scanners, and route testing utilities such as traceroute.

## Mapped ATT&CK techniques (3)

- [T1016: System Network Configuration Discovery](/mitre/techniques/T1016.md): Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems.
- [T1049: System Network Connections Discovery](/mitre/techniques/T1049.md): Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
- [T1590: Gather Victim Network Information](/mitre/techniques/T1590.md): Adversaries may gather information about the victim's networks that can be used during targeting.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Consequences

- Confidentiality / Other

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
