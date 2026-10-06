# CAPEC-605: Cellular Jamming

<a id="capec-605"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

In this attack scenario, the attacker actively transmits signals to overpower and disrupt the communication between a cellular user device and a cell tower. Several existing techniques are known in the open literature for this attack for 2G, 3G, and 4G LTE cellular technology. For example, some attacks target cell towers by overwhelming them with false status messages, while others introduce high levels of noise on signaling channels.

## Prerequisites

- Lack of anti-jam features in cellular technology (2G, 3G, 4G, LTE)

## Skills required

- [Low] This attack can be performed by low capability attackers with commercially available tools.

## Consequences

- Availability / Resource Consumption

## Mitigations

- Mitigating this attack requires countermeasures employed on both the retransmission device as well as on the cell tower. Therefore, any system that relies on existing commercial cell towards will likely be vulnerable to this attack. By using a private cellular LTE network (i.e., a custom cell tower), jamming countermeasures could be developed and employed.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
