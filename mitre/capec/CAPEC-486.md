# CAPEC-486 — UDP Flood

<a id="capec-486"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary may execute a flooding attack using the UDP protocol with the intent to deny legitimate users access to a service by consuming the available network bandwidth. Additionally, firewalls often open a port for each UDP connection destined for a service with an open UDP port, meaning the firewalls in essence save the connection state thus the high packet nature of a UDP flood can also overwhelm resources allocated to the firewall. UDP attacks can also target services like DNS or VoIP which utilize these protocols. Additionally, due to the session-less nature of the UDP protocol, the source of a packet is easily spoofed making it difficult to find the source of the attack.

## Related CWE (1)

- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) — The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- This type of an attack requires the ability to generate a large amount of UDP traffic to send to the desired port of a target service using UDP.

## Mitigations

- To mitigate this type of an attack, modern firewalls drop UDP traffic destined for closed ports, and unsolicited UDP reply packets. A variety of other countermeasures such as universal reverse path forwarding and remote triggered black holing(RFC3704) along with modifications to BGP like black hole routing and sinkhole routing(RFC3882) help mitigate the spoofed source IP nature of these attacks.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
