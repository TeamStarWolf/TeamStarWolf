# CAPEC-617: Cellular Rogue Base Station

<a id="capec-617"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

In this attack scenario, the attacker imitates a cellular base station with their own "rogue" base station equipment. Since cellular devices connect to whatever station has the strongest signal, the attacker can easily convince a targeted cellular device (e.g. the retransmission device) to talk to the rogue base station.

## Skills required

- [Low] This technique has been demonstrated by amateur hackers and commercial tools and open source projects are available to automate the attack.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Passively monitor cellular network connection for real-time threat detection and logging for manual review.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
