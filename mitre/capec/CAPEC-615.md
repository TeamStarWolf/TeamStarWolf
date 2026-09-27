# CAPEC-615 — Evil Twin Wi-Fi Attack

<a id="capec-615"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

Adversaries install Wi-Fi equipment that acts as a legitimate Wi-Fi network access point. When a device connects to this access point, Wi-Fi data traffic is intercepted, captured, and analyzed. This also allows the adversary to use "adversary-in-the-middle" (CAPEC-94) for all communications.

## Related CWE (1)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html) — The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or…

## Prerequisites

- None

## Consequences

- Confidentiality / Read Data

## Mitigations

- Commercial defensive technology that monitors for rogue Wi-Fi access points, adversary-in-the-middle attacks, and anomalous activity with the mobile device baseband radios.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
