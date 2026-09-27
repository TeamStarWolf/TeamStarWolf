# CAPEC-609 — Cellular Traffic Intercept

<a id="capec-609"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

Cellular traffic for voice and data from mobile devices and retransmission devices can be intercepted via numerous methods. Malicious actors can deploy their own cellular tower equipment and intercept cellular traffic surreptitiously. Additionally, government agencies of adversaries and malicious actors can intercept cellular traffic via the telecommunications backbone over which mobile traffic is

## Mapped ATT&CK techniques (1)

- [T1111](/mitre/techniques/T1111.md)

## Related CWE (1)

[CWE-311](/CWE_REFERENCE.md)

**Prerequisites:** ::None::

**Skills required:** ::SKILL:Adversaries can purchase hardware and software solutions, or create their own solutions, to capture/intercept cellular radio traffic. The cost

**Mitigations:** ::Encryption of all data packets emanating from the smartphone to a retransmission device via two encrypted tunnels with Suite B cryptography, all the way to the VPN gateway at the datacenter.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
