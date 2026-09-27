# CAPEC-604 — Wi-Fi Jamming

<a id="capec-604"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

In this attack scenario, the attacker actively transmits on the Wi-Fi channel to prevent users from transmitting or receiving data from the targeted Wi-Fi network. There are several known techniques to perform this attack – for example: the attacker may flood the Wi-Fi access point (e.g. the retransmission device) with deauthentication frames. Another method is to transmit high levels of noise on

**Prerequisites:** ::Lack of anti-jam features in 802.11::Lack of authentication on deauthentication/disassociation packets on 802.11-based networks::

**Skills required:** ::SKILL:This attack can be performed by low capability attackers with freely available tools. Commercial tools are also available that can target sele

**Mitigations:** ::Countermeasures have been proposed for both disassociation flooding and RF jamming, however these countermeasures are not standardized and would need to be supported on both the retransmission device and the handset in order to be effective. Commer


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
