# CAPEC-604: Wi-Fi Jamming

<a id="capec-604"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  
OpenCRE: [CAPEC-604](https://opencre.org/smartlink/standard/CAPEC/604)  

In this attack scenario, the attacker actively transmits on the Wi-Fi channel to prevent users from transmitting or receiving data from the targeted Wi-Fi network. There are several known techniques to perform this attack – for example: the attacker may flood the Wi-Fi access point (e.g. the retransmission device) with deauthentication frames. Another method is to transmit high levels of noise on the RF band used by the Wi-Fi network.

## Prerequisites

- Lack of anti-jam features in 802.11
- Lack of authentication on deauthentication/disassociation packets on 802.11-based networks

## Skills required

- [Low] This attack can be performed by low capability attackers with freely available tools. Commercial tools are also available that can target select networks or all WiFi networks within a range of several miles.

## Consequences

- Availability / Other
- Availability / Resource Consumption

## Mitigations

- Countermeasures have been proposed for both disassociation flooding and RF jamming, however these countermeasures are not standardized and would need to be supported on both the retransmission device and the handset in order to be effective. Commercial products are not currently available that support jamming countermeasures for Wi-Fi.

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
