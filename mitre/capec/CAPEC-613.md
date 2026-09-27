# CAPEC-613 — WiFi SSID Tracking

<a id="capec-613"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

In this attack scenario, the attacker passively listens for WiFi management frame messages containing the Service Set Identifier (SSID) for the WiFi network. These messages are frequently transmitted by WiFi access points (e.g., the retransmission device) as well as by clients that are accessing the network (e.g., the handset/mobile device). Once the attacker is able to associate an SSID with a pa

## Related CWE (2)

- [CWE-201 — Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html)
- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

## Prerequisites

- None

## Skills required

- Open source and commercial software tools are available and open databases of known WiFi SSID addresses are available online.:LEVEL:Low

## Mitigations

- Do not enable the feature of Hidden SSIDs (also known as Network Cloaking) – this option disables the usual broadcasting of the SSID by the access point, but forces the mobile handset to send requests on all supported radio channels which contains

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
