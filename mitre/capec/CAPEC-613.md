# CAPEC-613: WiFi SSID Tracking

<a id="capec-613"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

In this attack scenario, the attacker passively listens for WiFi management frame messages containing the Service Set Identifier (SSID) for the WiFi network. These messages are frequently transmitted by WiFi access points (e.g., the retransmission device) as well as by clients that are accessing the network (e.g., the handset/mobile device). Once the attacker is able to associate an SSID with a particular user or set of users (for example, when attending a public event), the attacker can then scan for this SSID to track that user in the future.

## Related CWE (2)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.
- [CWE-300: Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html): The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.

## Skills required

- [Low] Open source and commercial software tools are available and open databases of known WiFi SSID addresses are available online.

## Mitigations

- Do not enable the feature of "Hidden SSIDs" (also known as "Network Cloaking") – this option disables the usual broadcasting of the SSID by the access point, but forces the mobile handset to send requests on all supported radio channels which contains the SSID. The result is that tracking of the mobile device becomes easier since it is transmitting the SSID more frequently.
- Frequently change the SSID to new and unrelated values

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
