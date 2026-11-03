# CAPEC-589: DNS Blocking

<a id="capec-589"></a>

Abstraction: Detailed  
Status: Draft  

An adversary intercepts traffic and intentionally drops DNS requests based on content in the request. In this way, the adversary can deny the availability of specific services or content to the user even if the IP address is changed.

## Related CWE (1)

- [CWE-300: Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html): The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.

## Prerequisites

- This attack requires the ability to conduct deep packet inspection with an In-Path device that can drop the targeted traffic and/or connection.

## Consequences

- Availability / Other

## Mitigations

- Hard Coded Alternate DNS server in applications
- Avoid dependence on DNS
- Include "hosts file"/IP address in the application.
- Ensure best practices with respect to communications channel protections.
- Use a .onion domain with Tor support

## Related pages

- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-300
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-300
- [CAPEC-466: Leveraging Active Adversary in the Middle Attacks to Bypass Same Origin Policy](/mitre/capec/CAPEC-466.md), also related to CWE-300
- [CAPEC-590: IP Address Blocking](/mitre/capec/CAPEC-590.md), also related to CWE-300
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-300
- [CAPEC-613: WiFi SSID Tracking](/mitre/capec/CAPEC-613.md), also related to CWE-300
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
