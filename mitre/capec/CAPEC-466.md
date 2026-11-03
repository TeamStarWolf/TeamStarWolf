# CAPEC-466: Leveraging Active Adversary in the Middle Attacks to Bypass Same Origin Policy

<a id="capec-466"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An attacker leverages an adversary in the middle attack (CAPEC-94) in order to bypass the same origin policy protection in the victim's browser. This active adversary in the middle attack could be launched, for instance, when the victim is connected to a public WIFI hot spot. An attacker is able to intercept requests and responses between the victim's browser and some non-sensitive website that does not use TLS.

## Related CWE (1)

- [CWE-300: Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html): The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.

## Prerequisites

- The victim and the attacker are both in an environment where an active adversary in the middle attack is possible (e.g., public WIFI hot spot)The victim visits at least one website that does not use TLS / SSL

## Skills required

- [Low] Ability to intercept and modify requests / responses
- [Medium] Ability to create iFrame and JavaScript code that would initiate unauthorized requests to sensitive sites from the victim's browser
- [Medium] Solid understanding of the HTTP protocol

## Consequences

- Confidentiality / Read Data
- Authorization / Execute Unauthorized Commands

## Mitigations

- Design: Tunnel communications through a secure proxy
- Design: Trust level separation for privileged / non privileged interactions (e.g., two different browsers, two different users, two different operating systems, two different virtual machines)

## Related pages

- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), named in the description above
- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-300
- [CAPEC-589: DNS Blocking](/mitre/capec/CAPEC-589.md), also related to CWE-300
- [CAPEC-590: IP Address Blocking](/mitre/capec/CAPEC-590.md), also related to CWE-300
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-300
- [CAPEC-613: WiFi SSID Tracking](/mitre/capec/CAPEC-613.md), also related to CWE-300
- [CAPEC-615: Evil Twin Wi-Fi Attack](/mitre/capec/CAPEC-615.md), also related to CWE-300
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
