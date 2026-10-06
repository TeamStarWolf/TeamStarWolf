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

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
