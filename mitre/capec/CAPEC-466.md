# CAPEC-466 — Leveraging Active Adversary in the Middle Attacks to Bypass Same Origin Policy

<a id="capec-466"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An attacker leverages an adversary in the middle attack (CAPEC-94) in order to bypass the same origin policy protection in the victim's browser. This active adversary in the middle attack could be launched, for instance, when the victim is connected to a public WIFI hot spot. An attacker is able to intercept requests and responses between the victim's browser and some non-sensitive website that do

## Related CWE (1)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

## Prerequisites

- The victim and the attacker are both in an environment where an active adversary in the middle attack is possible (e.g., public WIFI hot spot)The victim visits at least one website that does not use

## Skills required

- Ability to intercept and modify requests / responses:LEVEL:Low
- Ability to create iFrame and JavaScript code that would initiate unautho

## Mitigations

- Design: Tunnel communications through a secure proxy
- Design: Trust level separation for privileged / non privileged interactions (e.g., two different browsers, two different users, two different operating systems, two different virtual machines)

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
