# CAPEC-502 — Intent Spoof

<a id="capec-502"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary, through a previously installed malicious application, issues an intent directed toward a specific trusted application's component in an attempt to achieve a variety of different objectives including modification of data, information disclosure, and data injection. Components that have been unintentionally exported and made public are subject to this type of an attack. If the componen

## Related CWE (1)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) — The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Prerequisites

- An adversary must be able install a purpose built malicious application onto the Android device and convince the user to execute it. The malicious application will be used to issue spoofed intents.:

## Mitigations

- To limit one's exposure to this type of attack, developers should avoid exporting components unless the component is specifically designed to handle requests from untrusted applications. Developers should be aware that declaring an intent filter wi

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
