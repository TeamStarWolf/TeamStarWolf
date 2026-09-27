# CAPEC-499 — Android Intent Intercept

<a id="capec-499"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary, through a previously installed malicious application, intercepts messages from a trusted Android-based application in an attempt to achieve a variety of different objectives including denial of service, information disclosure, and data injection. An implicit intent sent from a trusted application can be received by any application that has declared an appropriate intent filter. If th

## Related CWE (1)

- [CWE-925 — Improper Verification of Intent by Broadcast Receiver](https://cwe.mitre.org/data/definitions/925.html) — The Android application uses a Broadcast Receiver that receives an Intent but does not properly verify that the Intent came from an authorized source.

## Prerequisites

- An adversary must be able install a purpose built malicious application onto the Android device and convince the user to execute it. The malicious application is used to intercept implicit intents.:

## Mitigations

- To mitigate this type of an attack, explicit intents should be used whenever sensitive data is being sent. An explicit intent is delivered to a specific application as declared within the intent, whereas the Android operating system determines who

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
