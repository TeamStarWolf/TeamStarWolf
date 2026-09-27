# CAPEC-699 — Eavesdropping on a Monitor

<a id="capec-699"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An Adversary can eavesdrop on the content of an external monitor through the air without modifying any cable or installing software, just capturing this signal emitted by the cable or video port, with this the attacker will be able to impact the confidentiality of the data without being detected by traditional security tools

## Related CWE (1)

- [CWE-1300 — Improper Protection of Physical Side Channels](https://cwe.mitre.org/data/definitions/1300.html)

## Prerequisites

- Victim should use an external monitor device
- Physical access to the target location and devices

## Skills required

- Knowledge of how to use the SDR and related software: With this knowledge, the adversary will find the correct frequency where the signal is b

## Mitigations

- Enhance: Increase the number of electromagnetic shield layers in the display ports and cables to contain or reduce the intensity of the leaked signal.
- Implement: Use a protocol that encrypts the video signal; in case the signal is intercepted the

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
