# CAPEC-510 — SaaS User Request Forgery

<a id="capec-510"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

An adversary, through a previously installed malicious application, performs malicious actions against a third-party Software as a Service (SaaS) application (also known as a cloud based application) by leveraging the persistent and implicit trust placed on a trusted user's session. This attack is executed after a trusted user is authenticated into a cloud service, piggy-backing on the authenticat

## Related CWE (1)

- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

## Prerequisites

- An adversary must be able install a purpose built malicious application onto the trusted user's system and convince the user to execute it while authenticated to the SaaS application.

## Skills required

- This attack pattern often requires the technical ability to modify a malicious software package (e.g. Zeus) to spider a targeted site and a wa

## Mitigations

- To limit one's exposure to this type of attack, tunnel communications through a secure proxy service.
- Detection of this type of attack can be done through heuristic analysis of behavioral anomalies (a la credit card fraud detection) which can be u

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
