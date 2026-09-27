# CAPEC-384 — Application API Message Manipulation via Man-in-the-Middle

<a id="capec-384"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Status:** Draft  

An attacker manipulates either egress or ingress data from a client within an application framework in order to change the content of messages. Performing this attack can allow the attacker to gain unauthorized privileges within the application, or conduct attacks such as phishing, deceptive strategies to spread malware, or traditional web-application attacks. The techniques require use of special

## Related CWE (5)

- [CWE-471 — Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

## Prerequisites

- Targeted software is utilizing application framework APIs

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
