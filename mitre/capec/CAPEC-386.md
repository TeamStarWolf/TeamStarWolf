# CAPEC-386 — Application API Navigation Remapping

<a id="capec-386"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An attacker manipulates either egress or ingress data from a client within an application framework in order to change the destination and/or content of links/buttons displayed to a user within API messages. Performing this attack allows the attacker to manipulate content in such a way as to produce messages or content that looks authentic but contains links/buttons that point to an attacker controlled destination. Some applications make navigation remapping more difficult to detect because the actual HREF values of images, profile elements, and links/buttons are masked. One example would be to place an image in a user's photo gallery that when clicked upon redirected the user to an off-site location. Also, traditional web vulnerabilities (such as CSRF) can be constructed with remapped buttons or links. In some cases navigation remapping can be used for Phishing attacks or even means to artificially boost the page view, user site reputation, or click-fraud.

## Related CWE (5)

- [CWE-471 — Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html) — The product does not properly protect an assumed-immutable element from being modified by an attacker.
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) — The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) — The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html) — The product does not encrypt sensitive or critical information before storage or transmission.

## Prerequisites

- Targeted software is utilizing application framework APIs

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
