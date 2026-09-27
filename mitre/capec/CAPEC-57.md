# CAPEC-57 — Utilizing REST's Trust in the System Resource to Obtain Sensitive Data

<a id="capec-57"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Draft  

This attack utilizes a REST(REpresentational State Transfer)-style applications' trust in the system resources and environment to obtain sensitive data once SSL is terminated.

## Mapped ATT&CK techniques (1)

- [T1040 — Network Sniffing](/mitre/techniques/T1040.md)

## Related CWE (3)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Prerequisites

- Opportunity to intercept must exist beyond the point where SSL is terminated.
- The adversary must be able to insert a listener actively (proxying the communication) or passively (sniffing the commun

## Skills required

- To insert a network sniffer or other listener into the communication stream:LEVEL:Low

## Mitigations

- Implementation: Implement message level security such as HMAC in the HTTP communication
- Design: Utilize defense in depth, do not rely on a single security mechanism like SSL
- Design: Enforce principle of least privilege

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
