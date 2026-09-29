# CAPEC-57 — Utilizing REST's Trust in the System Resource to Obtain Sensitive Data

<a id="capec-57"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Draft  

This attack utilizes a REST(REpresentational State Transfer)-style applications' trust in the system resources and environment to obtain sensitive data once SSL is terminated.

## Mapped ATT&CK techniques (1)

- [T1040 — Network Sniffing](/mitre/techniques/T1040.md) — Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.

## Related CWE (3)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html) — The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.
- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) — When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- Opportunity to intercept must exist beyond the point where SSL is terminated.
- The adversary must be able to insert a listener actively (proxying the communication) or passively (sniffing the communication) in the client-server communication path.

## Skills required

- [Low] To insert a network sniffer or other listener into the communication stream

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Implementation: Implement message level security such as HMAC in the HTTP communication
- Design: Utilize defense in depth, do not rely on a single security mechanism like SSL
- Design: Enforce principle of least privilege

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
