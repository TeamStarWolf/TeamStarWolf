# CAPEC-219 — XML Routing Detour Attacks

<a id="capec-219"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

An attacker subverts an intermediate system used to process XML content and forces the intermediate to modify and/or re-route the processing of the content. XML Routing Detour Attacks are Adversary in the Middle type attacks (CAPEC-94). The attacker compromises or inserts an intermediate system in the processing of the XML message. For example, WS-Routing can be used to specify a series of nodes or intermediaries through which content is passed. If any of the intermediate nodes in this route are compromised by an attacker they could be used for a routing detour attack. From the compromised system the attacker is able to route the XML process to other nodes of their choice and modify the responses so that the normal chain of processing is unaware of the interception. This system can forward the message to an outside entity and hide the forwarding and processing from the legitimate processing systems by altering the header information.

## Related CWE (2)

- [CWE-441 — Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html) — The product receives a request, message, or directive from an upstream component, but the product does not sufficiently preserve the original source of the request before forwarding the request to an external actor that…
- [CWE-610 — Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html) — The product uses an externally controlled name or reference that resolves to a resource that is outside of the intended control sphere.

## Prerequisites

- The targeted system must have multiple stages processing of XML content.

## Skills required

- [Low] To inject a bogus node in the XML routing table

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Design: Specify maximum number intermediate nodes for the request and require SSL connections with mutual authentication.
- Implementation: Use SSL for connections between all parties with mutual authentication.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
