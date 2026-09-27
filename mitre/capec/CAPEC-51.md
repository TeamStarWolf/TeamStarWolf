# CAPEC-51 — Poison Web Service Registry

<a id="capec-51"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

SOA and Web Services often use a registry to perform look up, get schema information, and metadata about services. A poisoned registry can redirect (think phishing for servers) the service requester to a malicious service provider, provide incorrect information in schema or metadata, and delete information about service provider interfaces.

## Related CWE (3)

- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- The attacker must be able to write to resources or redirect access to the service registry.

## Skills required

- [Low] To identify and execute against an over-privileged system interface

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Design: Enforce principle of least privilege
- Design: Harden registry server and file access permissions
- Implementation: Implement communications to and from the registry using secure protocols

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
