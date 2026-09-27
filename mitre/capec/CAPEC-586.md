# CAPEC-586 — Object Injection

<a id="capec-586"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary attempts to exploit an application by injecting additional, malicious content during its processing of serialized objects. Developers leverage serialization in order to convert data or state into a static, binary format for saving to disk or transferring over a network. These objects are then deserialized when needed to recover the data/state. By injecting a malformed object into a vu

## Related CWE (1)

- [CWE-502 — Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) — The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.

## Prerequisites

- The target application must unserialize data before validation.

## Mitigations

- Implementation: Validate object before deserialization process
- Design: Limit which types can be deserialized.
- Implementation: Avoid having unnecessary types or gadgets available that can be leveraged for malicious ends. Use an allowlist of accept

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
