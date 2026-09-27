# CAPEC-110 — SQL Injection through SOAP Parameter Tampering

<a id="capec-110"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attacker modifies the parameters of the SOAP message that is sent from the service consumer to the service provider to initiate a SQL injection attack. On the service provider side, the SOAP message is parsed and parameters are not properly validated before being used to access a database in a way that does not use parameter binding, thus enabling the attacker to control the structure of the ex

## Related CWE (2)

- [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) — The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended…
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- SOAP messages are used as a communication mechanism in the system
- SOAP parameters are not properly validated at the service provider
- The service provider does not properly utilize parameter bindin

## Skills required

- If the attacker is able to gain good understanding of the system's database schema:LEVEL:Medium
- If the attacker has to perform Blind SQ

## Mitigations

- Properly validate and sanitize/reject user input at the service provider.
- Ensure that prepared statements or other mechanism that enables parameter binding is used when accessing the database in a way that would prevent the attackers' supplied dat

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
