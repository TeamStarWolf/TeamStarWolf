# CAPEC-110 — SQL Injection through SOAP Parameter Tampering

<a id="capec-110"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

An attacker modifies the parameters of the SOAP message that is sent from the service consumer to the service provider to initiate a SQL injection attack. On the service provider side, the SOAP message is parsed and parameters are not properly validated before being used to access a database in a way that does not use parameter binding, thus enabling the attacker to control the structure of the ex

## Related CWE (2)

[CWE-89](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md)

**Prerequisites:** ::SOAP messages are used as a communication mechanism in the system::SOAP parameters are not properly validated at the service provider::The service provider does not properly utilize parameter bindin

**Skills required:** ::SKILL:If the attacker is able to gain good understanding of the system's database schema:LEVEL:Medium::SKILL:If the attacker has to perform Blind SQ

**Mitigations:** ::Properly validate and sanitize/reject user input at the service provider.::Ensure that prepared statements or other mechanism that enables parameter binding is used when accessing the database in a way that would prevent the attackers' supplied dat


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
