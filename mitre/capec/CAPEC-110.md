# CAPEC-110: SQL Injection through SOAP Parameter Tampering

<a id="capec-110"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An attacker modifies the parameters of the SOAP message that is sent from the service consumer to the service provider to initiate a SQL injection attack. On the service provider side, the SOAP message is parsed and parameters are not properly validated before being used to access a database in a way that does not use parameter binding, thus enabling the attacker to control the structure of the executed SQL query. This pattern describes a SQL injection attack with the delivery mechanism being a SOAP message.

## Related CWE (2)

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html): The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- SOAP messages are used as a communication mechanism in the system
- SOAP parameters are not properly validated at the service provider
- The service provider does not properly utilize parameter binding when building SQL queries

## Skills required

- [Medium] If the attacker is able to gain good understanding of the system's database schema
- [High] If the attacker has to perform Blind SQL Injection

## Consequences

- Integrity / Modify Data
- Availability / Unreliable Execution
- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Properly validate and sanitize/reject user input at the service provider.
- Ensure that prepared statements or other mechanism that enables parameter binding is used when accessing the database in a way that would prevent the attackers' supplied data from controlling the structure of the executed query.
- At the database level, ensure that the database user used by the application in a particular context has the minimum needed privileges to the database that are needed to perform the operation. When possible, run queries against pre-generated views rather than the tables directly.

## Related pages

- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-20 and CWE-89
- [CAPEC-108: Command Line Execution through SQL Injection](/mitre/capec/CAPEC-108.md), also related to CWE-20 and CWE-89
- [CAPEC-109: Object Relational Mapping Injection](/mitre/capec/CAPEC-109.md), also related to CWE-20 and CWE-89
- [CAPEC-66: SQL Injection](/mitre/capec/CAPEC-66.md), also related to CWE-89
- [CAPEC-470: Expanding Control over the Operating System from the Database](/mitre/capec/CAPEC-470.md), also related to CWE-89
- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
