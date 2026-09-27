# CAPEC-84 — XQuery Injection

<a id="capec-84"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

This attack utilizes XQuery to probe and attack server systems; in a similar manner that SQL Injection allows an attacker to exploit SQL calls to RDBMS, XQuery Injection uses improperly validated data that is passed to XQuery commands to traverse and execute commands that the XQuery routines have access to. XQuery injection can be used to enumerate elements on the victim's environment, inject comm

## Related CWE (2)

- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)

## Prerequisites

- The XQL must execute unvalidated data

## Skills required

- Basic understanding of XQuery:LEVEL:Low

## Mitigations

- Design: Perform input allowlist validation on all XML input
- Implementation: Run xml parsing and query infrastructure with minimal privileges so that an attacker is limited in their ability to probe other system resources from XQL.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
