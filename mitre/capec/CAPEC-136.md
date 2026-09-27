# CAPEC-136 — LDAP Injection

<a id="capec-136"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attacker manipulates or crafts an LDAP query for the purpose of undermining the security of the target. Some applications use user input to create LDAP queries that are processed by an LDAP server. For example, a user might provide their username during authentication and the username might be inserted in an LDAP query during the authentication process. An attacker could use this input to injec

## Related CWE (3)

- [CWE-77 — Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
- [CWE-90 — Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Prerequisites

- The target application must accept a string as user input, fail to sanitize characters that have a special meaning in LDAP queries in the user input, and insert the user-supplied string in an LDAP q

## Skills required

- The attacker needs to have knowledge of LDAP, especially its query syntax.:LEVEL:Medium

## Mitigations

- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content.
- Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error mes

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
