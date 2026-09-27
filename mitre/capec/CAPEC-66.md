# CAPEC-66 — SQL Injection

<a id="capec-66"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

This attack exploits target software that constructs SQL statements based on user input. An attacker crafts input strings so that when the target software constructs SQL statements based on the input, the resulting SQL statement performs actions other than those the application intended. SQL Injection results from failure of the application to appropriately validate input.

## Related CWE (2)

[CWE-89](/CWE_REFERENCE.md) [CWE-1286](/CWE_REFERENCE.md)

**Prerequisites:** ::SQL queries used by the application to store, retrieve or modify data.::User-controllable input that is not properly validated by the application as part of SQL queries.::

**Skills required:** ::SKILL:It is fairly simple for someone with basic SQL knowledge to perform SQL injection, in general. In certain instances, however, specific knowled

**Mitigations:** ::Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as SQL content. Keywords such as UNION, SELECT or INSERT must be filtered in addition to characters such as a single-quote(') or SQL


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
