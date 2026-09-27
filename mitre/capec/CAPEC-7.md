# CAPEC-7 — Blind SQL Injection

<a id="capec-7"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

Blind SQL Injection results from an insufficient mitigation for SQL Injection. Although suppressing database error messages are considered best practice, the suppression alone is not sufficient to prevent SQL Injection. Blind SQL Injection is a form of SQL Injection that overcomes the lack of error messages. Without the error messages that facilitate SQL Injection, the adversary constructs input s

## Related CWE (6)

[CWE-89](/CWE_REFERENCE.md) [CWE-209](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::SQL queries used by the application to store, retrieve or modify data.::User-controllable input that is not properly validated by the application as part of SQL queries.::

**Skills required:** ::SKILL:Determining the database type and version, as well as the right number and type of parameters to the query being injected in the absence of er

**Mitigations:** ::Security by Obscurity is not a solution to preventing SQL Injection. Rather than suppress error messages and exceptions, the application must handle them gracefully, returning either a custom error page or redirecting the user to a default page, wi


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
