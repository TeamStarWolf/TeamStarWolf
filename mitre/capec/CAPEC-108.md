# CAPEC-108 — Command Line Execution through SQL Injection

<a id="capec-108"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Low  
**Status:** Draft  

An attacker uses standard SQL injection methods to inject data into the command line for execution. This could be done directly through misuse of directives such as MSSQL_xp_cmdshell or indirectly through injection of data into the database that would be interpreted as shell commands. Sometime later, an unscrupulous backend application (or could be part of the functionality of the same application

## Related CWE (5)

- [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-114 — Process Control](https://cwe.mitre.org/data/definitions/114.html)

## Prerequisites

- The application does not properly validate data before storing in the database
- Backend application implicitly trusts the data stored in the database
- Malicious data is used on the backend as a comm

## Skills required

- The attacker most likely has to be familiar with the internal functionality of the system to launch this attack. Without that knowledge, there

## Mitigations

- Disable MSSQL xp_cmdshell directive on the database
- Properly validate the data (syntactically and semantically) before writing it to the database.
- Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
