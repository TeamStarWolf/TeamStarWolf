# CAPEC-7 — Blind SQL Injection

<a id="capec-7"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

Blind SQL Injection results from an insufficient mitigation for SQL Injection. Although suppressing database error messages are considered best practice, the suppression alone is not sufficient to prevent SQL Injection. Blind SQL Injection is a form of SQL Injection that overcomes the lack of error messages. Without the error messages that facilitate SQL Injection, the adversary constructs input strings that probe the target through simple Boolean SQL expressions. The adversary can determine if the syntax and structure of the injection was successful based on whether the query was executed or not. Applied iteratively, the adversary determines how and where the target is vulnerable to SQL Injection.

## Related CWE (6)

- [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) — The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended…
- [CWE-209 — Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) — The product generates an error message that includes sensitive information about its environment, users, or associated data.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html) — The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being read from an upstream component or sent to a downstream…

## Prerequisites

- SQL queries used by the application to store, retrieve or modify data.
- User-controllable input that is not properly validated by the application as part of SQL queries.

## Skills required

- [Medium] Determining the database type and version, as well as the right number and type of parameters to the query being injected in the absence of error messages requires greater skill than reverse-engineering database error messages.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Security by Obscurity is not a solution to preventing SQL Injection. Rather than suppress error messages and exceptions, the application must handle them gracefully, returning either a custom error page or redirecting the user to a default page, without revealing any information about the database or the application internals.
- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as SQL content. Keywords such as UNION, SELECT or INSERT must be filtered in addition to characters such as a single-quote(') or SQL-comments (--) based on the context in which they appear.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
