# CAPEC-676 — NoSQL Injection

<a id="capec-676"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

An adversary targets software that constructs NoSQL statements based on user input or with parameters vulnerable to operator replacement in order to achieve a variety of technical impacts such as escalating privileges, bypassing authentication, and/or executing code.

## Related CWE (2)

- [CWE-943 — Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html) — The product generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.
- [CWE-1286 — Improper Validation of Syntactic Correctness of Input](https://cwe.mitre.org/data/definitions/1286.html) — The product receives input that is expected to be well-formed - i.e., to comply with a certain syntax - but it does not validate or incorrectly validates that the input complies with the syntax.

## Prerequisites

- Awareness of the technology stack being leveraged by the target application.
- NoSQL queries used by the application to store, retrieve, or modify data.
- User-controllable input that is not properly validated by the application as part of NoSQL queries.
- Target potentially susceptible to operator replacement attacks.

## Skills required

- [Low] For keyword and JavaScript injection attacks, it is fairly simple for someone with basic NoSQL knowledge to perform NoSQL injection, once the target's technology stack has been determined.
- [Medium] For operator replacement attacks, the adversary must also have knowledge of HTTP Parameter Pollution attacks and how to conduct them.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as relevant NoSQL and JavaScript content. NoSQL-specific keywords, such as $ne, $eq or $gt for MongoDB, must be filtered in addition to characters such as a single-quote(') or semicolons (;) based on the context in which they appear. Validation should also extend to expected types.
- If possible, leverage safe APIs (e.g., PyMongo and Flask-PyMongo for Python and MongoDB) for queries as opposed to building queries from strings.
- Ensure the most recent version of a NoSQL database and it's corresponding API are used by the application.
- Use of custom error pages - Adversaries can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.
- Exercise the principle of Least Privilege with regards to application accounts to minimize damage if a NoSQL injection attack is successful.
- If using MongoDB, disable server-side JavaScript execution and leverage a sanitization module such as "mongo-sanitize".
- If using PHP with MongoDB, ensure all special query operators (starting with $) use single quotes to prevent operator replacement attacks.
- Additional mitigations will depend on the NoSQL database, API, and programming language leveraged by the application.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
