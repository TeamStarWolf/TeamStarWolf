# CAPEC-676 — NoSQL Injection

<a id="capec-676"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary targets software that constructs NoSQL statements based on user input or with parameters vulnerable to operator replacement in order to achieve a variety of technical impacts such as escalating privileges, bypassing authentication, and/or executing code.

## Related CWE (2)

[CWE-943](/CWE_REFERENCE.md) [CWE-1286](/CWE_REFERENCE.md)

**Prerequisites:** ::Awareness of the technology stack being leveraged by the target application.::NoSQL queries used by the application to store, retrieve, or modify data.::User-controllable input that is not properly 

**Skills required:** ::SKILL:For keyword and JavaScript injection attacks, it is fairly simple for someone with basic NoSQL knowledge to perform NoSQL injection, once the 

**Mitigations:** ::Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as relevant NoSQL and JavaScript content. NoSQL-specific keywords, such as $ne, $eq or $gt for MongoDB, must be filtered in addition


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
