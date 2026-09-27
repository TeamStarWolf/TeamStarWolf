# CAPEC-77 — Manipulating User-Controlled Variables

<a id="capec-77"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

This attack targets user controlled variables (DEBUG=1, PHP Globals, and So Forth). An adversary can override variables leveraging user-supplied, untrusted query variables directly used on the application server without any data sanitization. In extreme cases, the adversary can change variables controlling the business logic of the application. For instance, in languages like PHP, a number of poor

## Related CWE (7)

[CWE-15](/CWE_REFERENCE.md) [CWE-94](/CWE_REFERENCE.md) [CWE-96](/CWE_REFERENCE.md) [CWE-285](/CWE_REFERENCE.md) [CWE-302](/CWE_REFERENCE.md) [CWE-473](/CWE_REFERENCE.md) [CWE-1321](/CWE_REFERENCE.md)

**Prerequisites:** ::A variable consumed by the application server is exposed to the client.::A variable consumed by the application server can be overwritten by the user.::The application server trusts user supplied da

**Skills required:** ::SKILL:The malicious user can easily try some well-known global variables and find one which matches.:LEVEL:Low::SKILL:The adversary can use automate

**Mitigations:** ::Do not allow override of global variables and do Not Trust Global Variables. If the register_globals option is enabled, PHP will create global variables for each GET, POST, and cookie variable included in the HTTP request. This means that a malicio


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
