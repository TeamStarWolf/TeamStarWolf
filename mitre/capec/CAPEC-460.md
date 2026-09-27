# CAPEC-460 — HTTP Parameter Pollution (HPP)

<a id="capec-460"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary adds duplicate HTTP GET/POST parameters by injecting query string delimiters. Via HPP it may be possible to override existing hardcoded HTTP parameters, modify the application behaviors, access and, potentially exploit, uncontrollable variables, and bypass input validation checkpoints and WAF rules.

## Related CWE (3)

[CWE-88](/CWE_REFERENCE.md) [CWE-147](/CWE_REFERENCE.md) [CWE-235](/CWE_REFERENCE.md)

**Prerequisites:** ::HTTP protocol is used with some GET/POST parameters passed::

**Mitigations:** ::Configuration: If using a Web Application Firewall (WAF), filters should be carefully configured to detect abnormal HTTP requests::Design: Perform URL encoding::Implementation: Use strict regular expressions in URL rewriting::Implementation: Beware


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
