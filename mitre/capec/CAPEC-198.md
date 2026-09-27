# CAPEC-198 — XSS Targeting Error Pages

<a id="capec-198"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary distributes a link (or possibly some other query structure) with a request to a third party web server that is malformed and also contains a block of exploit code in order to have the exploit become live code in the resulting error page.

## Related CWE (1)

[CWE-81](/CWE_REFERENCE.md)

**Prerequisites:** ::A third party web server which fails to adequately sanitize messages sent in error pages.::The victim must be made to execute a query crafted by the adversary which results in the infected error rep

**Mitigations:** ::Design: Use libraries and templates that minimize unfiltered input.::Implementation: Normalize, filter and use an allowlist for any input that will be used in error messages.::Implementation: The victim should configure the browser to minimize acti


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
