# CAPEC-193 — PHP Remote File Inclusion

<a id="capec-193"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

In this pattern the adversary is able to load and execute arbitrary code remotely available from the application. This is usually accomplished through an insecurely configured PHP runtime environment and an improperly sanitized include or require call, which the user can then control to point to any web-accessible file. This allows adversaries to hijack the targeted application and force it to exe

## Related CWE (2)

[CWE-98](/CWE_REFERENCE.md) [CWE-80](/CWE_REFERENCE.md)

**Prerequisites:** ::Target application server must allow remote files to be included in the require, include, etc. PHP directives::The adversary must have the ability to make HTTP requests to the target web application

**Skills required:** ::SKILL:To inject the malicious payload in a web page:LEVEL:Low::SKILL:To bypass filters in the application:LEVEL:Medium::

**Mitigations:** ::Implementation: Perform input validation for all remote content, including remote and user-generated content::Implementation: Only allow known files to be included (allowlist)::Implementation: Make use of indirect references passed in URL parameter


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
