# CAPEC-243 — XSS Targeting HTML Attributes

<a id="capec-243"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary inserts commands to perform cross-site scripting (XSS) actions in HTML attributes. Many filters do not adequately sanitize attributes against the presence of potentially dangerous commands even if they adequately sanitize tags. For example, dangerous expressions could be inserted into a style attribute in an anchor tag, resulting in the execution of malicious code when the resulting p

## Related CWE (1)

[CWE-83](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must fail to adequately sanitize HTML attributes against the presence of dangerous commands.::

**Mitigations:** ::Design: Use libraries and templates that minimize unfiltered input.::Implementation: Normalize, filter and use an allowlist for all input including that which is not expected to have any scripting content.::Implementation: The victim should configu


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
