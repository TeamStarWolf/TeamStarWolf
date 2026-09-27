# CAPEC-134 — Email Injection

<a id="capec-134"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

An adversary manipulates the headers and content of an email message by injecting data via the use of delimiter characters native to the protocol.

## Related CWE (1)

[CWE-150](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must allow the user to send email to some recipient, to specify the content at least one header field in the message, and must fail to sanitize against the injection of comman


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
