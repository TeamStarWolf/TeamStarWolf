# CAPEC-563 — Add Malicious File to Shared Webroot

<a id="capec-563"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversaries may add malicious content to a website through the open file share and then browse to that content with a web browser to cause the server to execute the content. The malicious content will typically run under the context and permissions of the web server process, often resulting in local system or administrative privileges depending on how the web server is configured.

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Mitigations:** ::Ensure proper permissions on directories that are accessible through a web server. Disallow remote access to the web root. Disable execution on directories within the web root. Ensure that permissions of the web server process are only what is requ


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
