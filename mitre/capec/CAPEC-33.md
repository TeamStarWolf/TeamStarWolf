# CAPEC-33 — HTTP Request Smuggling

<a id="capec-33"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary abuses the flexibility and discrepancies in the parsing and interpretation of HTTP Request messages using various HTTP headers, request-line and body parameters as well as message sizes (denoted by the end of message signaled by a given HTTP header) by different intermediary HTTP agents (e.g., load balancer, reverse proxy, web caching proxies, application firewalls, etc.) to secretly

## Related CWE (1)

[CWE-444](/CWE_REFERENCE.md)

**Prerequisites:** ::An additional intermediary HTTP agent such as an application firewall or a web caching proxy between the adversary and the second agent such as a web server, that sends multiple HTTP messages over s

**Skills required:** ::SKILL:Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.:LEVEL:Medium::SKILL:Detailed knowl

**Mitigations:** ::Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.::Configuration: front-end HTTP agents notice ambiguous requests.::Configuration: back-end HTTP agents reject ambiguous requests and close the network connect


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
