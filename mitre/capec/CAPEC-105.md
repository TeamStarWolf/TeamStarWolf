# CAPEC-105 — HTTP Request Splitting

<a id="capec-105"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary abuses the flexibility and discrepancies in the parsing and interpretation of HTTP Request messages by different intermediary HTTP agents (e.g., load balancer, reverse proxy, web caching proxies, application firewalls, etc.) to split a single HTTP request into multiple unauthorized and malicious HTTP requests to a back-end HTTP agent (e.g., web server). See CanPrecede relationships fo

## Related CWE (4)

[CWE-74](/CWE_REFERENCE.md) [CWE-113](/CWE_REFERENCE.md) [CWE-138](/CWE_REFERENCE.md) [CWE-436](/CWE_REFERENCE.md)

**Prerequisites:** ::An additional intermediary HTTP agent such as an application firewall or a web caching proxy between the adversary and the second agent such as a web server, that sends multiple HTTP messages over s

**Skills required:** ::SKILL:Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.:LEVEL:Medium::SKILL:Detailed knowl

**Mitigations:** ::Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.::Configuration: front-end HTTP agents notice ambiguous requests.::Configuration: back-end HTTP agents reject ambiguous requests and close the network connect


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
