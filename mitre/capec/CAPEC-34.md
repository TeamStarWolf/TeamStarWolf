# CAPEC-34 — HTTP Response Splitting

<a id="capec-34"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary manipulates and injects malicious content, in the form of secret unauthorized HTTP responses, into a single HTTP response from a vulnerable or compromised back-end HTTP agent (e.g., web server) or into an already spoofed HTTP response from an adversary controlled domain/site. See CanPrecede relationships for possible consequences.

## Related CWE (4)

[CWE-74](/CWE_REFERENCE.md) [CWE-113](/CWE_REFERENCE.md) [CWE-138](/CWE_REFERENCE.md) [CWE-436](/CWE_REFERENCE.md)

**Prerequisites:** ::A vulnerable or compromised server or domain/site capable of allowing adversary to insert/inject malicious content that will appear in the server's response to target HTTP agents (e.g., proxies and 

**Skills required:** ::SKILL:Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.:LEVEL:Medium::SKILL:Detailed knowl

**Mitigations:** ::Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.::Configuration: front-end HTTP agents notice ambiguous requests.::Configuration: back-end HTTP agents reject ambiguous requests and close the network connect


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
