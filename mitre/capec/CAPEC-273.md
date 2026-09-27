# CAPEC-273 — HTTP Response Smuggling

<a id="capec-273"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary manipulates and injects malicious content in the form of secret unauthorized HTTP responses, into a single HTTP response from a vulnerable or compromised back-end HTTP agent (e.g., server). See CanPrecede relationships for possible consequences.

## Related CWE (3)

- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-436 — Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)
- [CWE-444 — Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

## Prerequisites

- A vulnerable or compromised server or domain/site capable of allowing adversary to insert/inject malicious content that will appear in the server's response to target HTTP agents (e.g., proxies and

## Skills required

- Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.:LEVEL:Medium
- Detailed knowl

## Mitigations

- Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.
- Configuration: front-end HTTP agents notice ambiguous requests.
- Configuration: back-end HTTP agents reject ambiguous requests and close the network connect

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
