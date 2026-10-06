# CAPEC-105: HTTP Request Splitting

<a id="capec-105"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary abuses the flexibility and discrepancies in the parsing and interpretation of HTTP Request messages by different intermediary HTTP agents (e.g., load balancer, reverse proxy, web caching proxies, application firewalls, etc.) to split a single HTTP request into multiple unauthorized and malicious HTTP requests to a back-end HTTP agent (e.g., web server). See CanPrecede relationships for possible consequences.

## Related CWE (4)

- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')](https://cwe.mitre.org/data/definitions/113.html): The product receives data from an HTTP agent/component (e.g., web server, proxy, browser, etc.), but it does not neutralize or incorrectly neutralizes CR and LF characters before the data is included in outgoing HTTP headers.
- [CWE-138: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as control elements or syntactic markers when they are sent to a downstream component.
- [CWE-436: Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html): Product A handles inputs or steps differently than Product B, which causes A to perform incorrect actions based on its perception of B's state.

## Prerequisites

- An additional intermediary HTTP agent such as an application firewall or a web caching proxy between the adversary and the second agent such as a web server, that sends multiple HTTP messages over same network connection.
- Differences in the way the two HTTP agents parse and interpret HTTP requests and its headers.
- HTTP headers capable of being user-manipulated.
- HTTP agents running on HTTP/1.0 or HTTP/1.1 that allow for Keep Alive mode, Pipelined queries, and Chunked queries and responses.

## Skills required

- [Medium] Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.
- [Medium] Detailed knowledge on how specific HTTP agents receive, send, process, interpret, and parse a variety of HTTP messages and headers.
- [Medium] Possess knowledge on the exact details in the discrepancies between several targeted HTTP agents in path of an HTTP message in parsing its message structure and individual headers.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.
- Configuration: front-end HTTP agents notice ambiguous requests.
- Configuration: back-end HTTP agents reject ambiguous requests and close the network connection.
- Configuration: Disable reuse of back-end connections.
- Configuration: Use HTTP/2 for back-end connections.
- Configuration: Use the same web server software for front-end and back-end server.
- Implementation: Utilize a Web Application Firewall (WAF) that has built-in mitigation to detect abnormal requests/responses.
- Configuration: Install latest vendor security patches available for both intermediary and back-end HTTP infrastructure (i.e. proxies and web servers)
- Configuration: Ensure that HTTP infrastructure in the chain or network path utilize a strict uniform parsing process.
- Implementation: Utilize intermediary HTTP infrastructure capable of filtering and/or sanitizing user-input.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
