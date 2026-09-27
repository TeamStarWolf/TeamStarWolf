# CAPEC-33 — HTTP Request Smuggling

<a id="capec-33"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary abuses the flexibility and discrepancies in the parsing and interpretation of HTTP Request messages using various HTTP headers, request-line and body parameters as well as message sizes (denoted by the end of message signaled by a given HTTP header) by different intermediary HTTP agents (e.g., load balancer, reverse proxy, web caching proxies, application firewalls, etc.) to secretly send unauthorized and malicious HTTP requests to a back-end HTTP agent (e.g., web server). See CanPrecede relationships for possible consequences.

## Related CWE (1)

- [CWE-444 — Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html) — The product acts as an intermediary HTTP agent (such as a proxy or firewall) in the data flow between two entities such as a client and server, but it does not interpret malformed HTTP requests or responses in ways that…

## Prerequisites

- An additional intermediary HTTP agent such as an application firewall or a web caching proxy between the adversary and the second agent such as a web server, that sends multiple HTTP messages over same network connection.
- Differences in the way the two HTTP agents parse and interpret HTTP requests and its headers.
- HTTP agents running on HTTP/1.1 that allow for Keep Alive mode, Pipelined queries, and Chunked queries and responses.

## Skills required

- [Medium] Detailed knowledge on HTTP protocol: request and response messages structure and usage of specific headers.
- [Medium] Detailed knowledge on how specific HTTP agents receive, send, process, interpret, and parse a variety of HTTP messages and headers.
- [Medium] Possess knowledge on the exact details in the discrepancies between several targeted HTTP agents in path of an HTTP message in parsing its message structure and individual headers.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges
- Integrity / Modify Data

## Mitigations

- Design: evaluate HTTP agents prior to deployment for parsing/interpretation discrepancies.
- Configuration: front-end HTTP agents notice ambiguous requests.
- Configuration: back-end HTTP agents reject ambiguous requests and close the network connection.
- Configuration: Disable reuse of back-end connections.
- Configuration: Use HTTP/2 for back-end connections.
- Configuration: Use the same web server software for front-end and back-end server.
- Implementation: Utilize a Web Application Firewall (WAF) that has built-in mitigation to detect abnormal requests/responses.
- Configuration: Prioritize Transfer-Encoding header over Content-Length, whenever an HTTP message contains both.
- Configuration: Disallow HTTP messages with both Transfer-Encoding and Content-Length or Double Content-Length Headers.
- Configuration: Disallow Malformed/Invalid Transfer-Encoding Headers used in obfuscation, such as: Headers with no space before the value “chunked” Headers with extra spaces Headers beginning with trailing characters Headers providing a value “chunk” instead of “chunked” (the server normalizes this as chunked encoding) Headers with multiple spaces before the value “chunked” Headers with quoted values (whether single or double quotations) Headers with CRLF characters before the value “chunked” Values with invalid characters
- Configuration: Install latest vendor security patches available for both intermediary and back-end HTTP infrastructure (i.e. proxies and web servers)
- Configuration: Ensure that HTTP infrastructure in the chain or network path utilize a strict uniform parsing process.
- Implementation: Utilize intermediary HTTP infrastructure capable of filtering and/or sanitizing user-input.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
