# CAPEC-664 — Server Side Request Forgery

<a id="capec-664"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

An adversary exploits improper input validation by submitting maliciously crafted input to a target application running on a server, with the goal of forcing the server to make a request either to itself, to web services running in the server’s internal network, or to external third parties. If successful, the adversary’s request will be made with the server’s privilege level, bypassing its authentication controls. This ultimately allows the adversary to access sensitive data, execute commands on the server’s network, and make external requests with the stolen identity of the server. Server Side Request Forgery attacks differ from Cross Site Request Forgery attacks in that they target the server itself, whereas CSRF attacks exploit an insecure user authentication mechanism to perform unauthorized actions on the user's behalf.

## Related CWE (2)

- [CWE-918 — Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html) — The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- Server must be running a web application that processes HTTP requests.

## Skills required

- [Medium] The adversary will have to detect the vulnerability through an intermediary service or specify maliciously crafted URLs and analyze the server response.
- [High] The adversary will be required to access internal resources, extract information, or leverage the services running on the server to perform unauthorized actions such as traversing the local network or routing a reflected TCP DDoS through them.

## Consequences

- Integrity, Confidentiality, Availability / Modify Data
- Confidentiality / Read Data
- Availability / Resource Consumption

## Mitigations

- Handling incoming requests securely is the first line of action to mitigate this vulnerability. This can be done through URL validation.
- Further down the process flow, examining the response and verifying that it is as expected before sending would be another way to secure the server.
- Allowlist the DNS name or IP address of every service the web application is required to access is another effective security measure. This ensures the server cannot make external requests to arbitrary services.
- Requiring authentication for local services adds another layer of security between the adversary and internal services running on the server. By enforcing local authentication, an adversary will not gain access to all internal services only with access to the server.
- Enforce the usage of relevant URL schemas. By limiting requests be made only through HTTP or HTTPS, for example, attacks made through insecure schemas such as file://, ftp://, etc. can be prevented.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
