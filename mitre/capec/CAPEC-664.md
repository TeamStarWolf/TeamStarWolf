# CAPEC-664 — Server Side Request Forgery

<a id="capec-664"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary exploits improper input validation by submitting maliciously crafted input to a target application running on a server, with the goal of forcing the server to make a request either to itself, to web services running in the server’s internal network, or to external third parties. If successful, the adversary’s request will be made with the server’s privilege level, bypassing its authen

## Related CWE (2)

[CWE-918](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md)

**Prerequisites:** ::Server must be running a web application that processes HTTP requests.::

**Skills required:** ::SKILL:The adversary will have to detect the vulnerability through an intermediary service or specify maliciously crafted URLs and analyze the server

**Mitigations:** ::Handling incoming requests securely is the first line of action to mitigate this vulnerability. This can be done through URL validation.::Further down the process flow, examining the response and verifying that it is as expected before sending woul


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
