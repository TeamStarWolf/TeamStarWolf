# CAPEC-183 — IMAP/SMTP Command Injection

<a id="capec-183"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An adversary exploits weaknesses in input validation on web-mail servers to execute commands on the IMAP/SMTP server. Web-mail servers often sit between the Internet and the IMAP or SMTP mail server. User requests are received by the web-mail servers which then query the back-end mail server for the requested information and return this response to the user. In an IMAP/SMTP command injection attack, mail-server commands are embedded in parts of the request sent to the web-mail server. If the web-mail server fails to adequately sanitize these requests, these commands are then sent to the back-end mail server when it is queried by the web-mail server, where the commands are then executed. This attack can be especially dangerous since administrators may assume that the back-end server is protected against direct Internet access and therefore may not secure it adequately against the execution of malicious commands.

## Related CWE (1)

- [CWE-77 — Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html) — The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command…

## Prerequisites

- The target environment must consist of a web-mail server that the attacker can query and a back-end mail server. The back-end mail server need not be directly accessible to the attacker.
- The web-mail server must fail to adequately sanitize fields received from users and passed on to the back-end mail server.
- The back-end mail server must not be adequately secured against receiving malicious commands from the web-mail server.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
