# CAPEC-86 — XSS Through HTTP Headers

<a id="capec-86"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An adversary exploits web applications that generate web content, such as links in a HTML page, based on unvalidated or improperly validated data submitted by other actors. XSS in HTTP Headers attacks target the HTTP headers which are hidden from most users and may not be validated by web applications.

## Related CWE (1)

- [CWE-80 — Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters such as <, >, and & that could be interpreted as web-scripting elements when they are sent…

## Prerequisites

- Target software must be a client that allows scripting communication from remote hosts.

## Skills required

- [Low] To achieve a redirection and use of less trusted source, an adversary can simply edit HTTP Headers that are sent to client machine.
- [High] Exploiting a client side vulnerability to inject malicious scripts into the browser's executable process.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all remote content.
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Session tokens for specific host
- Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
