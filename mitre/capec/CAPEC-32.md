# CAPEC-32 — XSS Through HTTP Query Strings

<a id="capec-32"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary embeds malicious script code in the parameters of an HTTP query string and convinces a victim to submit the HTTP request that contains the query string to a vulnerable web application. The web application then procedes to use the values parameters without properly validation them first and generates the HTML code that will be executed by the victim's browser.

## Related CWE (1)

- [CWE-80 — Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters such as <, >, and & that could be interpreted as web-scripting elements when they are sent…

## Prerequisites

- Target client software must allow scripting such as JavaScript. Server software must allow display of remote generated HTML without sufficient input or output validation.

## Skills required

- [Low] To place malicious payload on server via HTTP
- [High] Exploiting any information gathered by HTTP Query on script host

## Consequences

- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all remote content, including remote and user-generated content
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Session tokens for specific host
- Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.
- Implementation: Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
