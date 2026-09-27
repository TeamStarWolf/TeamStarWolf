# CAPEC-244 — XSS Targeting URI Placeholders

<a id="capec-244"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type exploits the ability of most browsers to interpret "data", "javascript" or other URI schemes as client-side executable content placeholders. This attack consists of passing a malicious URI in an anchor tag HREF attribute or any other similar attributes in other HTML tags. Such malicious URI contains, for example, a base64 encoded HTML content with an embedded cross-site scripting payload. The attack is executed when the browser interprets the malicious content i.e., for example, when the victim clicks on the malicious link.

## Related CWE (1)

- [CWE-83 — Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html) — The product does not neutralize or incorrectly neutralizes javascript: or other URIs from dangerous attributes within tags, such as onmouseover, onload, onerror, or style.

## Prerequisites

- Target client software must allow scripting such as JavaScript and allows executable content delivered using a data URI scheme.

## Skills required

- [Medium] To inject the malicious payload in a web page

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Authorization / Execute Unauthorized Commands
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.
- Implementation: Perform input validation for all remote content, including remote and user-generated content
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
