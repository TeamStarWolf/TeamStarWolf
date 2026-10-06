# CAPEC-199: XSS Using Alternate Syntax

<a id="capec-199"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

An adversary uses alternate forms of keywords or commands that result in the same action as the primary form but which may not be caught by filters. For example, many keywords are processed in a case insensitive manner. If the site's web filtering algorithm does not convert all tags into a consistent case before the comparison with forbidden keywords it is possible to bypass filters (e.g., incomplete black lists) by using an alternate case structure. For example, the "script" tag using the alternate forms of "Script" or "ScRiPt" may bypass filters where "script" is the only form tested. Other variants using different syntax representations are also possible as well as using pollution meta-characters or entities that are eventually ignored by the rendering engine. The attack can result in the execution of otherwise prohibited functionality.

## Related CWE (1)

- [CWE-87: Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html): The product does not neutralize or incorrectly neutralizes user-controlled input for alternate script syntax.

## Prerequisites

- Target client software must allow scripting such as JavaScript.

## Skills required

- [Low] To inject the malicious payload in a web page
- [High] To bypass non trivial filters in the application

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data
- Authorization / Execute Unauthorized Commands
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.
- Implementation: Perform input validation for all remote content, including remote and user-generated content
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
