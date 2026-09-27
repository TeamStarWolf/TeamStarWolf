# CAPEC-32 — XSS Through HTTP Query Strings

<a id="capec-32"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary embeds malicious script code in the parameters of an HTTP query string and convinces a victim to submit the HTTP request that contains the query string to a vulnerable web application. The web application then procedes to use the values parameters without properly validation them first and generates the HTML code that will be executed by the victim's browser.

## Related CWE (1)

- [CWE-80 — Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

## Prerequisites

- Target client software must allow scripting such as JavaScript. Server software must allow display of remote generated HTML without sufficient input or output validation.

## Skills required

- To place malicious payload on server via HTTP:LEVEL:Low
- Exploiting any information gathered by HTTP Query on script host:LEVEL:High

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Design: Utilize strict type, character, and encoding enforcement
- Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
