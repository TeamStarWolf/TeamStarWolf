# CAPEC-588 — DOM-Based XSS

<a id="capec-588"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is inserted into the client-side HTML being parsed by a web browser. Content served by a vulnerable web application includes script code used to manipulate the Document Object Model (DOM). This script code either does not properly validate input, or does not perform proper output encoding, thus creating an opportu

## Related CWE (3)

- [CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-83 — Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

## Prerequisites

- An application that leverages a client-side web browser with scripting enabled.
- An application that manipulates the DOM via client-side scripting.
- An application that failS to adequately sanitize

## Skills required

- Requires the ability to write scripts of some complexity and to inject it through user controlled fields in the system.:LEVEL:Medium

## Mitigations

- Use browser technologies that do not allow client-side scripting.
- Utilize proper character encoding for all output produced within client-site scripts manipulating the DOM.
- Ensure that all user-supplied input is validated before use.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
