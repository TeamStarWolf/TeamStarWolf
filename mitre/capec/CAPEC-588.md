# CAPEC-588: DOM-Based XSS

<a id="capec-588"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Stable  

This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is inserted into the client-side HTML being parsed by a web browser. Content served by a vulnerable web application includes script code used to manipulate the Document Object Model (DOM). This script code either does not properly validate input, or does not perform proper output encoding, thus creating an opportunity for an adversary to inject a malicious script launch a XSS attack. A key distinction between other XSS attacks and DOM-based attacks is that in other XSS attacks, the malicious script runs when the vulnerable web page is initially loaded, while a DOM-based attack executes sometime after the page loads. Another distinction of DOM-based attacks is that in some cases, the malicious script is never sent to the vulnerable web server at all. An attack like this is guaranteed to bypass any server-side filtering attempts to protect users.

## Related CWE (3)

- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html): The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-83: Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html): The product does not neutralize or incorrectly neutralizes javascript: or other URIs from dangerous attributes within tags, such as onmouseover, onload, onerror, or style.

## Prerequisites

- An application that leverages a client-side web browser with scripting enabled.
- An application that manipulates the DOM via client-side scripting.
- An application that failS to adequately sanitize or encode untrusted input.

## Skills required

- [Medium] Requires the ability to write scripts of some complexity and to inject it through user controlled fields in the system.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Authorization, Access Control / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data

## Mitigations

- Use browser technologies that do not allow client-side scripting.
- Utilize proper character encoding for all output produced within client-site scripts manipulating the DOM.
- Ensure that all user-supplied input is validated before use.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
