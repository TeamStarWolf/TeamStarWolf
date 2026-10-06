# CAPEC-243: XSS Targeting HTML Attributes

<a id="capec-243"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An adversary inserts commands to perform cross-site scripting (XSS) actions in HTML attributes. Many filters do not adequately sanitize attributes against the presence of potentially dangerous commands even if they adequately sanitize tags. For example, dangerous expressions could be inserted into a style attribute in an anchor tag, resulting in the execution of malicious code when the resulting page is rendered. If a victim is tricked into viewing the rendered page the attack proceeds like a normal XSS attack, possibly resulting in the loss of sensitive cookies or other malicious activities.

## Related CWE (1)

- [CWE-83: Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html): The product does not neutralize or incorrectly neutralizes javascript: or other URIs from dangerous attributes within tags, such as onmouseover, onload, onerror, or style.

## Prerequisites

- The target application must fail to adequately sanitize HTML attributes against the presence of dangerous commands.

## Mitigations

- Design: Use libraries and templates that minimize unfiltered input.
- Implementation: Normalize, filter and use an allowlist for all input including that which is not expected to have any scripting content.
- Implementation: The victim should configure the browser to minimize active content from untrusted sources.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
