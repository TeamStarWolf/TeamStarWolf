# CAPEC-460: HTTP Parameter Pollution (HPP)

<a id="capec-460"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An adversary adds duplicate HTTP GET/POST parameters by injecting query string delimiters. Via HPP it may be possible to override existing hardcoded HTTP parameters, modify the application behaviors, access and, potentially exploit, uncontrollable variables, and bypass input validation checkpoints and WAF rules.

## Related CWE (3)

- [CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html): The product constructs a string for a command to be executed by a separate component in another control sphere, but it does not properly delimit the intended arguments, options, or switches within that command string.
- [CWE-147: Improper Neutralization of Input Terminators](https://cwe.mitre.org/data/definitions/147.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as input terminators when they are sent to a downstream component.
- [CWE-235: Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html): The product does not handle or incorrectly handles when the number of parameters, fields, or arguments with the same name exceeds the expected amount.

## Prerequisites

- HTTP protocol is used with some GET/POST parameters passed

## Mitigations

- Configuration: If using a Web Application Firewall (WAF), filters should be carefully configured to detect abnormal HTTP requests
- Design: Perform URL encoding
- Implementation: Use strict regular expressions in URL rewriting
- Implementation: Beware of multiple occurrences of a parameter in a Query String

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
