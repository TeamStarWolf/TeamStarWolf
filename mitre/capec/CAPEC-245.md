# CAPEC-245 — XSS Using Doubled Characters

<a id="capec-245"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

The adversary bypasses input validation by using doubled characters in order to perform a cross-site scripting attack. Some filters fail to recognize dangerous sequences if they are preceded by repeated characters. For example, by doubling the < before a script command, (<<script or %3C%3script using URI encoding) the filters of some web applications may fail to recognize the presence of a script

## Related CWE (1)

- [CWE-85 — Doubled Character XSS Manipulations](https://cwe.mitre.org/data/definitions/85.html)

## Prerequisites

- The targeted web application does not fully normalize input before checking for prohibited syntax. In particular, it must fail to recognize prohibited methods preceded by certain sequences of repeat

## Mitigations

- Design: Use libraries and templates that minimize unfiltered input.
- Implementation: Normalize, filter and sanitize all user supplied fields.
- Implementation: The victim should configure the browser to minimize active content from untrusted sources

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
