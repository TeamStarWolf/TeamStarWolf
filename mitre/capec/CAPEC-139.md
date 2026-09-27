# CAPEC-139 — Relative Path Traversal

<a id="capec-139"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attacker exploits a weakness in input validation on the target by supplying a specially constructed path utilizing dot and slash characters for the purpose of obtaining access to arbitrary files or resources. An attacker modifies a known path on the target in order to reach material that is not available through intended channels. These attacks normally involve adding additional path separators

## Related CWE (1)

- [CWE-23 — Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

## Prerequisites

- The target application must accept a string as user input, fail to sanitize combinations of characters in the input that have a special meaning in the context of path navigation, and insert the user

## Skills required

- To inject the malicious payload in a web page:LEVEL:Low
- To bypass non trivial filters in the application:LEVEL:High

## Mitigations

- Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement
- Implementation: Perform input validation for all remote content, including remote and user-generated content.
- Implementation

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
