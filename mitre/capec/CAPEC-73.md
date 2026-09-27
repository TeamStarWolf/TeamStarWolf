# CAPEC-73 — User-Controlled Filename

<a id="capec-73"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type involves an adversary inserting malicious characters (such as a XSS redirection) into a filename, directly or indirectly that is then used by the target software to generate HTML text or other potentially executable content. Many websites rely on user-generated content and dynamically build resources like files, filenames, and URL links directly from user supplied data. In t

## Related CWE (8)

- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)
- [CWE-348 — Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html)
- [CWE-116 — Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
- [CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)
- [CWE-86 — Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- The victim must trust the name and locale of user controlled filenames.

## Skills required

- To achieve a redirection and use of less trusted source, an attacker can simply edit data that the host uses to build the filename:LEVEL:Low

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all re

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
