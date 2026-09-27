# CAPEC-247 — XSS Using Invalid Characters

<a id="capec-247"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An adversary inserts invalid characters in identifiers to bypass application filtering of input. Filters may not scan beyond invalid characters but during later stages of processing content that follows these invalid characters may still be processed. This allows the adversary to sneak prohibited commands past filters and perform normally prohibited operations. Invalid characters may include null, carriage return, line feed or tab in an identifier. Successful bypassing of the filter can result in a XSS attack, resulting in the disclosure of web cookies or possibly other results.

## Related CWE (1)

- [CWE-86 — Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html) — The product does not neutralize or incorrectly neutralizes invalid characters or byte sequences in the middle of tag names, URI schemes, and other identifiers.

## Prerequisites

- The target must fail to remove invalid characters from input and fail to adequately scan beyond these characters.

## Mitigations

- Design: Use libraries and templates that minimize unfiltered input.
- Implementation: Normalize, filter and use an allowlist for any input that will be included in any subsequent web pages or back end operations.
- Implementation: The victim should configure the browser to minimize active content from untrusted sources.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
