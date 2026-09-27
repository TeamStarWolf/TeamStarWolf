# CAPEC-78 — Using Escaped Slashes in Alternate Encoding

<a id="capec-78"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets the use of the backslash in alternate encoding. An adversary can provide a backslash as a leading character and causes a parser to believe that the next character is special. This is called an escape. By using that trick, the adversary tries to exploit alternate ways to encode the same character which leads to filter problems and opens avenues to attack.

## Related CWE (10)

- [CWE-180 — Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html)
- [CWE-181 — Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html)
- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-73 — External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)

## Prerequisites

- The application accepts the backlash character as escape character.
- The application server does incomplete input data decoding, filtering and validation.

## Skills required

- The adversary can naively try backslash character and discover that the target host uses it as escape character.:LEVEL:Low
- The adversar

## Mitigations

- Verify that the user-supplied data does not use backslash character to escape malicious characters.
- Assume all input is malicious. Create an allowlist that defines all valid input to the software system based on the requirements specifications. In

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
