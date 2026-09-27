# CAPEC-237 — Escaping a Sandbox by Calling Code in Another Language

<a id="capec-237"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Low  
**Status:** Draft  

The attacker may submit malicious code of another language to obtain access to privileges that were not intentionally exposed by the sandbox, thus escaping the sandbox. For instance, Java code cannot perform unsafe operations, such as modifying arbitrary memory locations, due to restrictions placed on it by the Byte code Verifier and the JVM. If allowed, Java code can call directly into native C c

## Related CWE (1)

- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Skills required

- The attacker must have a good knowledge of the platform specific mechanisms of signing and verifying code. Most code signing and verification

## Mitigations

- Assurance: Sanitize the code of the standard libraries to make sure there is no security weaknesses in them.
- Design: Use obfuscation and other techniques to prevent reverse engineering the standard libraries.
- Assurance: Use static analysis tool t

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
