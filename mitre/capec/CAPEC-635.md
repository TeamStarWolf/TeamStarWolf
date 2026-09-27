# CAPEC-635 — Alternative Execution Due to Deceptive Filenames

<a id="capec-635"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Status:** Draft  

The extension of a file name is often used in various contexts to determine the application that is used to open and use it. If an attacker can cause an alternative application to be used, it may be able to execute malicious code, cause a denial of service or expose sensitive information.

## Mapped ATT&CK techniques (1)

- [T1036.007 — Double File Extension](/mitre/techniques/T1036-007.md) — Adversaries may abuse a double extension in the filename as a means of masquerading the true file type.

## Related CWE (1)

- [CWE-162 — Improper Neutralization of Trailing Special Elements](https://cwe.mitre.org/data/definitions/162.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes trailing special elements that could be interpreted in unexpected ways when they are sent to a downstream…

## Prerequisites

- The use of the file must be controlled by the file extension.

## Mitigations

- Applications should insure that the content of the file is consistent with format it is expecting, and not depend solely on the file extension.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
