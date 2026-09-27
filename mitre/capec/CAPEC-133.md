# CAPEC-133 — Try All Common Switches

<a id="capec-133"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An attacker attempts to invoke all common switches and options in the target application for the purpose of discovering weaknesses in the target. For example, in some applications, adding a --debug switch causes debugging information to be displayed, which can sometimes reveal sensitive processing or configuration information to an attacker. This attack differs from other forms of API abuse in that the attacker is indiscriminately attempting to invoke options in the hope that one of them will work rather than specifically targeting a known option. Nonetheless, even if the attacker is familiar with the published options of a targeted application this attack method may still be fruitful as it might discover unpublicized functionality.

## Related CWE (1)

- [CWE-912 — Hidden Functionality](https://cwe.mitre.org/data/definitions/912.html) — The product contains functionality that is not documented, not part of the specification, and not accessible through an interface or command sequence that is obvious to the product's users or administrators.

## Prerequisites

- The attacker must be able to control the options or switches sent to the target.

## Mitigations

- Design: Minimize switch and option functionality to only that necessary for correct function of the command.
- Implementation: Remove all debug and testing options from production code.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
