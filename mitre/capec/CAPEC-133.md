# CAPEC-133 — Try All Common Switches

<a id="capec-133"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An attacker attempts to invoke all common switches and options in the target application for the purpose of discovering weaknesses in the target. For example, in some applications, adding a --debug switch causes debugging information to be displayed, which can sometimes reveal sensitive processing or configuration information to an attacker. This attack differs from other forms of API abuse in tha

## Related CWE (1)

- [CWE-912 — Hidden Functionality](https://cwe.mitre.org/data/definitions/912.html)

## Prerequisites

- The attacker must be able to control the options or switches sent to the target.

## Mitigations

- Design: Minimize switch and option functionality to only that necessary for correct function of the command.
- Implementation: Remove all debug and testing options from production code.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
