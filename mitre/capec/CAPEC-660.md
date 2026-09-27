# CAPEC-660 — Root/Jailbreak Detection Evasion via Hooking

<a id="capec-660"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary forces a non-restricted mobile application to load arbitrary code or code files, via Hooking, with the goal of evading Root/Jailbreak detection. Mobile device users often Root/Jailbreak their devices in order to gain administrative control over the mobile operating system and/or to install third-party mobile applications that are not provided by authorized application stores (e.g. Goo

## Mapped ATT&CK techniques (1)

- [T1055 — Process Injection](/mitre/techniques/T1055.md) — Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.

## Related CWE (1)

- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) — The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The targeted application must be non-restricted to allow code hooking.

## Skills required

- Knowledge about Root/Jailbreak detection and evasion techniques.:LEVEL:High
- Knowledge about code hooking.:LEVEL:Medium

## Mitigations

- Ensure mobile applications are signed appropriately to avoid code inclusion via hooking.
- Inspect the application's memory for suspicious artifacts, such as shared objects/JARs or dylibs, after other Root/Jailbreak detection methods.
- Inspect the a

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
