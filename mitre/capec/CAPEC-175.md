# CAPEC-175 — Code Inclusion

<a id="capec-175"></a>

**Abstraction:** Meta  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary exploits a weakness on the target to force arbitrary code to be retrieved locally or from a remote location and executed. This differs from code injection in that code injection involves the direct inclusion of code while code inclusion involves the addition or replacement of a reference to a code file, which is subsequently loaded by the target and used as part of the code of some ap

## Related CWE (1)

- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) — The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The target application must include external code/libraries that are executed when the application runs and the adversary must be able to influence the specific files that get included.
- The victim

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
