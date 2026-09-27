# CAPEC-159 — Redirect Access to Libraries

<a id="capec-159"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

An adversary exploits a weakness in the way an application searches for external libraries to manipulate the execution flow to point to an adversary supplied library or code base. This pattern of attack allows the adversary to compromise the application or server via the execution of unauthorized code. An application typically makes calls to functions that are a part of libraries external to the application. These libraries may be part of the operating system or they may be third party libraries. If an adversary can redirect an application's attempts to access these libraries to other libraries that the adversary supplies, the adversary will be able to force the targeted application to execute arbitrary code. This is especially dangerous if the targeted application has enhanced privileges. Access can be redirected through a number of techniques, including the use of symbolic links, search path modification, and relative path manipulation.

## Mapped ATT&CK techniques (1)

- [T1574.008 — Path Interception by Search Order Hijacking](/mitre/techniques/T1574-008.md) — Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs.

## Related CWE (1)

- [CWE-706 — Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html) — The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Prerequisites

- The target must utilize external libraries and must fail to verify the integrity of these libraries before using them.

## Skills required

- [Low] To modify the entries in the configuration file pointing to malicious libraries
- [Medium] To force symlink and timing issues for redirecting access to libraries
- [High] To reverse engineering the libraries and inject malicious code into the libraries

## Consequences

- Authorization / Execute Unauthorized Commands
- Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Implementation: Restrict the permission to modify the entries in the configuration file.
- Implementation: Check the integrity of the dynamically linked libraries before use them.
- Implementation: Use obfuscation and other techniques to prevent reverse engineering the libraries.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
