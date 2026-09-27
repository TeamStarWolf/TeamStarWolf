# CAPEC-641 — DLL Side-Loading

<a id="capec-641"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary places a malicious version of a Dynamic-Link Library (DLL) in the Windows Side-by-Side (WinSxS) directory to trick the operating system into loading this malicious DLL instead of a legitimate DLL. Programs specify the location of the DLLs to load via the use of WinSxS manifests or DLL redirection and if they aren't used then Windows searches in a predefined set of directories to locat

## Mapped ATT&CK techniques (1)

- `T1574.002`

## Related CWE (1)

[CWE-706](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must fail to verify the integrity of the DLL before using them.::

**Skills required:** ::SKILL:Trick the operating system in loading a malicious DLL instead of a legitimate DLL.:LEVEL:High::

**Mitigations:** ::Prevent unknown DLLs from loading through using an allowlist policy.::Patch installed applications as soon as new updates become available.::Properly restrict the location of the software being used.::Use of sxstrace.exe on Windows as well as manua


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
