# CAPEC-641: DLL Side-Loading

<a id="capec-641"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Stable  

An adversary places a malicious version of a Dynamic-Link Library (DLL) in the Windows Side-by-Side (WinSxS) directory to trick the operating system into loading this malicious DLL instead of a legitimate DLL. Programs specify the location of the DLLs to load via the use of WinSxS manifests or DLL redirection and if they aren't used then Windows searches in a predefined set of directories to locate the file. If the applications improperly specify a required DLL or WinSxS manifests aren't explicit about the characteristics of the DLL to be loaded, they can be vulnerable to side-loading.

## Mapped ATT&CK techniques (1)

- `T1574.002`

## Related CWE (1)

- [CWE-706: Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html): The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Prerequisites

- The target must fail to verify the integrity of the DLL before using them.

## Skills required

- [High] Trick the operating system in loading a malicious DLL instead of a legitimate DLL.

## Consequences

- Integrity / Execute Unauthorized Commands, Bypass Protection Mechanism

## Mitigations

- Prevent unknown DLLs from loading through using an allowlist policy.
- Patch installed applications as soon as new updates become available.
- Properly restrict the location of the software being used.
- Use of sxstrace.exe on Windows as well as manual inspection of the manifests.
- Require code signing and avoid using relative paths for resources.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
