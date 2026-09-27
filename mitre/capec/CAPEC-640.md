# CAPEC-640 — Inclusion of Code in Existing Process

<a id="capec-640"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

The adversary takes advantage of a bug in an application failing to verify the integrity of the running process to execute arbitrary code in the address space of a separate live process. The adversary could use running code in the context of another process to try to access process's memory, system/network resources, etc. The goal of this attack is to evade detection defenses and escalate privileg

## Mapped ATT&CK techniques (4)

- [T1505.005 — Terminal Services DLL](/mitre/techniques/T1505-005.md)
- [T1574.006 — Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md)
- [T1574.013 — KernelCallbackTable](/mitre/techniques/T1574-013.md)
- [T1620 — Reflective Code Loading](/mitre/techniques/T1620.md)

## Related CWE (2)

- [CWE-114 — Process Control](https://cwe.mitre.org/data/definitions/114.html)
- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Prerequisites

- The targeted application fails to verify the integrity of the running process that allows an adversary to execute arbitrary code.

## Skills required

- Knowledge of how to load malicious code into the memory space of a running process, as well as the ability to have the running process execute

## Mitigations

- Prevent unknown or malicious software from loading through using an allowlist policy.
- Properly restrict the location of the software being used.
- Leverage security kernel modules providing advanced access control and process restrictions like SELi

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
