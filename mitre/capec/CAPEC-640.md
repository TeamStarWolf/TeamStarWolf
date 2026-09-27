# CAPEC-640 — Inclusion of Code in Existing Process

<a id="capec-640"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

The adversary takes advantage of a bug in an application failing to verify the integrity of the running process to execute arbitrary code in the address space of a separate live process. The adversary could use running code in the context of another process to try to access process's memory, system/network resources, etc. The goal of this attack is to evade detection defenses and escalate privileg

## Mapped ATT&CK techniques (4)

- [T1505.005](/mitre/techniques/T1505-005.md)
- [T1574.006](/mitre/techniques/T1574-006.md)
- [T1574.013](/mitre/techniques/T1574-013.md)
- [T1620](/mitre/techniques/T1620.md)

## Related CWE (2)

[CWE-114](/CWE_REFERENCE.md) [CWE-829](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application fails to verify the integrity of the running process that allows an adversary to execute arbitrary code.::

**Skills required:** ::SKILL:Knowledge of how to load malicious code into the memory space of a running process, as well as the ability to have the running process execute

**Mitigations:** ::Prevent unknown or malicious software from loading through using an allowlist policy.::Properly restrict the location of the software being used.::Leverage security kernel modules providing advanced access control and process restrictions like SELi


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
