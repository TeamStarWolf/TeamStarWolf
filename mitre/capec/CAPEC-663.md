# CAPEC-663 — Exploitation of Transient Instruction Execution

<a id="capec-663"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** Low

An adversary exploits a hardware design flaw in a CPU implementation of transient instruction execution to expose sensitive data and bypass/subvert access control over restricted resources. Typically, the adversary conducts a covert channel attack to target non-discarded microarchitectural changes caused by transient executions such as speculative execution, branch prediction, instruction pipelini

## Related CWE (3)

[CWE-1037](/CWE_REFERENCE.md) [CWE-1303](/CWE_REFERENCE.md) [CWE-1264](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary needs at least user execution access to a system and a maliciously crafted program/application/process with unprivileged code to misuse transient instruction set execution of the CPU.:

**Skills required:** ::SKILL:Detailed knowledge on how various CPU architectures and microcode perform transient execution for various low-level assembly language code ins

**Mitigations:** ::Implementation: DAWG (Dynamically Allocated Way Guard) - processor cache properly divided between different programs/processes that don't share resources::Implementation: KPTI (Kernel Page-Table Isolation) to completely separate user-space and kern


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
