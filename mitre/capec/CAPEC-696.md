# CAPEC-696 — Load Value Injection

<a id="capec-696"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Low

An adversary exploits a hardware design flaw in a CPU implementation of transient instruction execution in which a faulting or assisted load instruction transiently forwards adversary-controlled data from microarchitectural buffers. By inducing a page fault or microcode assist during victim execution, an adversary can force legitimate victim execution to operate on the adversary-controlled data wh

## Related CWE (1)

[CWE-1342](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary needs at least user execution access to a system and a maliciously crafted program/application/process with unprivileged code to misuse transient instruction set execution of the CPU.:

**Skills required:** ::SKILL:Detailed knowledge on how various CPU architectures and microcode perform transient execution for various low-level assembly language code ins

**Mitigations:** ::Do not allow the forwarding of data resulting from a faulting or assisted instruction. Some current mitigations claim to zero out the forwarded data, but this mitigation still does not suffice.::Insert explicit “lfence” speculation barriers in soft


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
