# CAPEC-663 — Exploitation of Transient Instruction Execution

<a id="capec-663"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** Low  
**Status:** Stable  

An adversary exploits a hardware design flaw in a CPU implementation of transient instruction execution to expose sensitive data and bypass/subvert access control over restricted resources. Typically, the adversary conducts a covert channel attack to target non-discarded microarchitectural changes caused by transient executions such as speculative execution, branch prediction, instruction pipelining, and/or out-of-order execution. The transient execution results in a series of instructions (gadgets) which construct covert channel and access/transfer the secret data.

## Related CWE (3)

- [CWE-1037 — Processor Optimization Removal or Modification of Security-critical Code](https://cwe.mitre.org/data/definitions/1037.html) — The developer builds a security-critical protection mechanism into the software, but the processor optimizes the execution of the program such that the mechanism is removed or modified.
- [CWE-1303 — Non-Transparent Sharing of Microarchitectural Resources](https://cwe.mitre.org/data/definitions/1303.html) — Hardware structures shared across execution contexts (e.g., caches and branch predictors) can violate the expected architecture isolation between contexts.
- [CWE-1264 — Hardware Logic with Insecure De-Synchronization between Control and Data Channels](https://cwe.mitre.org/data/definitions/1264.html) — The hardware logic for error handling and security checks can incorrectly forward data before the security check is complete.

## Prerequisites

- The adversary needs at least user execution access to a system and a maliciously crafted program/application/process with unprivileged code to misuse transient instruction set execution of the CPU.

## Skills required

- [High] Detailed knowledge on how various CPU architectures and microcode perform transient execution for various low-level assembly language code instructions/operations.
- [High] Detailed knowledge on compiled binaries and operating system shared libraries of instruction sequences, and layout of application and OS/Kernel address spaces for data leakage.

## Consequences

- Confidentiality / Read Data
- Access Control / Bypass Protection Mechanism
- Authorization / Execute Unauthorized Commands

## Mitigations

- Implementation: DAWG (Dynamically Allocated Way Guard) - processor cache properly divided between different programs/processes that don't share resources
- Implementation: KPTI (Kernel Page-Table Isolation) to completely separate user-space and kernel space page tables
- Configuration: Architectural Design of Microcode to limit abuse of speculative execution and out-of-order execution
- Configuration: Disable SharedArrayBuffer for Web Browsers
- Configuration: Disable Copy-on-Write between Cloud VMs
- Configuration: Privilege Checks on Cache Flush Instructions
- Implementation: Non-inclusive Cache Memories to prevent Flush+Reload Attacks

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
