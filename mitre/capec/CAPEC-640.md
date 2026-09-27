# CAPEC-640 — Inclusion of Code in Existing Process

<a id="capec-640"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

The adversary takes advantage of a bug in an application failing to verify the integrity of the running process to execute arbitrary code in the address space of a separate live process. The adversary could use running code in the context of another process to try to access process's memory, system/network resources, etc. The goal of this attack is to evade detection defenses and escalate privileges by masking the malicious code under an existing legitimate process. Examples of approaches include but not limited to: dynamic-link library (DLL) injection, portable executable injection, thread execution hijacking, ptrace system calls, VDSO hijacking, function hooking, reflective code loading, and more.

## Mapped ATT&CK techniques (4)

- [T1505.005 — Terminal Services DLL](/mitre/techniques/T1505-005.md) — Adversaries may abuse components of Terminal Services to enable persistent access to systems.
- [T1574.006 — Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md) — Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries.
- [T1574.013 — KernelCallbackTable](/mitre/techniques/T1574-013.md) — Adversaries may abuse the <code>KernelCallbackTable</code> of a process to hijack its execution flow in order to run their own payloads.
- [T1620 — Reflective Code Loading](/mitre/techniques/T1620.md) — Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads.

## Related CWE (2)

- [CWE-114 — Process Control](https://cwe.mitre.org/data/definitions/114.html) — Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker.
- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) — The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The targeted application fails to verify the integrity of the running process that allows an adversary to execute arbitrary code.

## Skills required

- [High] Knowledge of how to load malicious code into the memory space of a running process, as well as the ability to have the running process execute this code. For example, with DLL injection, the adversary must know how to load a DLL into the memory space of another running process, and cause this process to execute the code inside of the DLL.

## Consequences

- Integrity, Confidentiality / Execute Unauthorized Commands, Read Data

## Mitigations

- Prevent unknown or malicious software from loading through using an allowlist policy.
- Properly restrict the location of the software being used.
- Leverage security kernel modules providing advanced access control and process restrictions like SELinux.
- Monitor API calls like CreateRemoteThread, SuspendThread/SetThreadContext/ResumeThread, QueueUserAPC, and similar for Windows.
- Monitor API calls like ptrace system call, use of LD_PRELOAD environment variable, dlfcn dynamic linking API calls, and similar for Linux.
- Monitor API calls like SetWindowsHookEx and SetWinEventHook which install hook procedures for Windows.
- Monitor processes and command-line arguments for unknown behavior related to code injection.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
