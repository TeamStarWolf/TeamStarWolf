# Reverse Engineering

Reverse engineering is the discipline of analyzing compiled software without access to its original source code — dissecting binaries to understand behavior, find vulnerabilities, analyze malware, defeat software protections, or develop interoperability. It sits at the intersection of computer architecture, operating system internals, and adversarial thinking. Every exploit developer, malware analyst, and CTF player depends on reverse engineering skills. The analyst who can read disassembly, navigate a decompiler, and methodically trace execution through an unknown binary unlocks capabilities that automated tools simply cannot replicate.

Modern targets range from packed Windows PE binaries and Linux ELF files to firmware running on embedded routers, mobile APKs, and obfuscated scripting languages. The tools and techniques differ by target, but the underlying discipline is consistent: identify the file format, understand the execution model, trace the logic that matters, and extract the insight needed. Static analysis — examining the binary without running it — pairs with dynamic analysis — running the binary under a debugger in a controlled environment — to build a complete picture.

Security applications of RE include: malware analysis, vulnerability research, firmware security, CTF challenges, anti-cheat bypass research, and intellectual property protection audits.

---

## Where to Start

Start with Ghidra on beginner crackmes from Crackmes.one. Crackmes are small binaries with a single goal — produce the right serial key or password — which forces you to read disassembly, understand comparisons, and trace logic without the complexity of full malware. Learn x86/x64 assembly alongside tool use; you do not need to memorize the instruction set, you need to recognize common patterns (function prologues, comparisons, loops). pwn.college's reverse engineering module provides structured, graded challenges with built-in learning materials.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | File identification, string extraction, import analysis, basic disassembly in Ghidra, x86/x64 register model and common instructions, beginner crackmes | Ghidra beginner tutorials, Crackmes.one easy challenges, pwn.college RE module, "Hacking: The Art of Exploitation" ch. 1–2 |
| Practitioner | Calling conventions, stack frames, dynamic debugging with x64dbg or GDB+pwndbg, anti-analysis bypass, .NET/Java decompilation, script deobfuscation | OALabs YouTube, HackTheBox RE challenges, x64dbg tutorials, reversing.kr |
| Advanced | Custom unpacking, firmware extraction and analysis, kernel debugging, WinDbg, exploit RE, malware family reversals, scripting Ghidra/IDAPython | SANS SEC503/FOR610 content, OffSec OSED, FLARE-ON challenge archives, binary ninja BNIL deep dives |

---

## CPU Architecture Fundamentals

Understanding CPU registers, calling conventions, and stack frame layout is mandatory. Without this foundation you cannot read disassembly meaningfully.

### x86/x64 Registers

| Register (64-bit) | Register (32-bit) | Role |
|---|---|---|
| RAX | EAX | Accumulator — holds return values, arithmetic results |
| RBX | EBX | Base — general purpose, preserved across calls (callee-saved) |
| RCX | ECX | Counter — loop counters; 1st argument on Windows x64 |
| RDX | EDX | Data — I/O, multiply/divide; 2nd argument on Windows x64 |
| RSI | ESI | Source Index — string/memory source; 2nd argument on Linux x64 |
| RDI | EDI | Destination Index — string/memory destination; 1st argument on Linux x64 |
| RSP | ESP | Stack Pointer — top of stack; never clobber casually |
| RBP | EBP | Base Pointer — stack frame base reference |
| RIP | EIP | Instruction Pointer — current execution address |
| — | EFLAGS | Status flags: ZF (zero), SF (sign), CF (carry), OF (overflow) |
| R8–R15 | — | Extended registers (x64 only); R8/R9 are 5th/6th args on Windows x64 |

### Calling Conventions

| Convention | Platform | Argument Order | Stack Cleanup |
|---|---|---|---|
| System V AMD64 ABI | Linux/macOS x64 | RDI, RSI, RDX, RCX, R8, R9 → stack | Caller |
| Microsoft x64 ABI | Windows x64 | RCX, RDX, R8, R9 → stack (+ 32-byte shadow space) | Caller |
| cdecl | x86 32-bit (C default) | All args pushed right-to-left on stack | Caller |
| stdcall | x86 32-bit Windows API | Args pushed right-to-left on stack | Callee |
| fastcall | x86 32-bit (MSVC) | First two args in ECX/EDX, rest on stack | Callee |

### Stack Frame Layout (x86)

```
High addresses
+------------------+
| function args    | ← caller pushed these (above EBP)
+------------------+
| return address   | ← saved EIP pushed by CALL
+------------------+
| saved EBP        | ← function prologue: push ebp
+------------------+  ← EBP points here
| local variables  | ← below EBP (sub esp, N)
+------------------+
Low addresses (ESP)
```

**Function prologue / epilogue:**
```asm
; Prologue
push rbp
mov  rbp, rsp
sub  rsp, 0x40      ; allocate local variables

; Epilogue
mov  rsp, rbp       ; or: leave
pop  rbp
ret
```

**Common patterns to recognize:**
- Stack canary: value loaded from `fs:[0x28]` (Linux) stored between locals and return address, checked before `ret`
- ASLR awareness: binaries compiled with PIE will have position-independent code; addresses change each run
- Anti-debug telltale: early `IsDebuggerPresent` call or `RDTSC` pair near entry point

---

## Reverse Engineering Targets

| Target | Format | Key Characteristics |
|---|---|---|
| Windows PE binaries (EXE, DLL) | PE/PE32+ | Import/export tables, sections (.text/.data/.rsrc), TLS callbacks, PE headers reveal packer/compiler |
| Linux ELF binaries | ELF | Dynamic/static linking, symbol tables, DWARF debug info, PLT/GOT for import resolution |
| macOS Mach-O binaries | Mach-O | Fat binaries (multi-arch), load commands, Objective-C runtime metadata |
| .NET assemblies | CIL/MSIL | Managed bytecode — decompiles to near-original C#; dnSpy gives you debuggable source |
| Java / Android (APK) | JVM bytecode / DEX | JAR → near-original Java via JADX; APK = ZIP containing DEX + resources + manifest |
| Python bytecode | .pyc / PyInstaller | uncompyle6/.pyc → Python source; pyinstxtractor unpacks PyInstaller bundles |
| Firmware | SquashFS, CramFS, JFFS2, raw | binwalk extraction, architecture identification (ARM/MIPS/x86), hardcoded credentials |
| Obfuscated scripts | JS, PowerShell, VBScript | de4js, js-beautify, PowerShell -Decode; browser DevTools for JS deobfuscation |
| iOS IPA | Mach-O + ObjC/Swift | Class-dump for ObjC metadata, Hopper or Ghidra for ARM64, Frida for dynamic hooking |

---

## Static Analysis Workflow

Static analysis examines the binary without executing it. It is safer (no malware detonation risk) and often reveals strings, imports, and high-level logic quickly. Use it first on every unknown binary.

1. **File identification** — `file binary`, `xxd binary | head` (check magic bytes), `binwalk binary`. Know what you have before spending time in a disassembler.
2. **Hash and VT lookup** — `sha256sum binary`, submit hash to VirusTotal. Known malware saves hours of analysis time.
3. **Entropy analysis** — Detect-It-Easy (DIE), PEiD, or `binwalk -E`. Entropy > 7.0 in a section strongly suggests packing or encryption. High entropy in `.text` = packed executable; high entropy in `.data` = encrypted config or payload.
4. **String extraction** — `strings -n 8 binary` for quick pass; then **FLOSS** (Mandiant's FireEye Labs Obfuscated String Solver) for stack strings and tight-loop strings that `strings` misses. Look for: URLs, IP addresses, registry keys, mutex names, error messages, file paths.
5. **Import/export analysis** — `dumpbin /imports` (Windows), `readelf -d`, `nm`, `objdump -d`. Imports reveal capability:
   - `CreateRemoteThread` / `WriteProcessMemory` = process injection
   - `VirtualAllocEx` = shellcode staging
   - `InternetOpenUrl` / `WinInet` functions = C2 or download
   - `RegSetValueEx` / `RegOpenKey` = registry persistence
   - `CryptEncrypt` / `BCryptEncrypt` = ransomware candidate
6. **Open in disassembler/decompiler** — Ghidra (free), IDA Pro (commercial), Binary Ninja. Let auto-analysis run.
7. **Find main()** — follow entry point → `__libc_start_main` → `main` (Linux ELF), or search symbol list. Windows: EP → CRT startup → `WinMain`/`main`.
8. **Trace logic** — follow input validation paths, key comparisons, interesting API call chains. **Rename functions** and variables as you understand them (`sub_401000` → `decrypt_config`). The decompiler output improves with every annotation.
9. **Cross-reference tracing** — use `F` (Ghidra) or `X` (IDA) to find all callers of interesting functions. Trace data flow from suspicious imports back to where attacker-controlled input enters.
10. **Document findings** — function purpose, data structures, external connections, notable strings. Export annotated project before closing.

### Key Ghidra Shortcuts

```
L          → Label / rename symbol
;          → Add comment at current address
F          → Find references to current address (xrefs)
Ctrl+G     → Go to specific address
Ctrl+L     → Go to label / symbol by name
Right-click function → Create Structure (for struct identification)
Script Manager → Run DecompilerParameterID for better decompilation
Window → Function Graph → visual control flow
```

---

## Dynamic Analysis Workflow

Dynamic analysis runs the binary in a controlled environment under observation. It catches behavior that static analysis misses: unpacking routines, encrypted config decryption, runtime API resolution, and anti-analysis evasion.

1. **Prepare isolated lab** — FlareVM (Windows analysis toolkit) or REMnux (Linux), host-only network adapter, snapshot before detonation. Never run malware on a host you care about.
2. **Baseline the system** — capture process list, open network connections, registry state, and file system state before running the sample.
3. **Attach monitoring tools** — ProcMon (file/registry/process), Process Hacker (memory, threads, handles), Wireshark (network), RegShot (registry diff before/after).
4. **Network simulation** — FakeNet-NG (Windows) or INetSim (Linux) simulate DNS/HTTP/FTP/IRC responses. Keep malware "happy" so it proceeds past C2 check-in and reveals more behavior.
5. **Run with debugger** — x64dbg (Windows), GDB + pwndbg/peda/GEF (Linux). Attach or launch with debugger.
6. **Set breakpoints** — at `main`, key API calls (`CreateFile`, `WriteFile`, `connect`, `RegOpenKey`, `VirtualAlloc`, `CreateRemoteThread`), and suspicious functions identified in static analysis.
7. **Use API Monitor** — intercept and log every Win32 API call with full arguments; invaluable for tracing config decryption and C2 protocol construction.
8. **Step through and observe** — watch register values, memory writes, arguments to API calls. Use memory view to watch buffers being constructed.
9. **Bypass anti-analysis** — NOP out `IsDebuggerPresent` checks, patch `jne` → `je` to bypass license checks, use ScyllaHide plugin to hide the debugger from detection.
10. **Unpacking** — if packed, run until OEP (Original Entry Point), dump memory with PE-sieve or OllyDumpEx, fix IAT with Scylla, re-analyze the unpacked PE in a disassembler.
11. **Document runtime behavior** — file writes, network connections, registry changes, process spawning, injected DLLs. Map observed behavior to ATT&CK techniques.

---

## Anti-Analysis Techniques and Bypasses

| Technique | How It Works | Bypass |
|---|---|---|
| Anti-debugging: IsDebuggerPresent | Checks `PEB.BeingDebugged` flag; exits or alters behavior if debugger detected | Patch call to NOP or always return 0; ScyllaHide plugin patches PEB automatically |
| Anti-debugging: CheckRemoteDebuggerPresent | Detects remote debugger attachment via NtQueryInformationProcess | ScyllaHide; patch return value in debugger |
| Timing checks (RDTSC) | Measures CPU cycles between two RDTSC calls — large gap = debugger present | Hardware breakpoints (no clock delay); ScyllaHide timing patches; patch RDTSC to return fixed values |
| VM / sandbox detection: CPUID | Checks CPUID output for hypervisor bit or VMware/VirtualBox strings | Custom VM with hypervisor bit cleared; patch CPUID result in debugger |
| VM detection: registry / file artifacts | Checks for VMware/VirtualBox registry keys, driver names, MAC prefix (00:50:56) | Remove VM artifacts using hardening scripts; patch check locations to NOP |
| Code obfuscation: control flow flattening | Replaces natural control flow with a dispatcher switch; every block routes through a central state variable | Symbolic execution (angr) to recover original CFG; manual trace in debugger |
| Code obfuscation: junk code / opaque predicates | Unreachable instructions and always-true/false branches confuse static analysis | Dynamic analysis reveals true path; manually prune false branches in decompiler |
| String encryption | Strings XOR/AES encrypted at runtime; `strings` output is empty | FLOSS for static extraction; set breakpoint after decryption routine and dump decrypted strings from memory |
| Packing (UPX, custom) | Original PE compressed/encrypted; unpacked at runtime | `upx -d` for UPX; for custom packers run to OEP, dump with Scylla/OllyDumpEx, fix IAT |
| Process injection / hollowing | Code runs in a legitimate process (svchost.exe); hides from process list | Monitor for WriteProcessMemory + SetThreadContext via ProcMon; attach debugger to hollowed process |
| Anti-dumping | Manipulates `SizeOfImage` in PE header; overwrites code sections after execution | OllyDumpEx with manual size fix; Scylla with PE reconstruction |
| Parent process spoofing | Malware spawns itself with a spoofed PPID to appear as a child of explorer.exe | ProcMon parent-child tree; event 4688 `ParentProcessName` correlation |

---

## Key CTF Reverse Engineering Techniques

- **License key validation** — typically compares transformed input to hardcoded value; trace comparison instruction, patch `jne` → `je` (nop the conditional jump) or extract the expected value directly
- **Custom encoding** — identify encoding loops (XOR, rotate, base64 variant); extract the key/table from constants in the decompiler output; replicate in Python
- **Flag format hunting** — search for flag format string (`CTF{`, `FLAG{`, `picoCTF{`) in strings output or memory dump after running the binary
- **angr symbolic execution** — automate path exploration to find inputs that trigger a specific code path (e.g., print "Correct"):
  ```python
  import angr
  proj = angr.Project('./crackme', auto_load_libs=False)
  simgr = proj.factory.simgr()
  simgr.explore(find=0x401234, avoid=0x401567)  # find success address, avoid failure
  if simgr.found:
      print(simgr.found[0].posix.dumps(0))  # dump stdin that reaches success
  ```
- **Scripting Ghidra** — use the Script Manager (Java or Python) to automate bulk renaming, decrypt embedded strings, or identify all calls to a specific import

---

## Essential x86/x64 Assembly Reference

### Key Instructions

| Instruction | Operation | Notes |
|---|---|---|
| MOV dst, src | Copy value | Most common instruction; `MOV eax, [ebp-8]` loads local variable |
| LEA dst, [addr] | Load effective address | Pointer arithmetic — does **not** dereference; used for `&var` |
| PUSH / POP | Stack operations | `PUSH rax` decrements RSP by 8, stores RAX |
| ADD / SUB | Arithmetic | Sets ZF, SF, CF, OF based on result |
| XOR reg, reg | Zero a register | Faster than `MOV reg, 0`; also the dominant crypto primitive in malware |
| AND / OR | Bitwise logic | Flag masking, bit testing |
| CMP a, b | Compute a−b, set flags | Does not store result — only updates flags |
| TEST a, b | Compute a AND b, set flags | `TEST eax, eax` + `JZ` = null check pattern |
| JMP / JE / JNE / JG / JL | Conditional jumps | Based on flags from preceding CMP/TEST |
| CALL addr | Push RIP/EIP, jump | Saves return address; the `ret` address you overwrite in exploits |
| RET | Pop RIP/EIP, jump | Returns from function; target of stack overflow |
| NOP | No operation (0x90) | Used in NOP sleds; common patch target to disable checks |
| INT 3 | Software breakpoint (0xCC) | Inserted by debuggers; also used in anti-debug tricks |

### CPU Flags

| Flag | Set When | Common Use |
|---|---|---|
| ZF (Zero) | Result equals zero | `JE`/`JNE` (equality comparisons) |
| SF (Sign) | Result is negative (MSB = 1) | `JL`/`JG` (signed comparisons) |
| CF (Carry) | Unsigned overflow | `JB`/`JA` (unsigned comparisons) |
| OF (Overflow) | Signed overflow | Signed arithmetic edge cases |

---

## Managed Language Reversing (.NET / Java / Python)

Managed languages compile to intermediate bytecode rather than native machine code, making decompilation dramatically more effective than with native binaries. Expect near-original source quality.

### .NET
- **dnSpy** — decompile CIL/MSIL to C# and debug live; edit IL and recompile — the most powerful .NET RE tool
- **ILSpy** — lightweight .NET decompiler; good for quick reads without a full debug environment
- **dotPeek** (JetBrains) — free .NET decompiler with Visual Studio integration
- CIL is typed and structured — class names, method names, and variable types are preserved unless obfuscated with ConfuserEx or similar

### Java / Android
- **JADX** — best APK and JAR decompiler; produces navigable Java source with cross-references
- APK analysis: unzip the APK, run `jadx -d output/ app.apk`, read the Java source like any other codebase
- Check `AndroidManifest.xml` for permissions, exported activities, and attack surface before diving into code

### Python
- **pyinstxtractor** — extract embedded .pyc files from a PyInstaller-packaged EXE
- **uncompyle6 / decompile3** — decompile .pyc bytecode to Python source (version-dependent)
- **dis module** — Python's built-in bytecode disassembler for cases where decompilers fail

### JavaScript
- **de4js** — automated deobfuscator for common obfuscation patterns
- **js-beautify** — reformats minified JS to readable form
- **Browser DevTools** — set breakpoints in Sources tab; most effective for live web app analysis

---

## Firmware Reversing

Firmware reversing extracts and analyzes the software running on embedded devices — routers, IoT sensors, PLCs, and similar hardware.

1. **Obtain firmware** — download from vendor site, extract via JTAG/UART, or capture from device update traffic
2. **Extract file system** — `binwalk -e firmware.bin` auto-extracts known file system types
3. **Identify architecture** — `file` on extracted binaries; `binwalk -A` for opcode scanning; common: ARM (little/big endian), MIPS, x86
4. **Mount and explore** — mount SquashFS/CramFS, review `/etc/passwd`, web interface code, startup scripts
5. **Search for weaknesses** — `grep -r "password\|admin\|secret\|key" .` on extracted filesystem; check for hardcoded credentials, command injection in CGI handlers
6. **Emulate** — QEMU for full-system emulation of ARM/MIPS firmware; allows dynamic analysis without the physical device

| Tool | Purpose |
|---|---|
| binwalk | Signature-based extraction; entropy analysis |
| Firmwalker | Automated search for passwords, SSH keys, SSL certs in extracted firmware |
| FACT | Web-based firmware analysis platform; automated unpacking and vulnerability scanning |
| QEMU | Full-system emulation for ARM/MIPS/PowerPC firmware |
| Ghidra | Disassembly and decompilation with ARM/MIPS processor support |

---

## Tools & Repositories

| Tool | Platform | Cost | Primary Use |
|---|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Cross-platform | Free | Decompilation, scripting via Java/Python API, plugin ecosystem |
| [IDA Pro](https://hex-rays.com/ida-pro) | Cross-platform | Commercial | Gold standard; Hex-Rays decompiler, IDAPython, extensive plugin library |
| [Binary Ninja](https://binary.ninja) | Cross-platform | Commercial + free tier | Modern UI, BNIL intermediate language, Python API |
| [Cutter (Radare2 GUI)](https://cutter.re) | Cross-platform | Free | Open-source RE platform with Ghidra decompiler plugin |
| [x64dbg](https://x64dbg.com) | Windows | Free | Windows debugger with ScyllaHide, plugin ecosystem, x32/x64 |
| [WinDbg Preview](https://apps.microsoft.com/store/detail/windbg-preview/9PGJGD53TN86) | Windows | Free | Kernel and user-mode debugging; TTD (time-travel debugging) |
| [GDB + pwndbg](https://github.com/pwndbg/pwndbg) | Linux | Free | Enhanced GDB for exploit development and binary RE on Linux |
| [JADX](https://github.com/skylot/jadx) | Java / Android | Free | APK and JAR decompiler to near-original Java source |
| [dnSpy](https://github.com/dnSpy/dnSpy) | .NET | Free | .NET assembly decompiler and debugger; edit and recompile IL |
| [Detect-It-Easy (DIE)](https://github.com/horsicq/Detect-It-Easy) | Cross-platform | Free | Packer/compiler/protector identification; entropy visualization |
| [FLOSS (Mandiant)](https://github.com/mandiant/flare-floss) | Cross-platform | Free | Extract obfuscated strings from PE binaries (stack strings, tight loops) |
| [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) | Windows | Free | File, registry, and process activity monitoring |
| [Process Hacker](https://processhacker.sourceforge.io/) | Windows | Free | Process memory, thread, and handle inspection |
| [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) | Windows | Free | Simulate internet services for safe malware network analysis |
| [INetSim](https://www.inetsim.org/) | Linux | Free | Linux equivalent of FakeNet-NG |
| [binwalk](https://github.com/ReFirmLabs/binwalk) | Cross-platform | Free | Firmware extraction and entropy analysis |
| [API Monitor](http://www.rohitab.com/apimonitor) | Windows | Free | Intercept and log Win32 API calls with full arguments |
| [PE-sieve](https://github.com/hasherezade/pe-sieve) | Windows | Free | Scan running processes for anomalies, dump injected code |
| [angr](https://github.com/angr/angr) | Python | Free | Symbolic execution framework for automated path exploration |
| [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) | Cross-platform | Free | Unpack PyInstaller bundles to .pyc for decompilation |

---

## Commercial Platforms

| Platform | Focus | Notes |
|---|---|---|
| [IDA Pro](https://hex-rays.com/ida-pro) | Industry-standard disassembler/decompiler | The professional standard; Hex-Rays decompiler produces the cleanest pseudocode |
| [Binary Ninja](https://binary.ninja) | Modern RE platform with automation API | Excellent Python/C++ API for scripted analysis workflows |
| [JEB Decompiler](https://www.pnfsoftware.com/) | Android / native code decompiler | Strong Android DEX and ARM decompilation; popular for mobile RE |
| [Hopper Disassembler](https://www.hopperapp.com/) | macOS / Linux | Lightweight commercial disassembler for macOS/iOS targets |
| [Hex-Rays Decompiler](https://hex-rays.com/decompiler/) | x86/x64/ARM decompilation | Ships with IDA Pro; also available as standalone add-on |

---

## Practice Platforms

| Platform | Focus | Difficulty |
|---|---|---|
| [pwn.college](https://pwn.college) | Structured RE + binary exploitation curriculum | Beginner to advanced |
| [Crackmes.one](https://crackmes.one) | Community crackme challenges — serial keygens, license bypass | All levels |
| [HackTheBox RE Challenges](https://hackthebox.com) | Varied RE challenges across platforms and file types | Easy to Insane |
| [PicoCTF](https://picoctf.org) | Beginner-friendly RE and forensics challenges with hints | Beginner |
| [reversing.kr](http://reversing.kr) | Korean RE challenge site; intermediate puzzles | Intermediate and up |
| [FLARE-ON Challenge](https://flare-on.com) | Annual Mandiant RE CTF; the most respected skill benchmark in malware RE | Advanced |

---

## Free Training

- [pwn.college RE Module](https://pwn.college) — structured reverse engineering curriculum; the most complete free RE learning path from beginner to advanced
- [OALabs YouTube](https://www.youtube.com/@OALabs) — real-world malware and crackme walkthroughs covering unpacking, anti-analysis bypass, and decompiler use
- [LiveOverflow Binary Exploitation](https://www.youtube.com/@LiveOverflow) — binary exploitation and reverse engineering tutorials from first principles
- [Ghidra Official Training](https://github.com/NationalSecurityAgency/ghidra) — NSA's official Ghidra course materials included in the repo
- [OpenSecurityTraining2](https://p.ost2.fyi) — free university-quality RE courses including "Intro to x86" and "Intermediate x86"; the most thorough free assembly fundamentals course available
- [FLARE-ON Archives](https://flare-on.com) — all previous FLARE-ON challenge binaries and official writeups
- [Malware Unicorn Workshops](https://malwareunicorn.org) — free RE and malware analysis workshops with complete lab materials; RE101 and RE102 are excellent starting points

---

## NIST 800-53 Alignment

| Control | Family | RE Relevance |
|---|---|---|
| SA-11 | System and Services Acquisition | Developer security testing — RE validates whether security testing identified real weaknesses |
| SA-12 | Supply Chain Protection | Firmware and third-party library RE to identify supply chain implants or backdoors |
| SI-7 | Software, Firmware, and Information Integrity | Integrity verification of software and firmware — RE detects tampering |
| SI-3 | Malicious Code Protection | RE is the core technique for analyzing malicious code to derive signatures and IOCs |
| RA-5 | Vulnerability Scanning | RE supports vulnerability discovery that feeds into the scanning/patching cycle |
| CA-8 | Penetration Testing | RE is a required skill for thorough penetration testing of binary applications |
| IR-4 | Incident Handling | RE of malware found during incidents drives containment and eradication decisions |
| AU-2 | Event Logging | RE reveals what events malware disables or evades — informs logging coverage decisions |

---

## ATT&CK Coverage

| Technique | ID | RE Connection |
|---|---|---|
| Obfuscated Files or Information | T1027 | RE identifies and defeats obfuscation applied to malware payloads |
| Deobfuscate/Decode Files or Information | T1140 | RE workflow recovers plaintext from encrypted/encoded malware components |
| Process Injection | T1055 | RE reveals injection mechanisms (reflective DLL, process hollowing, APC injection) |
| Reflective Code Loading | T1620 | RE of reflective loaders is required to understand advanced implant staging |
| Shared Modules | T1129 | RE traces how malware resolves and abuses loaded modules at runtime |
| Masquerading | T1036 | RE identifies fake file extensions, spoofed process names, and metadata manipulation |
| Virtualization/Sandbox Evasion | T1497 | RE reveals VM/sandbox detection checks and timing tricks used to evade analysis |
| Debugger Evasion | T1622 | RE of anti-debug techniques is prerequisite to bypassing them in analysis |
| Software Packing | T1027.002 | RE identifies packer signatures and recovers original executable via unpacking |
| Command and Scripting Interpreter | T1059 | RE of obfuscated PowerShell, VBScript, and JS reveals malicious intent |
| Compile After Delivery | T1027.004 | RE of compiler-generated artifacts helps attribute and date malware families |

---

## Certifications

| Certification | Provider | Focus |
|---|---|---|
| **GREM** (GIAC Reverse Engineering Malware) | SANS / GIAC | Gold standard malware RE certification; static/dynamic analysis, code reversing, anti-analysis |
| **OSED** (Offensive Security Exploit Developer) | OffSec | RE, vulnerability discovery, Windows exploit development; 72-hour practical exam |
| **eCMAP** (Certified Malware Analysis Professional) | eLearnSecurity | Malware analysis and RE using real-world samples |
| **CRTO** (Certified Red Team Operator) | Zero-Point Security | Red team ops including binary analysis and tradecraft |
| **Certified RE Professional** | Various vendors | Quality varies; evaluate based on practical exam component |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| *Practical Malware Analysis* (Sikorski/Honig) | Book | The definitive malware RE reference; covers tools, techniques, and real-world examples chapter by chapter |
| *The Art of Memory Forensics* (Ligh et al.) | Book | Complements RE with memory analysis techniques; covers Volatility and Windows internals |
| *Hacking: The Art of Exploitation* (Erickson) | Book | Assembly and exploit development fundamentals; first principles approach |
| [OpenSecurityTraining2](https://p.ost2.fyi) | Free course | University-quality x86/x64 RE courses; the most thorough free assembly curriculum |
| [LiveOverflow YouTube](https://www.youtube.com/@LiveOverflow) | Video | Binary exploitation and RE from first principles; honest and technically rigorous |
| [Ghidra Official Documentation](https://github.com/NationalSecurityAgency/ghidra) | Reference | NSA's official course materials and API documentation |
| [OALabs YouTube](https://www.youtube.com/@OALabs) | Video | Practical malware analysis and crackme walkthroughs; best for real-world RE |
| [FLARE-ON Archives](https://flare-on.com) | Challenges | Annual Mandiant RE CTF with official writeups; industry's hardest RE benchmark |

---

## Related Disciplines

- [malware-analysis.md](malware-analysis.md) — RE is the core technical skill in malware analysis; everything in that discipline builds on reading disassembly and tracing binary logic
- [exploit-development.md](exploit-development.md) — finding and weaponizing vulnerabilities requires RE to locate the vulnerable code path and understand memory layout
- [vulnerability-research.md](vulnerability-research.md) — RE of patch diffs and target binaries is how vulnerability researchers identify exploitable bugs
- [forensics.md](forensics.md) — memory forensics and artifact analysis frequently require RE skills to interpret recovered code and data structures
