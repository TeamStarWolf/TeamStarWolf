# Reverse Engineering

Reverse engineering is the discipline of analyzing compiled software without access to its original source code — dissecting binaries to understand behavior, find vulnerabilities, analyze malware, defeat software protections, or develop interoperability. It sits at the intersection of computer architecture, operating system internals, and adversarial thinking. Every exploit developer, malware analyst, and CTF player depends on reverse engineering skills. The analyst who can read disassembly, navigate a decompiler, and methodically trace execution through an unknown binary unlocks capabilities that automated tools simply cannot replicate.

Modern targets range from packed Windows PE binaries and Linux ELF files to firmware running on embedded routers, mobile APKs, and obfuscated scripting languages. The tools and techniques differ by target, but the underlying discipline is consistent: identify the file format, understand the execution model, trace the logic that matters, and extract the insight needed. Static analysis — examining the binary without running it — pairs with dynamic analysis — running the binary under a debugger in a controlled environment — to build a complete picture.

---

## Where to Start

Start with Ghidra on beginner crackmes from Crackmes.one. Crackmes are small binaries with a single goal — produce the right serial key or password — which forces you to read disassembly, understand comparisons, and trace logic without the complexity of full malware. Learn x86/x64 assembly alongside tool use; you do not need to memorize the instruction set, you need to recognize common patterns (function prologues, comparisons, loops). pwn.college's reverse engineering module provides structured, graded challenges with built-in learning materials.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | File identification, string extraction, import analysis, basic disassembly in Ghidra, x86/x64 register model and common instructions, beginner crackmes | Ghidra beginner tutorials, Crackmes.one easy challenges, pwn.college RE module, "Hacking: The Art of Exploitation" ch. 1–2 |
| Practitioner | Calling conventions, stack frames, dynamic debugging with x64dbg or GDB+pwndbg, anti-analysis bypass, .NET/Java decompilation, script deobfuscation | OALabs YouTube, HackTheBox RE challenges, x64dbg tutorials, reversing.kr |
| Advanced | Custom unpacking, firmware extraction and analysis, kernel debugging, WinDbg, exploit RE, malware family reversals, scripting Ghidra/IDAPython | SANS SEC503/FOR610 content, OffSec OSED, FLARE-ON challenge archives, binary ninja BNIL deep dives |

---

## Reverse Engineering Targets

Understanding the file format and execution model of your target is the mandatory first step before any analysis can begin.

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
| iOS IPA | Mach-O + ObjC/Swift | Class-dump for ObjC metadata, Hopper or Ghidra for ARM64, frida for dynamic hooking |

---

## Essential x86/x64 Assembly Concepts

You do not need to write assembly — you need to read it. These are the patterns and concepts that appear constantly in real binaries.

### Registers

| Register | 64-bit | 32-bit | Role |
|---|---|---|---|
| Accumulator | RAX | EAX | Return values, arithmetic results |
| Base | RBX | EBX | General purpose, preserved across calls |
| Counter | RCX | ECX | Loop counters; 1st arg (Windows x64) |
| Data | RDX | EDX | I/O, multiply/divide; 2nd arg (Windows x64) |
| Source Index | RSI | ESI | String/memory source; 2nd arg (Linux) |
| Destination Index | RDI | EDI | String/memory destination; 1st arg (Linux) |
| Stack Pointer | RSP | ESP | Top of stack — do not clobber casually |
| Base Pointer | RBP | EBP | Stack frame base reference |
| Instruction Pointer | RIP | EIP | Current execution address |

### Calling Conventions

| Convention | Platform | Argument Order |
|---|---|---|
| System V AMD64 ABI | Linux/macOS (x64) | RDI, RSI, RDX, RCX, R8, R9 → stack |
| Microsoft x64 ABI | Windows (x64) | RCX, RDX, R8, R9 → stack (32-byte shadow space) |
| cdecl | x86 32-bit Linux | All args on stack, caller cleans up |
| stdcall | x86 32-bit Windows | Args on stack, callee cleans up |

### Key Instructions

| Instruction | Operation | Notes |
|---|---|---|
| MOV dst, src | Copy value | Most common instruction in any binary |
| LEA dst, [addr] | Load effective address | Pointer arithmetic — does not dereference |
| PUSH / POP | Stack operations | Save/restore registers, pass args (32-bit) |
| ADD / SUB | Arithmetic | Sets ZF, SF, CF, OF |
| XOR reg, reg | Zero a register | Faster than MOV reg, 0; also used for crypto |
| AND / OR | Bitwise logic | Flag masking, bit testing |
| CMP a, b | Compute a−b, set flags | Does not store result — only sets flags |
| TEST a, b | Compute a AND b, set flags | Common pattern: TEST eax,eax / JZ (null check) |
| JMP / JE / JNE / JG / JL | Conditional jumps | Based on flags from CMP/TEST |
| CALL addr | Push RIP, jump | Saves return address on stack |
| RET | Pop RIP, jump | Returns from function |
| NOP | No operation | Patching target to disable checks |

### Stack Frame (Function Prologue / Epilogue)

```asm
; Prologue — sets up stack frame
push rbp
mov  rbp, rsp
sub  rsp, 0x40       ; allocate local variables

; Epilogue — tears down stack frame
mov  rsp, rbp        ; or: leave (equivalent)
pop  rbp
ret
```

### CPU Flags

| Flag | Bit | Set When |
|---|---|---|
| ZF | Zero | Result equals zero (CMP equal, TEST zero) |
| SF | Sign | Result is negative (MSB = 1) |
| CF | Carry | Unsigned overflow |
| OF | Overflow | Signed overflow |

---

## Static Analysis Workflow

Static analysis examines the binary without executing it. It is safer (no malware detonation risk) and often reveals strings, imports, and high-level logic quickly. Use it first on every unknown binary.

1. **File identification** — `file binary`, `xxd binary | head` (check magic bytes), `binwalk binary`. Know what you have before spending time in a disassembler.
2. **Hash and VT lookup** — `sha256sum binary`, submit hash to VirusTotal. Known malware saves hours of analysis time.
3. **String extraction** — `strings -a binary`, then FLOSS for obfuscated strings. Look for URLs, registry keys, mutex names, error messages, file paths.
4. **Import/export analysis** — `dumpbin /imports` (Windows), `readelf -d`, `nm`, `objdump -d`. Imports reveal capability: `CreateRemoteThread` = process injection, `InternetConnect` = network, `CryptEncrypt` = ransomware candidate.
5. **Entropy analysis** — high entropy (>7.0) in sections indicates packing or encryption. Detect-It-Easy or binwalk `-E` visualizes this.
6. **Open in disassembler/decompiler** — Ghidra (free), IDA Pro (commercial), Binary Ninja. Let auto-analysis run.
7. **Find main()** — follow entry point → `__libc_start_main` → `main` (Linux ELF), or search symbol list. Windows: EP → CRT startup → `WinMain`/`main`.
8. **Trace logic** — follow input validation paths, key comparisons, interesting API call chains. Rename functions and variables as you understand them — the decompiler output improves with every annotation.
9. **Document findings** — function purpose, data structures, external connections, notable strings. Export annotated project before closing.

---

## Dynamic Analysis Workflow

Dynamic analysis runs the binary in a controlled environment under observation. It catches behavior that static analysis misses: unpacking routines, encrypted config decryption, runtime API resolution, and anti-analysis evasion.

1. **Prepare isolated environment** — snapshot VM with no real network, or route through FakeNet-NG / INetSim to simulate internet services. Never run malware on a host you care about.
2. **Baseline the system** — capture process list, open network connections, registry state, and file system state before running the sample.
3. **Attach monitoring tools** — ProcMon (file/registry/process), Process Hacker (memory, threads), Wireshark (network), RegShot (registry diff before/after).
4. **Run with debugger** — x64dbg (Windows), GDB + pwndbg/peda/GEF (Linux). Attach or launch with debugger.
5. **Set breakpoints** — `main`, key API calls (`CreateFile`, `WriteFile`, `connect`, `RegOpenKey`, `VirtualAlloc`, `CreateRemoteThread`), suspicious functions identified in static analysis.
6. **Step through and observe** — watch register values, memory writes, arguments to API calls. Use memory view to watch buffers being constructed.
7. **Bypass anti-analysis** — NOP out `IsDebuggerPresent` checks, patch `jne` → `je` to bypass license checks, use ScyllaHide plugin to hide the debugger from detection.
8. **Dump from memory** — after a packer unpacks to memory, dump the running process with OllyDumpEx or Scylla, fix the IAT, and analyze the unpacked PE in a disassembler.
9. **Document runtime behavior** — file writes, network connections, registry changes, process spawning, injected DLLs. Map observed behavior to ATT&CK techniques.

---

## Key Tools

| Tool | Platform | Cost | Primary Use |
|---|---|---|---|
| Ghidra | Cross-platform | Free | Decompilation, scripting via Java/Python API, plugin ecosystem |
| IDA Pro | Cross-platform | Commercial | Gold standard; Hex-Rays decompiler, IDAPython, extensive plugin library |
| Binary Ninja | Cross-platform | Commercial + free tier | Modern UI, BNIL intermediate language, Python API |
| Cutter (Radare2 GUI) | Cross-platform | Free | Open-source RE platform; r2 integration, Ghidra decompiler plugin |
| x64dbg | Windows | Free | Windows debugger with ScyllaHide, plugin ecosystem, x32/x64 |
| WinDbg / WinDbg Preview | Windows | Free | Kernel and user-mode debugging; TTD (time-travel debugging) |
| OllyDbg | Windows | Free | Classic 32-bit debugger; legacy malware and crackme analysis |
| GDB + pwndbg/peda/GEF | Linux | Free | Enhanced GDB for exploit development and binary RE on Linux |
| JADX | Java / Android | Free | APK and JAR decompiler to near-original Java source |
| dnSpy | .NET | Free | .NET assembly decompiler and debugger; edit and recompile IL |
| ILSpy | .NET | Free | .NET decompiler; lightweight Ghidra alternative for managed code |
| Detect-It-Easy (DIE) | Cross-platform | Free | Packer/compiler/protector identification; entropy visualization |
| FLOSS (Mandiant) | Cross-platform | Free | Extract obfuscated strings from PE binaries |
| Procmon | Windows | Free | File, registry, and process activity monitoring |
| Process Hacker | Windows | Free | Process memory, thread, and handle inspection |
| FakeNet-NG / INetSim | Windows / Linux | Free | Simulate internet services for safe malware network analysis |
| binwalk | Cross-platform | Free | Firmware extraction and entropy analysis |
| pyinstxtractor | Cross-platform | Free | Unpack PyInstaller bundles to .pyc for decompilation |
| uncompyle6 / decompile3 | Cross-platform | Free | Decompile Python .pyc bytecode to source |

---

## Anti-Analysis Techniques and Bypasses

Sophisticated binaries actively resist analysis. Knowing the techniques and their countermeasures is as important as knowing how to use the tools.

| Technique | Description | Bypass Method |
|---|---|---|
| Anti-debugging: IsDebuggerPresent | Calls `IsDebuggerPresent` API and exits if debugger detected | Patch the call to NOP or always return 0; ScyllaHide plugin |
| Anti-debugging: CheckRemoteDebugger | `CheckRemoteDebuggerPresent` detects remote debugger attachment | ScyllaHide; patch return value in debugger |
| Timing checks (RDTSC) | Measures execution time between instructions; unusually slow = debugger | Hardware breakpoints (do not stop clock); ScyllaHide timing patches |
| VM detection: CPUID | Checks CPUID output for hypervisor bit or VMware/VirtualBox strings | Custom VM with hypervisor bit cleared; patch CPUID result |
| VM detection: registry artifacts | Checks for VMware/VirtualBox registry keys or driver names | Remove VM artifacts using VMware Workstation hardening scripts; patch checks |
| Packing (UPX, custom) | Original code compressed/encrypted; unpacks at runtime | `upx -d` for UPX; for custom packers, let it unpack in memory then dump with Scylla/OllyDumpEx |
| Obfuscation: junk code | Unreachable or meaningless instructions inserted to confuse disassembly | Trace actual execution path in debugger; identify and skip junk blocks |
| Obfuscation: opaque predicates | Conditional jumps that always go one direction but look like real branches | Dynamic analysis reveals true path; manually prune false branch in decompiler |
| String encryption | Strings decrypted at runtime so static `strings` output is empty | FLOSS for static extraction; set breakpoint after decryption routine in debugger |
| Anti-dumping | Manipulates `SizeOfImage` in PE header; overwrites code after use | OllyDumpEx with manual size fix; Scylla with PE reconstruction |

---

## Managed Language Reversing (.NET / Java / Python)

Managed languages compile to intermediate bytecode rather than native machine code, which makes decompilation dramatically more effective than with native binaries. Expect near-original source quality.

### .NET
- **dnSpy** — decompile CIL/MSIL to C# and debug live; edit IL and recompile — the most powerful .NET RE tool
- **ILSpy** — lightweight .NET decompiler; good for quick reads without a full debug environment
- **dotPeek** (JetBrains) — free .NET decompiler with Visual Studio integration
- CIL is typed and structured — class names, method names, and variable types are preserved unless obfuscated with ConfuserEx or similar

### Java / Android
- **JADX** — best APK and JAR decompiler; produces navigable Java source with cross-references
- **Fernflower / CFR** — alternative Java decompilers when JADX struggles with specific patterns
- APK analysis: unzip the APK, run `jadx -d output/ app.apk`, read the Java source like any other codebase
- Check `AndroidManifest.xml` for permissions, exported activities, and attack surface before diving into code

### Python
- **pyinstxtractor** — extract the embedded .pyc files from a PyInstaller-packaged EXE
- **uncompyle6 / decompile3** — decompile .pyc bytecode to Python source (version-dependent; match decompiler to Python version)
- **dis module** — Python's built-in bytecode disassembler for cases where decompilers fail

### JavaScript
- **de4js** — automated JavaScript deobfuscator for common obfuscation patterns
- **js-beautify** — reformats minified JS to readable form
- **Browser DevTools** — set breakpoints in the Sources tab; most effective for live web app analysis
- Malicious JS in phishing: CyberChef for base64/hex layers, then js-beautify

---

## Firmware Reversing

Firmware reversing extracts and analyzes the software running on embedded devices — routers, IoT sensors, PLCs, and similar hardware. The goal is typically finding hardcoded credentials, command injection vulnerabilities, or update mechanism weaknesses.

1. **Obtain firmware** — download from vendor site, extract via JTAG/UART, or capture from device update traffic
2. **Extract file system** — `binwalk -e firmware.bin` auto-extracts known file system types; use `dd` with calculated offsets for manual extraction
3. **Identify architecture** — `file` on extracted binaries; `binwalk -A` for opcode scanning; common: ARM (little/big endian), MIPS, x86
4. **Mount and explore** — mount SquashFS/CramFS, review `/etc/passwd`, web interface code, startup scripts, and update mechanism
5. **Search for weaknesses** — `grep -r "password\|admin\|secret\|key" .` on extracted filesystem; check for hardcoded credentials, command injection in CGI handlers, insecure update validation
6. **Emulate** — QEMU for full-system emulation of ARM/MIPS firmware; allows dynamic analysis without the physical device
7. **Analyze binaries** — Ghidra with architecture-specific processor modules; focus on network-facing daemons and authentication logic

| Tool | Purpose |
|---|---|
| binwalk | Signature-based extraction; entropy analysis; the first tool to run on any firmware blob |
| Firmwalker | Automated search for interesting files (passwords, SSH keys, SSL certs) in extracted firmware |
| FACT (Firmware Analysis and Comparison Tool) | Web-based firmware analysis platform; automated unpacking, vulnerability scanning, comparison between versions |
| QEMU | Full-system emulation for ARM/MIPS/PowerPC firmware dynamic analysis |
| Ghidra | Disassembly and decompilation of firmware binaries with ARM/MIPS processor support |

---

## Practice Platforms

| Platform | Focus | Difficulty |
|---|---|---|
| [pwn.college](https://pwn.college) | Structured RE + binary exploitation module with autograded challenges and lecture content | Beginner to advanced |
| [Crackmes.one](https://crackmes.one) | Community crackme challenges — serial keygens, license bypass, password finding | All levels |
| [HackTheBox RE Challenges](https://hackthebox.com) | Varied RE challenges across platforms and file types | Easy to Insane |
| [PicoCTF](https://picoctf.org) | Beginner-friendly RE and forensics challenges with hints and writeup-friendly structure | Beginner |
| [reversing.kr](http://reversing.kr) | Korean RE challenge site; intermediate puzzles with diverse binary formats | Intermediate and up |
| [FLARE-ON Challenge](https://flare-on.com) | Annual Mandiant RE CTF; the most respected skill benchmark in the malware RE community | Advanced |

---

## Free Training

- [pwn.college RE Module](https://pwn.college) — structured reverse engineering curriculum with hands-on challenges; the most complete free RE learning path from beginner to advanced binary exploitation
- [OALabs YouTube](https://www.youtube.com/@OALabs) — real-world malware and crackme walkthroughs covering unpacking, anti-analysis bypass, and decompiler use; the best free YouTube resource for practical RE
- [LiveOverflow Binary Exploitation](https://www.youtube.com/@LiveOverflow) — binary exploitation and reverse engineering tutorials from first principles; accessible and technically rigorous
- [Ghidra Official Training](https://github.com/NationalSecurityAgency/ghidra) — NSA's official Ghidra course materials included in the repo; covers navigation, scripting, and analysis workflows
- [OpenSecurityTraining2](https://p.ost2.fyi) — free university-quality reverse engineering courses including "Intro to x86" and "Intermediate x86"; the most thorough free assembly fundamentals course available
- [FLARE-ON Archives](https://flare-on.com) — all previous FLARE-ON challenge binaries and official writeups; work through past years to build structured RE skills
- [Malware Unicorn Workshops](https://malwareunicorn.org) — free RE and malware analysis workshops with complete lab materials; RE101 and RE102 are excellent starting points

---

## Certifications

- **GREM** (GIAC Reverse Engineering Malware) — the gold standard malware RE certification; covers static/dynamic analysis, code reversing, network analysis, and anti-analysis techniques; pairs with SANS FOR610
- **OSED** (Offensive Security Exploit Developer) — OffSec certification covering reverse engineering, vulnerability discovery, and Windows exploit development; requires real RE skill to pass the 72-hour practical exam
- **Certified RE Professional** — vendor-specific credentials from multiple training providers; quality varies — evaluate based on the practical exam component

---

## Related Disciplines

Reverse engineering is foundational to several adjacent disciplines. Skills built here transfer directly:

- [Malware Analysis](malware-analysis.md) — RE is the core technical skill in malware analysis; everything in that discipline builds on the ability to read disassembly and trace binary logic
- [Exploit Development](exploit-development.md) — finding and weaponizing vulnerabilities requires RE to locate the vulnerable code path and understand memory layout
- [CTF Methodology](../CTF_METHODOLOGY.md) — RE challenges are a core CTF category; the crackme workflow and tool fluency built here applies directly to CTF binary challenges
