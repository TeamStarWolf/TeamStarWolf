# Reverse Engineering Reference

> Professional reference for security researchers, malware analysts, and CTF participants.
> All techniques described are intended for authorized, ethical use only.

---

## Table of Contents

1. [RE Fundamentals & Legal Framework](#1-re-fundamentals--legal-framework)
2. [Ghidra Comprehensive Guide](#2-ghidra-comprehensive-guide)
3. [IDA Pro & Binary Ninja](#3-ida-pro--binary-ninja)
4. [Assembly for Security Analysis](#4-assembly-for-security-analysis)
5. [Dynamic Analysis & Debugging](#5-dynamic-analysis--debugging)
6. [Unpacking & Deobfuscation](#6-unpacking--deobfuscation)
7. [Protocol Reverse Engineering](#7-protocol-reverse-engineering)
8. [Mobile & Embedded RE](#8-mobile--embedded-re)
9. [Vulnerability Discovery via RE](#9-vulnerability-discovery-via-re)
10. [CTF RE & Learning Resources](#10-ctf-re--learning-resources)

---

## 1. RE Fundamentals & Legal Framework

### 1.1 Purposes of Reverse Engineering

| Purpose | Description |
|---|---|
| Security Research | Identifying vulnerabilities in software before attackers do |
| Vulnerability Analysis | Understanding root cause, exploitability, and scope of flaws |
| Malware Analysis | Dissecting malicious code to understand behavior and build defenses |
| Interoperability | Creating compatible implementations when documentation is unavailable |
| CTF / Education | Skill development through capture-the-flag challenges |
| Patch Diffing | Comparing patched vs. unpatched binaries to find n-day vulnerabilities |

### 1.2 Legal Framework

#### United States

- **DMCA Section 1201(j) - Security Research Exemption**: Permits circumvention of technological protection measures for good-faith security research, testing, investigating, and correcting. Must be on systems you own or have permission to analyze.
- **CFAA (Computer Fraud and Abuse Act)**: Requires explicit written authorization before testing systems. Authorized access is critical â€” oral permission is insufficient for professional engagements.
- **Safe harbor principles**: Good-faith researchers who discover and responsibly disclose vulnerabilities have stronger legal standing. Document your research process.

#### European Union

- **EU Software Directive, Article 6**: Permits decompilation when necessary to achieve interoperability of an independently created program. Obtained information must not be used for development of a substantially similar program.
- **NIS2 Directive**: Encourages coordinated vulnerability disclosure and security research within member states.

#### Responsible Disclosure

- Notify vendor with technical details before public disclosure
- Allow a reasonable remediation window (commonly 90 days, per Google Project Zero policy)
- Work with CERT coordination centers for non-responsive vendors
- Consider CVE assignment via MITRE or vendor CNA programs

### 1.3 RE Methodology

```
Static Analysis
    No execution; examine file structure, disassembly, strings, imports
         |
Dynamic Analysis
    Execute in controlled environment; observe behavior, API calls, network
         |
Hybrid Analysis
    Combine static findings with runtime observations; iterate
         |
Documentation
    Document findings, IOCs, code structure, vulnerabilities discovered
```

**Iterative approach**: Start with quick static wins, pivot to dynamic when static hits walls, use static to understand dynamic observations, repeat.

### 1.4 Binary Format Overview

#### PE (Portable Executable) - Windows

```
MZ Header (DOS stub)
COFF File Header
    - Machine (0x8664 = x86-64, 0x14c = x86, 0xAA64 = ARM64)
    - NumberOfSections
Optional Header
    - Magic (0x10b = PE32, 0x20b = PE32+)
    - AddressOfEntryPoint (RVA)
    - ImageBase
    - DataDirectory[16] (Import/Export/Resource/TLS/etc.)
Section Table
    - .text  (CODE, EXECUTE+READ)
    - .data  (initialized data, READ+WRITE)
    - .rdata (read-only data, strings, vtables)
    - .bss   (uninitialized data)
    - .rsrc  (resources)
    - .reloc (base relocations)
```

Tools: pefile Python library, PE-bear, CFF Explorer, peview.

#### ELF (Executable and Linkable Format) - Linux/Unix

```
ELF Header
    - e_ident (magic 7fELF + class/data/OS)
    - e_machine (EM_X86_64=62, EM_ARM=40, EM_AARCH64=183)
    - e_entry (entry point VA)
Program Headers (segments, used by loader)
    - PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK
Section Headers (used by linker/tools)
    - .text, .data, .bss, .rodata
    - .symtab / .dynsym (symbol tables)
    - .plt / .got.plt (lazy binding)
```

Tools: readelf -a, objdump -d, pwntools ELF().

#### Mach-O - macOS/iOS

```
Mach Header (magic 0xFEEDFACF for 64-bit)
Load Commands
    - LC_SEGMENT_64 (__TEXT, __DATA, __LINKEDIT)
    - LC_CODE_SIGNATURE
    - LC_ENCRYPTION_INFO_64 (App Store DRM)
```

Universal binaries (fat binaries) contain multiple Mach-O slices.
Tools: otool -l, nm, class-dump, jtool2.

### 1.5 Architecture Overview

| Architecture | Word Size | Endian | Common Use |
|---|---|---|---|
| x86 (IA-32) | 32-bit | Little | Legacy Windows/Linux |
| x86-64 (AMD64) | 64-bit | Little | Modern desktop/server |
| ARM32 (ARMv7) | 32-bit | Little/Big | Mobile, IoT |
| AArch64 (ARM64) | 64-bit | Little | Modern mobile, Apple Silicon |
| MIPS32/64 | 32/64-bit | Little/Big | Embedded, routers |
| RISC-V | 32/64-bit | Little | Embedded, emerging |

### 1.6 Calling Conventions

#### System V AMD64 ABI (Linux/macOS x86-64)

```
Integer/Pointer arguments: RDI, RSI, RDX, RCX, R8, R9 (then stack)
Return value:              RAX (integer), XMM0 (float)
Callee-saved:              RBX, RBP, R12-R15
Stack alignment:           16-byte at CALL instruction
Red zone:                  128 bytes below RSP (leaf functions)
```

#### Windows x64 ABI (Microsoft)

```
Integer/Pointer arguments: RCX, RDX, R8, R9 (then stack)
Return value:              RAX
Shadow space:              32 bytes (4 slots) allocated by CALLER before call
Callee-saved:              RBX, RBP, RDI, RSI, R12-R15, XMM6-XMM15
```

#### ARM64 AAPCS64

```
Integer/Pointer arguments: X0-X7 (then stack)
Return value:              X0 (integer), V0 (float)
Callee-saved:              X19-X28, X29 (FP), X30 (LR)
```

#### 32-bit x86 Conventions

```
cdecl   (C default):  args pushed right-to-left, caller cleans stack, EAX=return
stdcall (WinAPI):     args pushed right-to-left, CALLEE cleans stack
fastcall:             ECX, EDX = first two args
thiscall (MSVC C++):  ECX = this pointer, callee cleans stack
```

### 1.7 Analysis Environment Setup

**FlareVM (Windows)**: https://github.com/mandiant/flare-vm
- Includes: x64dbg, IDA Free, Ghidra, FLOSS, DIE, CFF Explorer, PE-bear, Wireshark

**REMnux (Linux)**: https://remnux.org
- Includes: Ghidra, Radare2, FLOSS, Volatility, Zeek, Suricata, Cutter

**Snapshot discipline**: Always snapshot VM before executing unknown samples. Use isolated network with INetSim or FakeNet-NG. Monitor with Process Monitor, Process Hacker, Wireshark simultaneously.

---
## 2. Ghidra Comprehensive Guide

### 2.1 Installation & Project Management

```bash
# Requirements: JDK 17+  https://ghidra-sre.org
./ghidraRun          # Linux/macOS
ghidraRun.bat        # Windows

# Headless analysis
./support/analyzeHeadless /path/to/project ProjectName     -import /path/to/binary -postScript MyScript.java
```

### 2.2 CodeBrowser Interface

| Window | Purpose |
|---|---|
| Program Trees | Section/segment hierarchy (navigate .text, .data, etc.) |
| Symbol Tree | Functions, Labels, Classes, Namespaces; searchable |
| Data Type Manager | Built-in types, Windows headers, custom structs |
| Listing | Primary disassembly view |
| Decompiler | High-level C-like pseudocode |
| Defined Strings | All strings in binary with references |
| Function Graph | Visual CFG of current function |

**Key shortcuts**: L=Rename, T=Retype, ;=Comment, X=Xrefs, G=GoTo, Space=Toggle Graph, Ctrl+E=Structure Editor

### 2.3 Decompiler Output Interpretation

P-code (Ghidra's IR) translates all architectures before decompiling:
```
COPY   dst, src           ; dst = src
INT_ADD dst, a, b         ; dst = a + b
LOAD   dst, space, addr   ; dst = *addr
STORE  space, addr, src   ; *addr = src
CALL   addr
CBRANCH label, cond
```

Common artifacts:
- `CONCAT44(extraout_var, local_c)` = joined registers (e.g., EDX:EAX)
- `CARRY4(uVar1, param_1)` = unsigned overflow check
- `operator.new(0x58)` = C++ heap allocation

### 2.4 Analysis Workflow

```
1. Import binary, let auto-analysis complete
2. Defined Strings -> find interesting strings -> follow references
3. Symbol Tree -> Imports: CreateFile, send/recv, VirtualAlloc, RegSetValue
4. Find entry point: search for "main" or "entry"
5. Rename FUN_XXXXXXXX (press L), retype parameters (right-click -> Retype Variable)
6. Apply structures to pointer variables
7. Iterate: follow cross-references, understand callers/callees
```

### 2.5 Structure Editor

```
Observe: *(param_1 + 0) = dword, *(param_1 + 4) = pointer, *(param_1 + 0xc) = dword

Data Type Manager -> New -> Structure:
    Offset 0x00: int   field_00
    Offset 0x04: char* field_04
    Offset 0x0c: uint  field_0c

Right-click variable -> Retype Variable -> MyStruct *
Decompiler now shows: param_1->field_04 instead of *(param_1 + 4)
```

### 2.6 GhidraScript

**Java API:**
```java
// @category Analysis
public class MyScript extends GhidraScript {
    public void run() throws Exception {
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            if (f.getName().startsWith("FUN_"))
                println("Unnamed: " + f.getName() + " @ " + f.getEntryPoint());
        }
        setPlateComment(toAddr(0x401000L), "Entry point of interest");
    }
}
```

**Python (Jython):**
```python
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getParameterCount() > 4:
        print("Complex: " + func.getName() + " @ " + str(func.getEntryPoint()))

target = getFunction("InternetOpenA")
if target:
    for ref in getReferencesTo(target.getEntryPoint()):
        print("Called from: " + str(ref.getFromAddress()))
```

**ghidra_bridge (external Python):**
```bash
pip install ghidra_bridge
# Run ghidra_bridge_server.py in Ghidra first
```
```python
import ghidra_bridge
with ghidra_bridge.GhidraBridge(namespace=globals()):
    for f in currentProgram.getFunctionManager().getFunctions(True):
        print(f.getName())
```

### 2.7 Headless Analysis

```bash
./support/analyzeHeadless /tmp/proj MyProject -import /samples/malware.exe
./support/analyzeHeadless /tmp/proj MyProject -import /samples/ -recursive     -postScript ExtractStrings.py > results.txt 2>&1
```

### 2.8 Version Tracking & BSim

**Version Tracking** (Tools -> Version Tracking): compare old vs new binary; unmatched functions = new code; changed functions = patch targets.

**BSim**:
```bash
./support/bsim createdatabase file:/tmp/bsim_db medium_32
./support/bsim generatesigs ghidra:/tmp/proj/binary --bsim file:/tmp/bsim_db
# Ghidra -> BSim -> Search BSim Database
```

### 2.9 Notable Extensions

| Extension | Purpose |
|---|---|
| ghidra-firmware-utils | UEFI, Intel ME, coreboot firmware |
| GhidraNES / GhidraGBA | Game console ROM analysis |
| kaiju | CERT function hashing plugin |
| OOAnalyzer | C++ object reconstruction |
| ret-sync | Sync with GDB/x64dbg/WinDbg |

---
## 3. IDA Pro & Binary Ninja

### 3.1 IDA Pro Workflow

```
1. Open binary -> auto-analysis (wait for progress bar)
2. Functions window (Ctrl+1), Names window (Ctrl+4), Strings (Shift+F12)
3. Start with interesting imports -> X to find callers
4. Navigate graph view (Space) for control flow
```

**Key shortcuts**: X=Xrefs, G=GoTo, N=Rename, Y=SetType, ;=Comment, D=DataType, F5=Decompiler

### 3.2 IDAPython

```python
import idc, idaapi, idautils, ida_bytes, ida_name, ida_funcs

val = idc.get_operand_value(0x401234, 1)               # operand value
ea = ida_name.get_ea_by_name("CreateFileW")            # address by name

for func_ea in idautils.Functions():                   # iterate functions
    print(idc.get_func_name(func_ea) + " @ " + hex(func_ea))

idc.set_cmt(0x401000, "Entry point", 0)                # regular comment
idc.set_cmt(0x401000, "Entry point", 1)                # repeatable comment
data = ida_bytes.get_bytes(0x402000, 16)               # read bytes
ida_funcs.add_func(0x403000)                           # create function
idc.set_name(0x404000, "decrypt_blob", idc.SN_CHECK)   # rename
ida_bytes.patch_byte(0x401005, 0x90)                   # patch NOP

for xref in idautils.XrefsTo(ea):
    print("from " + hex(xref.frm))

func = idaapi.get_func(0x401234)
print("Function start: " + hex(func.start_ea))
```

### 3.3 FLIRT Signatures

```
Purpose: Recognize standard library functions without symbols
Workflow:
1. File -> Load File -> FLIRT Signature File -> select .sig
2. Matched functions get proper names (FUN_401234 -> _strlen)

Creating signatures:
pelf   libssl.a  libssl.pat      # generate pattern file
sigmake libssl.pat libssl.sig   # generate signature

Pre-built databases:
  https://github.com/push0ebp/sig-database
  https://github.com/Maktm/FLIRTDB
```

### 3.4 LUMINA & Remote Debugging

**LUMINA**: IDA cloud function hash lookup. Enable: Options -> General -> LUMINA.

**Remote debugging**:
```bash
# Run on target machine (from IDA/dbgsrv/):
./linux_server64 -p 23946
win64_server.exe    # Windows target

# In IDA: Debugger -> Select Debugger -> Remote GDB
# Process Options -> Hostname: <target IP>:23946
```

### 3.5 Binary Ninja Architecture

**IL Layers** (lowest to highest abstraction):
```
LLIL - Low Level IL: direct assembly translation, register names preserved
MLIL - Medium Level IL (SSA): variables named, type inference
HLIL - High Level IL: C-like pseudocode
```

**Python API:**
```python
import binaryninja as bn

bv = bn.open_view("/path/to/binary")
bv.update_analysis_and_wait()

for func in bv.functions:
    print(func.name + " @ " + hex(func.start))

for func in bv.functions:
    for block in func.hlil:
        for instr in block:
            print(instr)

func = bv.get_functions_by_name("main")[0]
for param in func.parameter_vars:
    print("param: " + param.name + " type=" + str(param.type))

for ref in bv.get_code_refs(func.start):
    print("called from " + hex(ref.address))

func.name = "decrypt_config"
func.set_comment_at(func.start, "Decrypts embedded config blob")
data = bv.read(0x401000, 64)
bv.write(0x401005, b'')
bv.create_database("/path/to/output.bndb")
```

### 3.6 Binary Ninja Plugins & Cutter

**Plugins**: SigKit (FLIRT), Tenet (trace visualization), emilator (x86 emulation), bnida (IDA import)
- Install: Binary Ninja -> Plugins -> Plugin Manager

**Cutter** (Radare2 GUI, https://cutter.re):
```bash
aaa           # analyze all
afl           # list all functions
pdf @ main    # disassemble function at main
px 64 @ 0x401000  # hex dump
iz            # strings in data sections
ii            # imports
ie            # exports
```

---
## 4. Assembly for Security Analysis

### 4.1 x86-64 Instruction Reference

```asm
; Data Movement
MOV  dst, src       ; dst = src
LEA  dst, [expr]    ; dst = address of expr (no memory access)
MOVSX dst, src      ; move with sign extension
MOVZX dst, src      ; move with zero extension
XCHG dst, src       ; swap
BSWAP reg           ; reverse byte order (endian swap)
PUSH src / POP dst  ; RSP -= 8; [RSP] = src / dst = [RSP]; RSP += 8

; Control Flow
CALL target         ; PUSH RIP; JMP target
RET                 ; POP RIP (return)
RET  n              ; POP RIP; RSP += n (stdcall)
JMP  target         ; unconditional jump

; Conditional jumps (Jcc):
JE/JZ    JNE/JNZ   ; equal/zero, not equal
JA/JAE   JB/JBE    ; above/below (unsigned)
JG/JGE   JL/JLE    ; greater/less (signed)
JS/JNS   JO/JNO    ; sign, overflow

; Arithmetic
ADD  dst, src   SUB  dst, src
IMUL dst, src, imm            ; dst = src * imm
DIV  src                      ; RAX = RDX:RAX / src; RDX = remainder
INC/DEC dst    NEG dst        ; ++/--, negate
AND/OR/XOR/NOT dst, src       ; bitwise ops
SHL/SAR/SHR dst, n            ; shifts
CMP  a, b     TEST a, b       ; set flags only
```

### 4.2 String Ops & SIMD

```asm
; String operations (with REP prefix):
REP MOVSB/MOVSQ    ; copy [RSI]->[RDI], RCX times
REP STOSB/STOSQ    ; fill [RDI] with AL/RAX
REPE CMPSB         ; compare while equal
REPNE SCASB        ; scan for AL (strlen pattern)

; SIMD / Crypto recognition:
MOVDQA/MOVDQU xmm0, [mem]   ; 128-bit aligned/unaligned move
PCMPEQB xmm0, xmm1          ; compare 16 bytes (string search)
PXOR    xmm0, xmm1          ; 128-bit XOR (AES, ChaCha20)
AESENC/AESENCLAST xmm0, xmm1 ; AES-NI hardware rounds
PSHUFB  xmm0, xmm1          ; byte shuffle (AES MixColumns)
SHA256RNDS2 xmm0, xmm1      ; SHA-NI hardware round
```

### 4.3 Stack Frame Structure

```asm
; Prologue:
PUSH RBP          ; save caller's base pointer
MOV  RBP, RSP     ; establish frame
SUB  RSP, 0x40    ; allocate locals

; Locals: [RBP - 0x04], [RBP - 0x08] ...
; First stack arg (SysV): [RBP + 0x10]

; Epilogue:
MOV  RSP, RBP
POP  RBP
RET
```

Stack layout (high to low): stack args | return address | saved RBP | locals | (red zone 128B below RSP, SysV only)

### 4.4 Recognizing C Constructs

```asm
; if (a > b) { ... } else { ... }
CMP  rax, rbx
JLE  else_branch
  ; then block
JMP  end_if
else_branch:
  ; else block
end_if:

; Switch (jump table):
CMP  eax, 5             ; bound check
JA   default_case
MOVSXD rcx, eax
LEA  rdx, [jump_table]
MOV  rax, [rdx + rcx*8]
JMP  rax                ; dispatch

; Loop:
XOR  ecx, ecx           ; i = 0
loop_top:
CMP  ecx, [n]
JGE  loop_end
  ; body
INC  ecx
JMP  loop_top

; Struct access (S *p in RDI):
MOV eax, [rdi]          ; p->a  (offset 0)
MOV rax, [rdi + 8]      ; p->b  (offset 8, pointer)
MOV eax, [rdi + 16]     ; p->c  (offset 16)
```

### 4.5 C++ Artifacts

```
Object layout: [vtable ptr][field1][field2]...
Vtable (.rdata): [func0][func1][func2]...

Virtual call:
    MOV rax, [rdi]       ; load vtable ptr
    CALL [rax + 0x10]    ; call vtable[2]

RTTI / name mangling (Itanium ABI):
    _Z3foov      -> foo()
    _ZN3Foo3barEi -> Foo::bar(int)
    c++filt _ZN3Foo3barEi   # demangle

IT block (ARM Thumb-2):
    CMP r0, #0
    ITTE EQ
    MOVEQ r1, #1    ; if EQ
    ADDEQ r0, r1, r2
    MOVNE r1, #0    ; if NE

MIPS delay slot: instruction after JAL/BEQ ALWAYS executes before jump
```

### 4.6 Recognizing Library Functions Without Symbols

```asm
; strlen (REPNE SCASB):
MOV  ecx, -1
REPNE SCASB        ; scan for null (AL=0)
NOT  ecx
DEC  ecx           ; result = string length

; memcpy (inline): REP MOVSQ with size/8 in RCX

; malloc: MOV edi, <size>; CALL malloc

; strcmp: byte-by-byte loop, CMP [rdi],[rsi], JNE differ, TEST al,al, JZ equal
```

---
## 5. Dynamic Analysis & Debugging

### 5.1 x64dbg

**Breakpoints**:  (API),  (hardware),  (memory)
**Stepping**: F7=step into, F8=step over, F9=run, Ctrl+F9=run until return
**Views**: Alt+1=CPU, Alt+2=Graph, Alt+5=Memory map, Alt+6=Call stack

**Plugins**:
| Plugin | Purpose |
|---|---|
| ScyllaHide | Comprehensive anti-debug bypass |
| xAnalyzer | Automatic API call annotation |
| OllyDumpEx | Dump process memory with PE reconstruction |
| ret-sync | Sync with Ghidra/IDA |

### 5.2 GDB with Security Extensions

pwndbg: context, heap, bins, got, telescope, checksec, cyclic, vis_heap_chunks

GEF: heap-analysis-helper, format-string-helper, pattern create/search, xinfo, vmmap



### 5.3 WinDbg



### 5.4 Frida Dynamic Instrumentation





**Android Java hooking**:


### 5.5 Anti-Analysis Identification

- **RDTSC timing**: delta too large = debugger. Bypass: ScyllaHide or patch to constant.
- **IsDebuggerPresent()**: patch return to 0 or ScyllaHide patches PEB.BeingDebugged
- **CheckRemoteDebuggerPresent()**: hook to return FALSE
- **NtQueryInformationProcess(ProcessDebugPort)**: debugPort != 0 = debugger attached
- **Heap flags**: PEB+0x18->ProcessHeap; +0x40->NtGlobalFlag==0x70 when debugged
- **TLS Callbacks**: execute BEFORE main/DllMain; in x64dbg: Options->Preferences->Events->TLS Callbacks
- **Exception-based CF**: INT3 or intentional AV triggers SEH/VEH handler; debugger sees differently

---
## 6. Unpacking and Deobfuscation

### 6.1 Packer Detection

Detect-It-Easy:  or 

Entropy analysis (above 7.0/8.0 suggests packed/encrypted sections):


### 6.2 Generic Unpacking

**ESP Trick (OEP Finding)**:


**VirtualAlloc Memory Breakpoint**:


**Scylla (IAT Reconstruction)**: IAT Autosearch -> Get Imports -> Dump -> Fix Dump

### 6.3 UPX



### 6.4 FLOSS



### 6.5 XOR Key Recovery



### 6.6 Base64 and Custom Encoding



### 6.7 Control Flow Flattening

Pattern: all blocks routed through a dispatcher switch on a state variable.



### 6.8 .NET Deobfuscation



### 6.9 Runtime Deobfuscation with Frida



---
## 7. Protocol Reverse Engineering

### 7.1 Methodology



### 7.2 Wireshark for Binary Protocols

- **Follow TCP Stream**: Right-click packet -> Follow -> TCP Stream; set Hex Dump view
- **Decode-as**: Right-click -> Decode As -> select protocol (for non-standard ports)
- **Export PDUs**: File -> Export PDUs to File
- **Display filters**: , , 

**Lua Dissector**:


### 7.3 Scapy for Custom Parsing



### 7.4 Pattern Identification Reference

| Pattern | Description | Notes |
|---|---|---|
| Length-prefixed | [4B length][data] | Check endianness; may include/exclude header |
| TLV | [type][len][value] | Type may be 1, 2, or 4 bytes |
| Magic bytes | First 2-8 bytes fixed | PE: 4D5A; ELF: 7F454C46; PNG: 89504E47 |
| CRC32 | Last 4 bytes | Verify with binascii.crc32 |

### 7.5 Protocol Buffers RE



### 7.6 TLS Traffic Decryption



### 7.7 Boofuzz Protocol Fuzzing



### 7.8 Firmware Protocol RE

**UART**: USB-UART adapter (3.3V), TX->RX, RX->TX, GND->GND. Common baud: 115200.


**JTAG**: OpenOCD + adapter (J-Link, Bus Pirate). Identify pins with JTAGulator.

---
## 8. Mobile and Embedded RE

### 8.1 Android Application RE



**objection REPL commands**:
- 
- 
- 
- 
- 

**Native library analysis**:


### 8.2 iOS Application RE



### 8.3 Embedded Firmware RE



**Ghidra for bare-metal**: Set correct Language, configure memory map from datasheet, mark reset vector.
ARM Cortex-M vector table at 0x00000000: [0x00]=SP, [0x04]=Reset handler.

### 8.4 UEFI Firmware RE



Analysis: load each .efi module in Ghidra, apply EFI type definitions,
match GUIDs, look for protocol installation and GetVariable calls.

---
## 9. Vulnerability Discovery via RE

### 9.1 Static Vulnerability Patterns in Disassembly

**Buffer overflow indicators** (no bounds check before copy):


**Integer overflow before allocation**:


**Format string vulnerability**:


**Use-after-free**:  without zeroing, then  dereferenced later.

**OOB access**: untrusted index in  without bounds check.

### 9.2 Taint Analysis



### 9.3 angr Symbolic Execution



### 9.4 Authentication Bypass Patterns

**Signed vs unsigned comparison**:


**Hardcoded credentials**: 

**Timing oracle**: early exit on strcmp mismatch leaks information;
constant-time: XOR all bytes, check accumulated result at end.

### 9.5 Patch Diffing for N-day Research

**BinDiff**: export BinExport from IDA/Ghidra for both versions,
compare matched/unmatched functions, focus on changed security-sensitive functions.

**Diaphora** (IDA plugin): exports .sqlite, compares two databases.

**Git bisect**:


---
## 10. CTF RE and Learning Resources

### 10.1 CTF Reverse Engineering Categories

| Category | Description | Common Tools |
|---|---|---|
| Crackme / Keygenme | License key / serial validation | Ghidra, x64dbg, z3 |
| Custom VM / Interpreter | Bytecode-executing virtual machine | Ghidra, angr, manual |
| Obfuscated Code | OLLVM, control flow flattening | deflat.py, D810 |
| Polyglot / Multi-format | Valid in multiple file formats | binwalk, file, xxd |
| Anti-debug Challenges | Deliberately evades debuggers | ScyllaHide, Frida |
| Firmware Images | Router/IoT binary analysis | binwalk, Ghidra |
| .NET / Java Bytecode | Managed code challenges | dnSpyEx, jadx |
| Kernel / Driver | Ring-0 code analysis | WinDbg, IDA |

### 10.2 CTF Methodology



Strategy: static (Ghidra) -> dynamic (debugger) -> automate (z3/angr/pwntools)

### 10.3 Z3 SMT Solver



### 10.4 angr for CTF



### 10.5 pwntools for RE Scripting



### 10.6 RetDec Decompiler



### 10.7 Practice Platforms

| Platform | Focus |
|---|---|
| pwn.college | Comprehensive RE + pwn curriculum, dojo system |
| reversing.kr | Classic crackme-style challenges |
| crackmes.one | Community crackmes, rated by difficulty |
| FLARE-ON Archive | Mandiant annual RE challenge (archived) |
| challenges.re | Dennis Yurichev RE challenges with solutions |
| OverTheWire | Linux-based progressive challenges |
| Hack The Box | Mixed challenges including RE category |
| picoCTF | Beginner-friendly, good RE category |

### 10.8 Learning Resources

**Video / Streaming**:
- OALabs (YouTube): malware analysis, unpacking, dynamic RE
- LiveOverflow (YouTube): binary exploitation, RE fundamentals
- Gynvael Coldwind (YouTube): CTF streams, RE, assembly
- MalwareTech (YouTube): malware analysis deep dives
- stacksmashing (YouTube): hardware RE, embedded, side-channel

**Courses & Books**:
- OpenSecurityTraining2 Arch 1001 / 1002 (x86-32 and x86-64, free)
- OpenSecurityTraining2 MalwareAnalysis (free)
- Practical Malware Analysis (Sikorski/Honig)
- The IDA Pro Book (Eagle)
- Hacking: The Art of Exploitation (Erickson)

**Reference Documentation**:
- Intel SDM: software.intel.com/sdm (Vol 2: instruction reference)
- ARM Architecture Reference Manual: developer.arm.com/documentation/ddi0487
- System V AMD64 ABI: gitlab.com/x86-psABIs/x86-64-ABI
- Microsoft PE/COFF Spec: docs.microsoft.com/en-us/windows/win32/debug/pe-format

**Communities**:
- REcon (Montreal) - dedicated RE conference
- DEF CON RE Village
- vx-underground (malware samples and papers)
- /r/ReverseEngineering

---

*Reference compiled for professional security research and education.*
*All techniques must be applied only on systems you own or have explicit written authorization to analyze.*
