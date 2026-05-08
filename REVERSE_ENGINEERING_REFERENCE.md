# Reverse Engineering Reference

> Defensive analyst reference for malware analysis, firmware analysis, and vulnerability research.
> All techniques described are for authorized security research, incident response, and defensive purposes.

---

## Section 1: RE Fundamentals & Architectures

### Legal Context and Authorization Framework

Reverse engineering for security research operates under several legal frameworks that analysts should understand before beginning any engagement.

**DMCA Section 1201 Security Research Exemption (USA):** The Digital Millennium Copyright Act's anti-circumvention provisions include a security research exemption (17 U.S.C. 1201(j)) allowing circumvention of technological protection measures for good-faith security research. The exemption requires the researcher to be employed or a student in a field of computer security, that the activity is for purposes of good-faith security research, and that information derived is used primarily to promote security. The Copyright Office periodically renews and expands exemptions. The 2021 rulemaking explicitly covers software security research, including on motor vehicles, medical devices, and networked devices. Always work under a defined scope of engagement or with explicit authorization from the software owner.

**CFAA Authorized Access (USA):** The Computer Fraud and Abuse Act (18 U.S.C. 1030) criminalizes access to protected computers "without authorization" or "exceeding authorized access." For RE analysts, this means: operate only on systems you own, systems where you have explicit written authorization (bug bounty scope, penetration test contract, incident response retainer), or isolated lab environments with no live system connectivity. The Van Buren v. United States (2021) Supreme Court ruling narrowed "exceeds authorized access" to mean accessing information that is off-limits, not merely using authorized access for an improper purpose. Explicit authorization remains best practice.

**EU Software Directive 2009/24/EC Interoperability Exception:** Article 6 of the EU Software Directive permits decompilation of a computer program without the rightholder's authorization when necessary to achieve interoperability of an independently created program with the original, provided: the acts are performed by a licensee or someone authorized to use the program, the information necessary for interoperability has not previously been made available, and the acts are confined to the parts of the original program necessary for interoperability. This is the primary legal basis for legitimate interoperability-focused RE in EU jurisdictions.

**Practical Authorization Checklist:**
- Written authorization or bug bounty scope document on file
- Isolated analysis environment (no production network connectivity)
- Data handling agreement for any samples containing PII
- Findings disclosure plan (coordinated disclosure timeline)
- Jurisdiction-specific counsel review for cross-border research

---

### x86-64 Architecture

#### Registers

| Register | Width | Primary Purpose |
|----------|-------|-----------------|
| RAX | 64-bit | Accumulator; return value (integer/pointer) |
| RBX | 64-bit | Base; callee-saved general purpose |
| RCX | 64-bit | Counter; 4th arg (Windows), loop counter |
| RDX | 64-bit | Data; 3rd arg (Windows), I/O port ops |
| RSI | 64-bit | Source index; 2nd arg (System V) |
| RDI | 64-bit | Destination index; 1st arg (System V) |
| RBP | 64-bit | Frame pointer (optional with -fomit-frame-pointer) |
| RSP | 64-bit | Stack pointer; always points to current top of stack |
| R8-R15 | 64-bit | Additional general-purpose registers |
| RIP | 64-bit | Instruction pointer; not directly writeable |

**Sub-register aliases:** EAX/AX/AH/AL are the lower 32/16/8/8 bits of RAX. Writing to a 32-bit register (e.g., EAX) zero-extends to 64 bits; writing to 16/8-bit registers does not. This is a common source of subtle bugs and an anti-analysis technique.

**RFLAGS Important Bits:**

| Bit | Abbreviation | Meaning |
|-----|--------------|---------|
| 0 | CF | Carry Flag: unsigned overflow |
| 2 | PF | Parity Flag |
| 4 | AF | Auxiliary Carry (BCD arithmetic) |
| 6 | ZF | Zero Flag: result was zero |
| 7 | SF | Sign Flag: result was negative |
| 8 | TF | Trap Flag: single-step debug mode |
| 9 | IF | Interrupt Enable Flag |
| 10 | DF | Direction Flag: string ops direction |
| 11 | OF | Overflow Flag: signed overflow |

**Segment Registers:** CS (Code Segment), DS (Data Segment), SS (Stack Segment), ES (Extra Segment), FS and GS (general purpose, OS-specific use). On Windows x64, GS holds the Thread Information Block (TIB) base; FS holds TIB on x86 Windows. On Linux x64, FS holds the Thread Local Storage (TLS) base. Malware frequently accesses FS:[0x30] (x86) or GS:[0x60] (x64) to locate the Process Environment Block (PEB) without calling Windows API functions.

**XMM/YMM/ZMM Registers:** XMM0-XMM15 are 128-bit SSE2 registers (available on all x86-64 CPUs). YMM0-YMM15 extend to 256-bit (AVX). ZMM0-ZMM31 extend to 512-bit (AVX-512). These are used for SIMD (Single Instruction Multiple Data) operations. In calling conventions, XMM0-XMM7 are used for floating-point arguments. Cryptographic implementations often use AESNI instructions (AESENC, AESDEC) operating on XMM registers.

#### Calling Conventions

**System V AMD64 ABI (Linux, macOS, BSDs):**
- Integer/pointer arguments: RDI, RSI, RDX, RCX, R8, R9 (in order)
- Additional args: pushed on stack right-to-left
- Return value: RAX (integer/pointer), RDX:RAX for 128-bit return
- Caller-saved (volatile): RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11
- Callee-saved (non-volatile): RBX, RBP, R12, R13, R14, R15
- Stack alignment: 16-byte aligned before CALL instruction
- Red zone: 128 bytes below RSP reserved (leaf functions may use without adjusting RSP)

**Microsoft x64 ABI (Windows):**
- Integer/pointer arguments: RCX, RDX, R8, R9 (in order)
- Floating-point arguments: XMM0, XMM1, XMM2, XMM3
- Additional args: pushed on stack
- Shadow space: 32 bytes (4 x 8) allocated by CALLER above return address, even if fewer than 4 args
- Return value: RAX, XMM0 for floating-point
- Caller-saved: RAX, RCX, RDX, R8, R9, R10, R11
- Callee-saved: RBX, RBP, RDI, RSI, R12, R13, R14, R15, XMM6-XMM15
- Stack alignment: 16-byte aligned before CALL

**Legacy cdecl (x86, Linux/GCC):**
- All arguments pushed on stack right-to-left
- Caller cleans up stack (ADD ESP, N after CALL)
- Return in EAX (EDX:EAX for 64-bit)
- Caller-saved: EAX, ECX, EDX

**Legacy stdcall (x86, Windows API):**
- Arguments pushed right-to-left; callee cleans stack (RETN N)
- Used throughout Win32 API

**Legacy fastcall (x86, MSVC):**
- First two args in ECX, EDX; remainder on stack

#### Stack Frame Structure

```asm
; Standard prologue
push rbp             ; save caller's frame pointer
mov  rbp, rsp        ; establish new frame pointer
sub  rsp, 0x50       ; allocate local variable space (16-byte aligned)
; Function body uses [rbp-N] for locals, [rbp+16] for first stack arg

; Standard epilogue
leave                ; equivalent to: mov rsp, rbp; pop rbp
ret                  ; return to caller
```

#### Common Compiler Patterns

**Loop Recognition:**
- do-while: single block with conditional backward jump (JNZ label_top)
- while: conditional forward jump to skip body (JZ label_end) at top, unconditional backward jump (JMP label_top) at bottom
- for: init before loop, condition check at top, increment after body
- Compilers (especially with optimization) often convert while to do-while by hoisting the condition

**Switch Statement Jump Tables:**
```asm
cmp  eax, MAX_CASE      ; bounds check
ja   default_handler    ; out of range -> default
lea  rcx, [table]       ; load table base (RIP-relative on x64)
mov  eax, [rcx+rax*4]  ; load 32-bit offset from table
add  rcx, rax           ; compute target address
jmp  rcx                ; dispatch
```
Recognize: bounds check immediately before indirect jump, nearby data block of same-sized entries.

**Virtual Dispatch (C++ vtables):**
```asm
mov rax, [rdi]          ; load vtable pointer (object at RDI, vptr at offset 0)
call [rax+0x18]         ; call virtual function at vtable slot index 3 (offset 0x18 = 3*8)
```
RTTI on MSVC: type_info structure in .rdata with mangled class name. On GCC/Clang: __cxa_type_info with _ZTI prefix. Use Ghidra's RecoverClassesFromRTTI script to reconstruct class hierarchy.

---

### ARM64/AArch64 Architecture

**Registers:**
- X0-X30: 64-bit general purpose (W0-W30 are 32-bit lower halves)
- X30 = LR (Link Register): holds return address for BL/BLR
- SP: Stack Pointer (aligned to 16 bytes)
- PC: Program Counter (not directly accessible as a register in most contexts)
- XZR/WZR: Zero register: reads always return 0, writes discarded

**AAPCS64 Calling Convention:**
- Arguments: X0-X7 (integer/pointer), V0-V7 (floating-point/SIMD)
- Return: X0 (or X0+X1 for 128-bit), V0 for float
- Callee-saved: X19-X28, X29 (frame pointer), X30 (link register), SP

**AArch32/Thumb2 Interworking:**
- BLX instruction switches between ARM and Thumb mode
- LSB of branch target address: 1 = Thumb, 0 = ARM
- T32 (Thumb2) instructions are 16 or 32 bits wide; common on Cortex-M embedded targets

---

### MIPS32 Architecture

**Register Conventions (MIPS O32 ABI):**
- $a0-$a3: First four function arguments
- $v0-$v1: Return values
- $t0-$t9: Temporaries (caller-saved)
- $s0-$s7: Saved temporaries (callee-saved)
- $ra: Return address (set by JAL/JALR)
- $sp: Stack pointer, $fp: Frame pointer, $gp: Global pointer

**Branch Delay Slots:** Every branch/jump instruction in MIPS has a delay slot: the instruction immediately following the branch is always executed before the branch takes effect. Disassemblers show this; decompilers abstract it away. Watch for intentional misuse: shellcode sometimes places meaningful code in delay slots to confuse naive disassemblers.

**Endianness:** MIPS runs both big-endian (network equipment, older SGI) and little-endian (PlayStation, some routers). The file command will identify; binwalk and Ghidra handle both.
---

## Section 2: Binary Formats

### ELF (Executable and Linkable Format)

ELF is the standard binary format for Linux, Android, BSD, and most embedded systems.

#### ELF Header Fields

| Field | Size | Notes |
|-------|------|-------|
| e_ident | 16 bytes | Magic: 7f 45 4c 46 (\x7fELF), class (32/64-bit), endian, ABI |
| e_type | 2 bytes | ET_EXEC=executable, ET_DYN=shared/PIE, ET_REL=object, ET_CORE=core dump |
| e_machine | 2 bytes | EM_X86_64=62, EM_ARM=40, EM_AARCH64=183, EM_MIPS=8 |
| e_entry | 4/8 bytes | Virtual address of entry point |
| e_phoff | 4/8 bytes | Offset to program header table |
| e_shoff | 4/8 bytes | Offset to section header table |
| e_flags | 4 bytes | Architecture-specific flags (ARM ABI version, MIPS arch) |

```bash
readelf -h binary     # ELF header
readelf -l binary     # program headers (segments)
readelf -S binary     # section headers
readelf -d binary     # dynamic section
readelf -s binary     # symbol table
readelf -r binary     # relocation entries
```

#### Key ELF Sections

| Section | Contents |
|---------|----------|
| .text | Executable machine code |
| .data | Initialized read-write data (global variables with initial values) |
| .bss | Zero-initialized data (no file space; allocated at load time) |
| .rodata | Read-only data: string literals, constants, jump tables |
| .got | Global Offset Table: pointer table for PIE/ASLR relocation |
| .plt | Procedure Linkage Table: stub code for lazy binding |
| .plt.got | PLT entries for read-only GOT (full RELRO builds) |
| .dynamic | Dynamic linking metadata: DT_NEEDED, DT_SYMTAB, etc. |
| .dynsym | Dynamic symbol table (exported/imported symbols) |
| .symtab | Full symbol table (stripped in release builds) |
| .rel.plt / .rela.plt | Relocation entries for PLT (RELA has explicit addend) |
| .debug_* | DWARF debug information: line numbers, types, variable names |

#### PLT/GOT Lazy Binding Mechanism

On first call to printf@PLT: the PLT stub loads the GOT entry, which initially points back into the PLT resolver. The resolver calls _dl_runtime_resolve(link_map, reloc_index), which patches the GOT entry with the real address. All subsequent calls go directly from PLT stub to printf in libc.

**Security relevance:** A writable GOT is a classic exploitation target. Check for FULL RELRO with: `readelf -l binary | grep GNU_RELRO` and verify BIND_NOW in the dynamic section.

#### Relocation Types (x86-64)

| Type | Value | Meaning |
|------|-------|---------|
| R_X86_64_64 | 1 | Absolute 64-bit address |
| R_X86_64_PC32 | 2 | PC-relative 32-bit |
| R_X86_64_GLOB_DAT | 6 | GOT entry for symbol |
| R_X86_64_JUMP_SLOT | 7 | PLT/GOT slot for symbol |
| R_X86_64_RELATIVE | 8 | Base + addend (PIE relocation) |

#### Hardening Features (checksec)

```bash
checksec --file=binary
# RELRO: Full  STACK CANARY: Found  NX: Enabled  PIE: Enabled  RPATH: No
```

| Feature | Meaning if Absent |
|---------|-------------------|
| RELRO Full | GOT is writable; overwrite attacks are possible |
| Stack Canary | Stack smashing without canary bypass is simpler |
| NX/DEP | Stack/heap is executable; direct shellcode injection possible |
| PIE | Code at fixed address; ROP gadget addresses are static |
| RPATH/RUNPATH | DLL hijacking via manipulated library search path |

---

### PE/PE32+ Format (Windows)

#### File Structure

```
[DOS Header (64 bytes)]
  e_magic: 0x5A4D (MZ)
  e_lfanew: offset to NT headers

[NT Headers]
  Signature: 0x00004550 (PE\0\0)
  FileHeader: Machine, NumberOfSections, TimeDateStamp, Characteristics
  OptionalHeader:
    Magic: 0x10B=PE32, 0x20B=PE32+
    AddressOfEntryPoint, ImageBase
    SectionAlignment, FileAlignment
    Subsystem (GUI=2, CUI=3, Native=1)
    DataDirectory[16]: Export, Import, Resource, Security, TLS, ...

[Section Table]
[Sections: .text .data .rdata .rsrc ...]
```

#### Section Characteristics Flags

| Flag | Meaning |
|------|---------|
| 0x00000020 | Contains code |
| 0x00000040 | Contains initialized data |
| 0x00000080 | Contains uninitialized data |
| 0x20000000 | Executable |
| 0x40000000 | Readable |
| 0x80000000 | Writeable |

#### Import Table (PE Imports)

The IMAGE_IMPORT_DESCRIPTOR describes one imported DLL. OriginalFirstThunk points to the Import Name Table (INT), containing IMAGE_IMPORT_BY_NAME structures with Hint and function name. FirstThunk points to the Import Address Table (IAT), which the Windows loader patches with real addresses at load time.

**IAT forensics:** In a running process, IAT entries hold resolved addresses. If an IAT entry points outside the expected DLL's memory range, this indicates IAT hooking (malware intercepting Windows API calls). Compare against GetModuleHandle/GetProcAddress results.

#### Export Table

IMAGE_EXPORT_DIRECTORY contains AddressOfFunctions (Export Address Table, RVA array), AddressOfNames (name strings), and AddressOfNameOrdinals (ordinal indices). Exports by ordinal only (no name) are common in malware to hinder static analysis.

#### TLS Callbacks

IMAGE_TLS_DIRECTORY.AddressOfCallBacks points to an array of function pointers executed **before** the entry point by the Windows loader. Malware uses TLS callbacks for anti-analysis code, early decryption, or to bypass code at the standard entry point. Check TLS callbacks in pestudio or pefile.

#### Resources (.rsrc)

Resources use a three-level tree: Type, Name, Language. Malware embeds payloads as resources, commonly RT_RCDATA (type 10) or custom types. Extract with wrestool or ResourceHacker. Resource entropy above 7.0 suggests an embedded encrypted or compressed payload.

#### Authenticode Signatures

Authenticode signs a hash of the file (excluding the signature region per the Authenticode specification). The WIN_CERTIFICATE structure in the Security Directory contains a PKCS#7 CMS SignedData blob. Malware increasingly uses stolen or leaked code-signing certificates. Verify with sigcheck -a (Sysinternals) or osslsigncode. Check CRL/OCSP revocation status.

#### .NET Assemblies

The CLR header (IMAGE_COR20_HEADER) at the COM descriptor data directory marks a .NET assembly. The metadata root begins with BSJB magic. Metadata tables describe types, methods, and fields. Decompilers (dnSpy, ILSpy) reconstruct near-source-quality C#. Apply de4dot before decompiling to handle ConfuserEx, SmartAssembly, and other .NET protectors.

---

### Mach-O (macOS, iOS, tvOS, watchOS)

#### Universal Binaries

Universal (fat) binaries contain a fat_header with nfat_arch entries. Each entry specifies cputype, cpusubtype, offset, and size. Extract a single slice with: `lipo -thin arm64 universal.dylib -output arm64.dylib`

#### Load Commands

| Load Command | Purpose |
|-------------|---------|
| LC_SEGMENT_64 | Defines a memory segment (__TEXT, __DATA, __LINKEDIT) |
| LC_DYLD_INFO | dyld info: rebase, binding, export trie |
| LC_SYMTAB | Symbol table offset and string table |
| LC_DYSYMTAB | Dynamic symbol table index ranges |
| LC_MAIN | Modern entry point specification |
| LC_LOAD_DYLIB | Dependency dynamic library |
| LC_CODE_SIGNATURE | Code signature blob offset |
| LC_ENCRYPTION_INFO_64 | FairPlay encrypted region (iOS App Store apps) |

Commands: `otool -l binary` (all load commands), `otool -L binary` (linked libraries), `nm -g binary` (exported symbols).

#### Code Signing

LC_CODE_SIGNATURE points to a SuperBlob containing: code directory hashes (SHA-256 of each 4096-byte page), entitlements plist, and CMS signature. Review entitlements with: `codesign -dv --entitlements - binary`. On iOS, entitlements control sandbox capabilities and reveal an app's privileged access level.

---

### WebAssembly (WASM)

WASM modules start with magic \x00asm and version \x01\x00\x00\x00. Sections are sequentially numbered:

| Section | Name | Contents |
|---------|------|----------|
| 1 | Type | Function signatures |
| 2 | Import | Imported functions, globals, tables, memory |
| 3 | Function | Maps function indices to type indices |
| 4 | Table | Indirect call tables (function pointers) |
| 5 | Memory | Linear memory definition (initial/max pages) |
| 6 | Global | Global variable definitions |
| 7 | Export | Exported items |
| 10 | Code | Function bodies |
| 11 | Data | Linear memory initialization |

Linear memory is a single contiguous byte array accessed with i32.load/i32.store instructions. There are no hardware page protections within the WASM sandbox. Use wasm2wat (wabt toolkit) for text-format disassembly and wasm-decompile for C-like pseudocode.
---

## Section 3: Static Analysis Tools

### Ghidra

Open-source RE suite developed by the NSA, released in 2019. Java-based with extensive scripting support. Free alternative to IDA Pro for most analysis tasks.

#### Navigation and Core Windows

- **CodeBrowser:** Main analysis window. Program tree and symbol table on left; disassembly listing in center; decompiler on right.
- **Function Graph:** CFG (control flow graph) view of a single function. Press G from the listing view. Essential for understanding complex control flow and obfuscated loops.
- **Decompiler Window:** Produces pseudo-C output. Right-click variables to retype; right-click function calls to edit signatures. Decompiler quality degrades with optimization; heavily optimized binaries require manual annotation.
- **Symbol Tree:** Lists namespaces, functions, labels, and classes. Sort by name or address.

#### Improving Decompiler Output

1. **Apply function signatures:** Right-click function -> Edit Function Signature. Import type libraries via File -> Parse C Source or pre-built .gdt files for Windows headers, Linux system headers, or Windows driver kit types.
2. **Set calling convention:** Correctly setting the calling convention prevents the decompiler from misidentifying which registers hold arguments.
3. **Retype variables:** Right-click local variable -> Retype Variable. Applying a correct struct pointer type propagates through the function and replaces opaque offsets with named field accesses.
4. **RTTI recovery:** Run RecoverClassesFromRTTI from Script Manager. Recovers vtable structure and class hierarchies from MSVC or GCC RTTI.
5. **Import Windows type libraries:** Community-provided GDT files for NTDLL, Kernel32, WinSock, and COM types significantly improve decompiler output for Windows malware.

#### PCode Intermediate Representation

Ghidra compiles all supported architectures to PCode, a register-transfer language operating on abstract Varnodes. PCode enables architecture-agnostic analysis scripts that work identically on x86, ARM, and MIPS.

#### Headless Analysis and Scripting

```bash
analyzeHeadless /tmp/ghidra_projects MyProject   -import /path/to/binary   -postScript FindEncryptionConstants.java   -scriptlog /tmp/analysis.log   -deleteProject
```

Python (Jython) scripting example:
```python
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getName().startswith("FUN_"):
        print("Unnamed:", hex(func.getEntryPoint().getOffset()))

refs = getReferencesTo(toAddr(0x401000))
for ref in refs:
    print("Called from:", hex(ref.getFromAddress().getOffset()))
```

#### Ghidra Server for Team Collaboration

Ghidra Server allows multiple analysts to share a single project with concurrent annotation, renaming, and type application. Useful for large malware families where function analysis can be divided among team members.

---

### IDA Pro / IDA Free

The industry-standard commercial disassembler. IDA Free supports x86/x86-64 only and does not include the Hex-Rays decompiler (separate license). The commercial version supports all major architectures and includes the decompiler.

#### IDAPython Scripting

```python
import idc, idautils, ida_hexrays

for func_ea in idautils.Functions():
    print(hex(func_ea), idc.get_func_name(func_ea))

# Decompile a function
cfunc = ida_hexrays.decompile(func_ea)
print(str(cfunc))

# Find all callers of a specific function
target = idc.get_name_ea_simple("InternetOpenA")
for xref in idautils.XrefsTo(target):
    print("Called from:", hex(xref.frm))
```

#### FLIRT Signatures

FLIRT (Fast Library Identification and Recognition Technology) signatures match statically linked library code. Without them, CRT and library functions clutter analysis. Apply: File -> Load File -> FLIRT Signature File (.sig). Create custom signatures with pelf and sigmake from the IDA SDK.

#### Type Libraries (.til files)

Type libraries provide struct, enum, and function prototype definitions for SDKs. Load Windows DDK types, COM interfaces, or custom protocol definitions. Apply types in the decompiler via right-click -> Set Type or IDAPython's SetType().

#### Cross-References

Press X to show all references to the current address. Types include: Call, Jump, Data read (r), Data write (w), Ordinary flow (f). Use graph view for complex call trees.

---

### Binary Ninja

Commercial RE platform with a layered Intermediate Language approach.

| IL Layer | Name | Description |
|----------|------|-------------|
| LLIL | Low Level IL | Direct register-level mapping from assembly |
| MLIL | Medium Level IL | Variables replace registers; type inference applied |
| HLIL | High Level IL | Structured control flow; closest to source code |

MLIL and HLIL require a commercial license. The Community edition provides LLIL and disassembly.

```python
import binaryninja as bn
bv = bn.open_view("/path/to/binary")
for func in bv.functions:
    for block in func.hlil:
        for instr in block:
            print(instr)
```

---

### radare2 / rizin

Open-source command-line RE framework. Rizin is a maintained fork with a stable API and improved tooling.

#### Essential Commands

```
r2 -A binary         # open with full analysis
aaa                  # analyze all (functions, xrefs, strings)
afl                  # list all functions
pdf @ main           # disassemble main()
agf @ main           # function CFG graph
pdc @ main           # pseudo-C decompile
s 0x401000           # seek to address
afn my_func          # rename function at current address
```

r2pipe Python scripting:
```python
import r2pipe, json
r2 = r2pipe.open("/path/to/binary", ["-2"])
r2.cmd("aaa")
functions = json.loads(r2.cmd("aflj"))
for f in functions:
    print(f['name'], hex(f['offset']), f['size'])
```

---

### LIEF (Library to Instrument Executable Formats)

Python/C++ library for parsing and modifying ELF, PE, Mach-O, and WASM without an interactive disassembler.

```python
import lief
binary = lief.parse("sample.exe")
for imp in binary.imports:
    for func in imp.entries:
        print(imp.name, func.name)
for sec in binary.sections:
    print(sec.name, hex(sec.virtual_address), sec.entropy)
```

---

### Command-Line Static Analysis Reference

```bash
objdump -d -M intel binary            # Intel-syntax disassembly
objdump -d -M intel -j .text binary   # .text section only
readelf -a binary                      # all ELF headers and sections
nm -D binary                           # dynamic symbols
nm --demangle binary                   # demangled C++ symbols
strings -a -n 8 binary                 # all printable strings, min 8 chars
strings -a -n 8 -e l binary            # Unicode (LE 16-bit) strings
file binary                            # format identification
```

Entropy analysis with pefile (Python):
```python
import pefile
pe = pefile.PE("sample.exe")
for sec in pe.sections:
    name = sec.Name.decode().rstrip('\x00')
    ent = sec.get_entropy()
    flag = " [HIGH]" if ent > 7.0 else ""
    print(f"{name}: entropy={ent:.2f}{flag}")
```
---

## Section 4: Dynamic Analysis & Debugging

### x64dbg / x32dbg (Windows User-Mode)

x64dbg is the primary open-source Windows debugger for user-mode malware analysis. x32dbg handles 32-bit processes; both are included in the same package.

#### Breakpoint Types

| Type | How to Set | Use Case |
|------|-----------|---------|
| Software (INT3) | F2 key | Most common; patches one byte of code |
| Hardware execute | Right-click -> Breakpoint -> Hardware | No code modification; survives integrity checks |
| Hardware on access | Right-click -> Hardware -> Access | Triggers when address is read |
| Hardware on write | Right-click -> Hardware -> Write | Triggers when address is written |
| Memory breakpoint | Right-click memory -> Breakpoint | Triggers on any access to a memory region |
| Conditional | Right-click BP -> Edit -> Add Condition | Examples: rax==0, utf8([rcx])=="config" |

**Anti-debug bypass:** Prefer hardware breakpoints when malware scans its own code for INT3 (0xCC) bytes as a debugger detection technique.

#### Key Plugins

**ScyllaHide:** Transparent anti-anti-debug. Patches: PEB.BeingDebugged to 0, NtQueryInformationProcess (ProcessDebugPort returns 0), heap flags, and RDTSC timing. Essential for any malware with anti-debug.

**x64dbgpy:** Python scripting interface for automation.

**Scylla:** PE dump and IAT reconstruction after manual unpacking.

---

### WinDbg (Windows Kernel and User Mode)

Microsoft's official debugger. Essential for kernel-mode analysis: rootkits, drivers, and BSoD (Blue Screen of Death) crash analysis.

#### Kernel Mode Connection

```
# Enable kernel debugging on target (run as admin, reboot):
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4

# On analysis machine:
windbg -k net:port=50000,key=1.2.3.4
```

#### Essential WinDbg Commands

```
lm                         # list loaded modules
lm vm nt                   # verbose info for ntoskrnl
x nt!*CreateProcess*       # find symbols matching pattern
dt ntdll!_PEB              # display PEB structure layout
dt ntdll!_TEB @$teb        # display TEB for current thread
dps rsp L20                # dump 32 pointer-sized values from RSP with symbols
u rip L10                  # unassemble 10 instructions from RIP
uf kernel32!CreateFileW    # unassemble entire function
g                          # go (continue execution)
p / t                      # step over / step into
k / kb / kv                # stack trace / with parameters / verbose
!process 0 0               # list all processes
!process -1 0              # current process info
!thread                    # current thread info
!handle 0 f                # list all handles in current process
!analyze -v                # automatic crash analysis (after .ecxr)
```

#### Debugger Object Model (dx)

```
dx Debugger.Sessions[0].Processes
dx Debugger.Sessions[0].Processes.Where(p => p.Name == "malware.exe")
dx -r2 Debugger.Sessions[0].Processes[1234].Threads
```

#### Time Travel Debugging (TTD)

TTD records a complete execution trace and allows stepping backward. Invaluable for malware analysis: work backward from a suspicious API call to find the code that triggered it.

```
# Record a TTD trace
windbg -accepteula -TTD C:\malware\sample.exe

# Navigation in TTD session
!tt 50%     # jump to 50% through the trace
p-          # step backward one instruction
g-          # run backward until next breakpoint
!tt 0       # rewind to start
```

---

### GDB with Enhancements (Linux and Embedded)

#### PWNDBG

Install: `pip install pwndbg`. Provides a complete heap analysis toolkit and improved context display.

```
heap                  # display all heap chunks
bins                  # tcache/fastbins/unsortedbin/smallbins/largebins
vis_heap_chunks       # visual heap layout
context               # registers + stack + disassembly + source in one view
telescope $rsp 20     # smart pointer-chasing stack display
nearpc 20             # 20 instructions around PC
```

#### Core GDB Commands

```
ni / si               # next instruction (step over) / step into
finish                # run until current function returns
bt                    # full backtrace
info registers        # all registers
x/20xw $rsp           # hex dump 20 dwords from RSP
x/s $rdi              # print string at RDI
set $rax = 0          # modify register value
watch *0x601020       # hardware watchpoint on memory write
catch syscall open    # break on open() syscall entry
```

#### Remote Debugging with gdbserver

```bash
# On target (embedded device, QEMU guest, Android)
gdbserver :1234 ./binary

# On analysis machine
gdb-multiarch ./binary
(gdb) target remote 192.168.1.100:1234
(gdb) continue
```

Works for: embedded Linux targets, QEMU-emulated firmware, Android with NDK gdbserver.

---

### LLDB (macOS and iOS)

```
lldb ./binary
(lldb) process launch -- arg1 arg2
(lldb) breakpoint set --name malloc
(lldb) breakpoint set --address 0x100001234
(lldb) register read
(lldb) memory read --format hex --size 8 --count 16 $rsp
(lldb) expression (int)getpid()
```

---

### Frida Dynamic Instrumentation

Cross-platform JavaScript/Python framework for runtime instrumentation without source code. Supports Android, iOS, Windows, Linux, macOS.

#### Core Interceptor API

```javascript
// Intercept a library function (attach with: frida -p PID -l script.js)
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
        console.log("[open] path:", this.path, "flags:", args[1].toInt32());
    },
    onLeave: function(retval) {
        console.log("[open] fd:", retval.toInt32(), "path:", this.path);
    }
});

// Bypass IsDebuggerPresent
Interceptor.attach(Module.findExportByName(null, "IsDebuggerPresent"), {
    onLeave: function(retval) { retval.replace(0); }
});

// Memory operations
var data = Memory.readByteArray(ptr("0x12345678"), 64);
Memory.writeUtf8String(ptr("0x12345678"), "patched_value");
```

#### Frida Command-Line Tools

```bash
frida-ps -U                                # list processes on USB device (Android/iOS)
frida -p 1234 -l script.js                 # attach to PID with script
frida -n "Calculator" -l script.js         # attach to process by name
frida-trace -i "open" -i "recv*" -p 1234   # auto-trace with generated scaffolding
frida-trace -I "libcrypto*" -n "App"       # trace all exports in matched libraries
```

#### Frida Stalker (Code Coverage and Tracing)

```javascript
Stalker.follow(Process.getCurrentThreadId(), {
    events: { call: true, ret: false, exec: false },
    onReceive: function(events) {
        var parsed = Stalker.parse(events);
        // process call/ret event stream for coverage
    }
});
```

---

### strace / ltrace (Linux Syscall and Library Tracing)

```bash
strace ./binary arg1                             # trace all syscalls
strace -e trace=file,network,process ./binary    # filter syscall categories
strace -p 1234 -f -e trace=openat,connect        # attach to PID, follow forks
strace -o strace_output.txt -tt ./binary         # timestamps + file output
ltrace -l '*' ./binary                           # all library calls
ltrace -e malloc+free+realloc ./binary           # trace memory allocation
```

strace output shows exact syscall arguments and return values. The -f flag follows child processes, which is essential for multi-process malware that spawns sub-processes to execute payloads.
---

## Section 5: Anti-Analysis Techniques & Countermeasures

This section is framed for defensive analysts: understanding what obfuscation and anti-analysis techniques look like enables faster identification and bypass during malware analysis.

### Code Obfuscation Techniques

#### Control Flow Flattening

All basic blocks are placed at the same nesting level within a dispatcher loop controlled by a state variable. Legitimate code has hierarchical, nested control flow; flattened code has all blocks at the same depth with one state variable routing execution.

**Recognition:**
- Single large dispatcher with a switch or if-else chain covering all blocks
- All "real" basic blocks at the same loop nesting depth
- State variable updated at the end of each block
- High cyclomatic complexity despite apparent simplicity

**Deobfuscation approaches:**
- angr symbolic execution: mark the state variable as symbolic, explore all paths, and recover original edges
- miasm2 framework: built-in control flow unflattener module
- Manual: identify all possible values of the state variable and reconstruct transitions

#### Opaque Predicates

Conditions that always evaluate to the same boolean value but appear complex enough to fool decompilers. Examples: `(n*(n+1)) % 2 == 0` (always true for any integer n), `(x & (x-1)) == 0` with a specific x value. Recognition: use symbolic execution (Z3 or angr) to determine if a branch condition is satisfiable in both directions.

#### String Obfuscation

**XOR encryption pattern:**
```c
void decrypt(char *buf, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) buf[i] ^= key;
}
```
Look for: short loop iterating over a buffer, XOR instruction with a constant or single-byte key, buffer initialized from .data before the loop.

**Stack strings:** Individual characters assigned to stack offsets (MOV BYTE PTR [rbp-N], CHAR_VALUE instructions). The complete string only exists at runtime.

**RC4 KSA loop:** Runs 256 iterations over a 256-byte S-box. The initialization loop `for(i=0;i<256;i++) S[i]=i;` followed by a shuffle loop is a strong RC4 indicator in disassembly.

**AES S-box constants:** The AES SubBytes S-box begins with `0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5`. These bytes in .rodata strongly indicate AES. AESNI instructions (AESENC, AESDEC, AESKEYGEN) indicate hardware-accelerated AES.

**FLOSS (FireEye FLARE Obfuscated String Solver):** Automatically recovers XOR-encrypted strings, stack strings, and strings decoded by tight loops. Run `floss --no-static-strings binary.exe` to show only decoded strings.

---

### Anti-Debugging Techniques

#### PEB.BeingDebugged (Windows)

The kernel sets PEB.BeingDebugged to 1 when a debugger is attached. Access in assembly:
- x86: `mov eax, fs:[0x30]` then `movzx eax, byte [eax+0x2]`
- x64: `mov rax, gs:[0x60]` then `movzx eax, byte [rax+0x2]`

**Bypass:** ScyllaHide automatically patches this byte to 0. Manual: set a write hardware breakpoint on PEB+0x2, or use the debugger to patch the byte directly.

#### NtQueryInformationProcess

Called with ProcessDebugPort (class 7): returns -1 (0xFFFFFFFFFFFFFFFF) if a debugger is attached, 0 otherwise. Also checked: ProcessDebugObjectHandle (class 30) and ProcessDebugFlags (class 31, returns 0 when debugged).

**Bypass:** ScyllaHide hooks these calls. Manual: set a breakpoint on NtQueryInformationProcess, check the class argument, and patch the return value.

#### Timing-Based Detection (RDTSC)

```asm
rdtsc
mov [saved], eax
; ... measured code block ...
rdtsc
sub eax, [saved]
cmp eax, 0x1000      ; threshold: ~4096 cycles
ja  anti_debug_path  ; debugger is slow -> detected
```

**Bypass:** NOP the conditional jump, or patch the comparison threshold to 0xFFFFFFFF. ScyllaHide can intercept RDTSC.

#### Common Anti-Debug Reference

| Technique | Detection Method | Bypass |
|-----------|-----------------|--------|
| IsDebuggerPresent | Reads PEB.BeingDebugged | ScyllaHide or patch PEB |
| CheckRemoteDebuggerPresent | Wraps NtQueryInformationProcess | ScyllaHide |
| OutputDebugString timing | Measures time for OutputDebugString to return | NOP comparison |
| SEH-based detection | Raises exception; checks if debugger consumed it | Catch exception or NOP check |
| CloseHandle with invalid handle | Debugger raises EXCEPTION_INVALID_HANDLE | ScyllaHide |
| TLS callback anti-debug | Runs before OEP | Set breakpoint at TLS callback addresses |
| Self-modifying code | Code writes over itself; debugger sees original bytes | Dump memory after modification |

---

### Anti-VM and Anti-Sandbox Techniques

#### CPUID-Based VM Detection

```asm
mov eax, 0     ; leaf 0: vendor string
cpuid          ; EBX:EDX:ECX = vendor
; VMware:   "VMwareVMware"
; VirtualBox: "VBoxVBoxVBox"
; KVM:      "KVMKVMKVM   "
; Hyper-V:  "Microsoft Hv"
; Intel:    "GenuineIntel"
```

**Bypass:** Configure the hypervisor to report a non-virtualized CPUID vendor string.

#### Registry-Based Detection

Keys checked by malware:
- HKLM\SOFTWARE\VMware Inc.\VMware Tools
- HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
- HKLM\HARDWARE\DESCRIPTION\System\BIOS (check for "VBOX", "VMWARE" in SystemBiosVersion)

**Bypass:** Uninstall guest additions; configure the hypervisor to hide VM-specific registry entries.

#### Process and Driver Enumeration

VMware artifacts: vmtoolsd.exe, vmwaretray.exe; drivers vmmouse.sys, vmhgfs.sys. VirtualBox artifacts: VBoxService.exe, VBoxTray.exe; driver VBoxGuest.sys.

**Bypass:** Rename or disable VM tools services. Use REMnux (Linux-based analysis VM) which minimizes obvious VM indicators.

---

### Packer Analysis and Unpacking

#### Identifying Packed Binaries

Indicators: few imports (< 5 non-standard functions), high section entropy (> 7.0), entry point in a non-standard section, decompiler shows a tight loop with VirtualAlloc/WriteProcessMemory/CreateThread.

Entropy analysis:
```python
import pefile
pe = pefile.PE("sample.exe")
for section in pe.sections:
    name = section.Name.decode().rstrip("\x00")
    ent = section.get_entropy()
    print(f"{name}: {ent:.2f} {'[packed]' if ent > 7.0 else ''}")
```

UPX detection: section names UPX0/UPX1, or UPX signature bytes. Unpacking: `upx -d sample.exe`. If headers are modified (common in malware), use the manual method.

#### ESP Trick for OEP Finding

1. Run to entry point (F9 in x64dbg)
2. Note RSP value; right-click RSP -> Hardware Breakpoint -> On Access
3. Press F9; packer begins unpacking (PUSHAD saves registers, RSP changes significantly)
4. After POPAD restores registers, RSP returns to original value and the hardware BP fires
5. The next instruction (usually JMP or CALL) leads to the Original Entry Point (OEP)

#### IAT Reconstruction with Scylla (x64dbg Plugin)

After reaching OEP with the unpacked code in memory:
1. Plugins -> Scylla
2. Enter OEP address; click IAT Autosearch
3. Click Get Imports; Scylla resolves all IAT entries
4. Click Dump to save the unpacked PE
5. Click Fix Dump to patch the saved PE with a correct IAT

---

### Symbolic Execution for Deobfuscation

#### angr

```python
import angr

proj = angr.Project("obfuscated_binary", auto_load_libs=False)
simgr = proj.factory.simulation_manager()
simgr.explore(find=0x401500, avoid=0x401600)

if simgr.found:
    state = simgr.found[0]
    print("Input:", state.posix.dumps(0))
```

#### Qiling (Full System Emulation)

Emulates entire OS userspace in Python. Useful for shellcode analysis and automated unpacking without a full VM.

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["shellcode.bin"], "x8664_linux", verbose=QL_VERBOSE.DEBUG)
ql.hook_address(lambda ql: print("Reached target"), 0x401000)
ql.run()
```
---

## Section 6: Decompilers & Code Recovery

### Ghidra Decompiler â€” Advanced Techniques

#### Struct Recovery Workflow

1. Identify recurring pointer offsets in decompiler output: *(param_1 + 0x10), *(param_1 + 0x18), etc.
2. In Data Type Manager: right-click category -> New -> Structure. Add fields with correct offsets and types.
3. Right-click the parameter in the decompiler -> Retype Variable -> select pointer to the new struct.
4. Ghidra propagates type information, replacing numeric offsets with named field accesses throughout the function.

#### C++ Class Recovery (RTTI)

Run RecoverClassesFromRTTI from Script Manager (Analysis -> Auto Analyze also triggers it). The script:
- Parses MSVC or GCC RTTI type_info structures in .rdata
- Names vtable functions with the class name prefix
- Creates namespaces for each class
- Identifies base classes from the inheritance hierarchy in RTTI

#### Custom Calling Conventions

Define custom calling conventions under Edit -> Options -> Compiler Specification. This is necessary for malware that uses non-standard argument-passing registers (e.g., malware-specific internal calling conventions).

---

### .NET Decompilation

#### dnSpy

The primary tool for .NET malware. Decompiles, edits, and debugs .NET assemblies.

**Decompiling:** Open the EXE or DLL directly. dnSpy produces C# or VB.NET with near-source quality because .NET metadata preserves type names, method signatures, and field names.

**Live debugging:** Set breakpoints in the decompiled C# code by clicking in the margin. Run the process under dnSpy (Debug -> Start). Execution pauses at breakpoints and the Locals window shows current variable values. Far simpler than native debugging for .NET malware.

**Patching:** Right-click method -> Edit Method -> modify C# -> Compile -> File -> Save Module. Common patches: remove license checks, disable anti-debug, alter configuration values.

**IL inspection:** Right-click method -> Edit IL Instructions to view raw CIL opcodes.

#### ILSpy

Open-source .NET decompiler using Roslyn. Best for .NET 5+ and .NET Core code.

```bash
ilspycmd assembly.dll -o output_dir/           # decompile to directory
ilspycmd -p assembly.dll -o project/           # decompile to .csproj project
```

#### ildasm (Raw IL)

```bash
ildasm.exe assembly.dll /out:assembly.il       # raw MSIL text output
```

Raw IL is useful when high-level decompilers fail on obfuscated code: calli instructions, ldtoken, and dynamic delegate construction are sometimes clearer at the IL level.

#### de4dot (.NET Deobfuscation)

```bash
de4dot sample.exe                  # auto-detect protector and deobfuscate
de4dot sample.exe --strenc         # force string decryption attempt
```

Supports: ConfuserEx, Dotfuscator, SmartAssembly, Babel, DNGuard, Eazfuscator, and 20+ others. Run before loading into dnSpy or ILSpy.

---

### Java and Android Decompilation

#### jadx

Best Java/Android decompiler for malware analysis.

```bash
jadx -d output_dir/ target.apk     # decompile APK
jadx -d output_dir/ target.jar     # decompile JAR
jadx-gui target.apk                # GUI with navigation
```

Features: ProGuard name mapping (File -> Load Proguard mapping), cross-reference navigation, full-text search, resource decoding (AndroidManifest.xml, XML layouts).

#### CFR (Command-Line Java Decompiler)

```bash
java -jar cfr.jar target.jar --outputdir ./output
java -jar cfr.jar target.jar --caseinsensitivefs true  # for obfuscated single-char names
```

---

### Android APK Reverse Engineering

#### Full Workflow

```bash
# Decode resources and manifest
apktool d target.apk -o decoded/
cat decoded/AndroidManifest.xml          # permissions, exported activities, intent filters

# Decompile to Java
jadx -d java_output/ target.apk

# Search for suspicious API usage
grep -r "Runtime.exec\|ProcessBuilder" java_output/
grep -r "TelephonyManager\|getDeviceId\|getLine1Number" java_output/
grep -r "SmsManager\|sendTextMessage" java_output/
grep -r "DexClassLoader\|PathClassLoader" java_output/    # dynamic code loading
grep -r "http://\|https://" java_output/ | grep -v schemas.android
```

#### Smali Patching

apktool produces smali (human-readable Dalvik bytecode). Use for patching when Java decompilation fails or when recompilation to Java is not needed.

Patch workflow: edit .smali files -> `apktool b decoded/ -o patched.apk` -> sign with `apksigner sign --ks keystore.jks patched.apk`

#### ProGuard/R8 Obfuscation

R8 (the current Android build tool) renames classes, methods, and fields to single-letter names and removes debug information. If a mapping.txt is available: load in jadx via File -> Load Proguard mapping file. Without mapping.txt: rely on API call patterns and behavioral analysis to identify class purposes.

---

### Go Binary Reverse Engineering

Go binaries are statically linked. Release builds strip debug symbols but retain pclntab (PC-line table), which contains function names and source file/line information.

```bash
redress binary              # parse pclntab and recover function names
go tool objdump -s 'main\.' binary   # disassemble main package functions (debug builds)
```

GoReSym (Mandiant tool) recovers both function names from pclntab and type information from the Go moduledata structure. Available as a standalone tool and as a Ghidra plugin. Run GoReSym first when analyzing any Go binary.

---

### Rust Binary Reverse Engineering

```bash
eu-readelf --debug-dump=info binary | head -200   # check for DWARF info
strings -n 12 binary | grep "::"                   # Rust mangled names contain ::
nm binary | rustfilt                                # demangle Rust symbols
```

Rust monomorphization creates one copy of each generic function per type parameter. Look for groups of identically structured functions with names differing only in the type suffix. Ghidra handles Rust binaries well once symbols are recovered.

---

### Python Bytecode (.pyc)

```bash
uncompyle6 sample.pyc > sample.py           # Python 2
decompile3 sample.pyc > sample.py           # Python 3.0-3.11
# pycdc for newer Python versions (C++-based, more reliable)

# Inspect raw bytecode without decompiling
python3 -c "
import dis, marshal
with open('sample.pyc', 'rb') as f:
    f.read(16)  # skip version-specific header
    code = marshal.loads(f.read())
dis.dis(code)
"
```

PyInstaller-packaged executables: run pyinstxtractor.py against the .exe to extract .pyc files, then decompile them. The main entry script is typically named after the original .py file or as entry_point.pyc.
---

## Section 7: Firmware & Embedded System RE

### binwalk

binwalk is the standard tool for firmware analysis. It identifies embedded file systems, compressed archives, kernel images, and other structures within firmware blobs.

#### Core Usage

```bash
# Signature scan only (identify, no extract)
binwalk firmware.bin

# Extract all recognized structures
binwalk -e -M -r firmware.bin
# -e: extract  -M: recursive (matryoshka)  -r: remove failed extractions

# Entropy analysis
binwalk -E firmware.bin
# Flat near 0: blank/zero-filled
# Consistent ~0.9: compressed data
# Consistent ~1.0: encrypted data
# Mixed regions: typical firmware with code + filesystem + compressed sections

# Manual carve after identifying offset
dd if=firmware.bin bs=1 skip=74565 of=region.bin count=524288
```

#### Entropy Analysis Interpretation

Uniform high entropy throughout a firmware image usually means the image is encrypted at rest and decrypted by a small bootstrap. Look for a small low-entropy region at the start that contains the decryption routine. The ESP8266, some Qualcomm platforms, and various IoT devices use this pattern.

---

### Filesystem Extraction

| Filesystem | Common Use | Extraction Tool |
|-----------|-----------|-----------------|
| SquashFS | Linux routers, NAS devices | unsquashfs filesystem.squashfs |
| CramFS | Older embedded Linux | cramfsck -x output/ cramfs.img |
| JFFS2 | MTD-based flash (Linux) | jefferson jffs2.img -d output/ |
| UBIFS | NAND flash, newer embedded | ubireader_extract_files ubi.img |
| ROMFS | Simple read-only RTOS filesystem | romfsck -x romfs.img |
| ext2/3/4 | Embedded Linux storage | mount -o loop,ro image.ext2 /mnt/ |

---

### Firmwalker (Automated Filesystem Analysis)

```bash
git clone https://github.com/craigz28/firmwalker
./firmwalker.sh /path/to/extracted/filesystem/ firmwalker_output.txt
```

Firmwalker searches for:
- Password files: /etc/passwd, /etc/shadow, config files with password patterns
- Private keys: *.pem, *.key, id_rsa, id_dsa
- SSL/TLS certificates: *.crt, *.cer, *.pem
- Web server scripts: CGI, PHP, Lua
- Hardcoded credentials in configuration files
- SSH authorized_keys files
- Hardcoded IP addresses and URLs

Manual searches:
```bash
grep -r "password" filesystem/etc/ 2>/dev/null
grep -ri "admin\|secret\|token" filesystem/ --include="*.conf" --include="*.cfg"
find filesystem/ -name "shadow" -o -name "passwd" 2>/dev/null
find filesystem/ -name "*.pem" -o -name "*.key" -o -name "*.p12" 2>/dev/null
```

---

### QEMU Firmware Emulation

#### User-Mode Emulation

```bash
qemu-mips ./binary_mips                            # MIPS big-endian
qemu-mipsel ./binary_mipsel                        # MIPS little-endian
qemu-arm ./binary_arm                              # ARM
qemu-aarch64 ./binary_arm64                        # AArch64

# Dynamic binary with chroot for shared libraries
sudo chroot ./extracted_rootfs/ /usr/bin/qemu-mips-static ./usr/sbin/httpd
```

#### System-Mode Emulation

```bash
qemu-system-mips   -M malta   -kernel vmlinuz-malta-mips   -initrd initrd.img   -hda rootfs.ext2   -append "root=/dev/sda console=ttyS0"   -nographic   -netdev user,id=net0,hostfwd=tcp::8080-:80   -device e1000,netdev=net0
```

#### QEMU + GDB for Debugging

```bash
# Start QEMU with GDB stub on port 1234
qemu-mips -g 1234 ./binary_mips

# Connect GDB
gdb-multiarch ./binary_mips
(gdb) target remote localhost:1234
(gdb) continue
```

---

### FirmAE (Automated Router Emulation)

FirmAE automates router firmware emulation including NVRAM setup, network interface configuration, and web server discovery:

```bash
sudo bash ./FirmAE/run.sh -r brand_model.bin    # emulate firmware
sudo bash ./FirmAE/run.sh -a brand_model.bin    # try all emulation strategies
```

---

### RTOS Identification

| RTOS | Identification |
|------|---------------|
| VxWorks | Strings: "Wind River", "WRS_KERNEL_TEXT_START"; symbol: vxWorksVersion |
| ThreadX | Strings: "ThreadX"; symbol: _tx_version_id |
| eCos | Strings: "eCos"; signature: ECOSENTRY; symbol: cyg_start |
| FreeRTOS | Symbols: vTaskSwitchContext, xTaskCreate; string: "FreeRTOS" |
| uC/OS-II | String: "uC/OS"; symbol: OSTaskCreate |
| Zephyr | Symbol: z_main_thread; Zephyr version string in image |

VxWorks-specific: a symbol table is often embedded directly in the firmware image (4-byte type, 4-byte address, 4-byte name pointer per entry). The WDB debug agent may be running on UDP/17185.

---

### Web Interface Analysis in Extracted Firmware

```bash
# Find web server binary
find extracted/ -name "httpd" -o -name "uhttpd" -o -name "mini_httpd"   -o -name "lighttpd" -o -name "nginx" 2>/dev/null

# Find CGI scripts
find extracted/ -name "*.cgi" -path "*/cgi-bin/*" 2>/dev/null

# Find Lua scripts (common in OpenWrt)
find extracted/ -name "*.lua" 2>/dev/null

# Search for command injection patterns
grep -r "system(" extracted/ --include="*.c" --include="*.cgi" 2>/dev/null
strings extracted/usr/sbin/httpd | grep -E "system|popen|exec"
```

**httpd binary analysis in Ghidra:**
1. Load with correct architecture (MIPS/ARM); let Ghidra auto-analyze
2. Find main() and the HTTP request dispatcher
3. Locate CGI parameter parsing: search for xrefs to getenv("QUERY_STRING"), fgets, recv
4. Trace user-controlled data to system(), popen(), sprintf() calls
5. Check for length validation before buffer operations

---

### Hardware Debug Interfaces

**JTAG:** Provides CPU-level debug access (hardware breakpoints, memory reads, halt/resume). Identification: JTAGULATOR for finding pins; connection via OpenOCD + FT2232H adapter. Command: `openocd -f interface/ftdi/generic.cfg -f target/imx6.cfg`. With JTAG you can: read flash without chip removal, set hardware breakpoints in ROM, examine full CPU state.

**UART/Serial Console:** Most embedded Linux devices expose a serial console at 3.3V or 5V TTL levels. Identify pins with a multimeter or logic analyzer. Common baud rates: 115200, 57600, 9600. Connect with: `minicom -D /dev/ttyUSB0 -b 115200`. Boot console output reveals kernel version, mount points, and may allow unauthenticated access during U-Boot countdown.

**SPI Flash Dumping:** Attach a clip (e.g., Pomona 5250) to the SPI flash chip and use flashrom: `flashrom -p ft2232_spi:type=2232H -r firmware_dump.bin`. Enables complete firmware extraction without board disassembly. Essential when other extraction methods are unavailable.
---

## Section 8: Protocol & Network Reverse Engineering

### Binary Protocol Analysis Methodology

Unknown binary protocols appear in malware C2 communications, proprietary IoT device management, and network appliance APIs. A systematic approach yields faster results than random exploration.

#### Differential Analysis

1. Send input A with a known value in one field; capture traffic
2. Send input B with a different value in only that field; capture traffic
3. Compare the two captures byte-by-byte
4. Bytes that changed correspond to the field you modified; unchanged bytes are fixed headers

Iterate across all variable fields to map the complete packet structure.

#### Structural Pattern Recognition

**Magic bytes:** First 2-4 bytes are typically constant (0xDEAD, 0x1337, vendor-specific). Identify by looking for bytes that never vary across all captured packets.

**Length fields:** Look for big-endian or little-endian uint16/uint32 values numerically equal to the remaining packet length. Vary payload size and watch which field tracks the change.

**TLV (Type-Length-Value):** Pattern: [type: N bytes][length: N bytes][value: length bytes]. Common in X.509 ASN.1, Bluetooth HCI, and many proprietary protocols. Recognition: the Length field always matches the size of the following Value region.

**Sequence numbers:** Fields that increment by 1 per message or per request/response pair. Useful for identifying retransmission logic in C2 protocols.

**Checksums:** Typically the last 2-4 bytes. Changes when any preceding byte changes. Test by flipping one payload bit and observing which trailing bytes change.

---

### Wireshark Custom Lua Dissector

```lua
-- Load with: Edit -> Preferences -> Protocols, or place in ~/.config/wireshark/plugins/
local myproto = Proto("myproto", "My Custom Protocol")

local f_magic   = ProtoField.uint16("myproto.magic",  "Magic",    base.HEX)
local f_type    = ProtoField.uint8( "myproto.type",   "Msg Type", base.DEC,
                    {[0]="Hello",[1]="Data",[2]="Ack",[3]="Bye"})
local f_seq     = ProtoField.uint32("myproto.seq",    "Seq No",   base.DEC)
local f_len     = ProtoField.uint16("myproto.len",    "Length",   base.DEC)
local f_payload = ProtoField.bytes( "myproto.payload","Payload")

myproto.fields = {f_magic, f_type, f_seq, f_len, f_payload}

function myproto.dissector(buffer, pinfo, tree)
    if buffer:len() < 9 then return end
    pinfo.cols.protocol = "MYPROTO"
    local sub = tree:add(myproto, buffer(), "My Protocol")
    sub:add(f_magic, buffer(0,2))
    sub:add(f_type,  buffer(2,1))
    sub:add(f_seq,   buffer(3,4))
    local plen = buffer(7,2):uint()
    sub:add(f_len,   buffer(7,2))
    if plen > 0 and buffer:len() >= 9 + plen then
        sub:add(f_payload, buffer(9, plen))
    end
    local types = {[0]="Hello",[1]="Data",[2]="Ack",[3]="Bye"}
    pinfo.cols.info = string.format("Type=%s Seq=%d Len=%d",
        types[buffer(2,1):uint()] or "Unk", buffer(3,4):uint(), plen)
end

DissectorTable.get("udp.port"):add(9999, myproto)
```

---

### Scapy for Protocol Crafting and Fuzzing

```python
from scapy.all import *
import random, struct

# Craft and send a custom protocol packet
pkt = IP(dst="192.168.1.1") / UDP(dport=9999) / Raw(
    load=struct.pack(">HBIH", 0xDEAD, 1, 42, 4) + b"test"
)
send(pkt)

# Mutation fuzzing loop
for i in range(1000):
    payload = bytes([random.randint(0,255) for _ in range(random.randint(1,500))])
    header = struct.pack(">HBIH", 0xDEAD, 1, i, len(payload))
    pkt = IP(dst="192.168.1.1") / UDP(dport=9999) / Raw(load=header+payload)
    send(pkt, verbose=0)

# Capture responses
pkts = sniff(filter="udp port 9999", count=10, timeout=5)
for p in pkts:
    if Raw in p:
        print("Response:", p[Raw].load.hex())
```

---

### TLS Interception for Protocol Analysis

When a binary protocol runs over TLS, decrypt at the TLS layer for analysis.

**mitmproxy (transparent proxy):**
```bash
mitmproxy --mode transparent --showhost
# Install mitmproxy CA certificate into system trust store or application trust store
mitmdump -w output.pcap "~dst host 192.168.1.1"
```

**Frida for SSL interception (when certificate pinning is present):**
Use the frida-ssl-pinning-bypass script to hook the certificate verification functions in the target application. This allows mitmproxy to intercept traffic from applications that do not respect the system certificate store.

**Burp Suite:** For REST/JSON or SOAP/XML over HTTPS, configure the target application to use Burp as a proxy. Import the Burp CA certificate. Use the Repeater and Intruder modules for manual testing and automated fuzzing.

---

### 010 Editor Binary Templates

010 Editor's binary template language parses and colorizes binary files based on a declared format. Community templates cover 200+ formats.

```c
// Template for a simple TLV-based protocol
typedef struct {
    uint8  type;
    uint16 length;
    byte   value[length];
} TLV_Record;

local int pos = 0;
while (pos < FileSize()) {
    TLV_Record rec;
    pos += sizeof(TLV_Record) - sizeof(rec.value) + rec.length;
}
```

---

### Kaitai Struct (Declarative Format Description)

Kaitai Struct is a declarative language for binary format descriptions. Write a .ksy file once; compile to Python, Java, C++, Go, Ruby, or JavaScript.

```yaml
meta:
  id: custom_proto
  endian: be
seq:
  - id: magic
    type: u2
    valid: 0xDEAD
  - id: msg_type
    type: u1
    enum: msg_types
  - id: seq_no
    type: u4
  - id: payload_len
    type: u2
  - id: payload
    size: payload_len
enums:
  msg_types:
    0: hello
    1: data
    2: ack
```

Online IDE: https://ide.kaitai.io/ for interactive parsing in the browser.

---

### Protocol State Machine Reconstruction

Reversing a complete client-server protocol requires reconstructing the state machine:

1. **Find all send/recv call sites:** In Ghidra, search xrefs to recv@PLT, send@PLT, WSARecv, WSASend, HttpSendRequest, InternetReadFile.
2. **Identify state variables:** Variables read before network calls and modified after responses determine which state the application is in.
3. **Map transitions:** For each state value, determine: what is sent, what response is expected, what state comes next, what error state handles failures.
4. **Reconstruct the diagram:** States as nodes, message types as labeled edges.

This state machine becomes the specification for a custom Wireshark dissector and a boofuzz fuzzing session.

---

### Network Protocol Fuzzing with boofuzz

```python
from boofuzz import *

session = Session(
    target=Target(connection=TCPSocketConnection("192.168.1.1", 9999)),
    crash_threshold_request=3,
    crash_threshold_element=3
)

s_initialize("Hello")
s_static(b"\xDE\xAD")       # magic bytes: not fuzzed
s_byte(0, name="msgtype")     # fuzzed: byte field
s_dword(1, name="seqno")      # fuzzed: 32-bit sequence number
s_size("payload", length=2, name="length")
s_block_start("payload")
s_string("AAAA", name="data") # fuzzed: variable-length string
s_block_end("payload")

session.connect(s_get("Hello"))
session.fuzz()
```

boofuzz monitors the target for crashes, logs all test cases, and records which case caused each crash. Use with a crash monitor (procmon or network-based) for automated result collection.
---

## Section 9: Vulnerability Research via Reverse Engineering

### Framing: Defensive Vulnerability Research

This section covers techniques used by security analysts to find vulnerabilities in software for defensive purposes: identifying weaknesses before they are exploited in production, understanding existing exploits to build better detections, and triaging crash reports from fuzzers or incident reports. All analysis should be performed on software you are authorized to test.

### Static Vulnerability Pattern Recognition

#### Buffer Overflows

**Source code search:**
```bash
grep -rn "strcpy\|strcat\|sprintf\|vsprintf\|gets\|scanf"   --include="*.c" --include="*.cpp" src/
```

**Binary analysis in Ghidra:**
1. Search -> Symbol Table -> filter for unsafe function names
2. Right-click -> References -> Show References to unsafe_func@PLT
3. At each call site: is the destination a fixed-size stack buffer? Is the source length validated?
4. Trace the source argument back to user-controlled input (network recv, file read, argv)

**Indicators of stack buffer overflow:**
- strcpy(fixed_buf, user_input) without strlen check
- sprintf(buf, "%s%s", a, b) where buf is a fixed stack allocation
- read(fd, stack_buf, LARGE_CONSTANT) where LARGE_CONSTANT exceeds the buffer

#### Integer Overflow Leading to Heap Underallocation

```c
// Classic pattern
size_t count = user_count;
size_t size  = count * sizeof(element_t);  // wraps if count > SIZE_MAX/sizeof(element_t)
void  *buf   = malloc(size);               // allocates tiny buffer
memcpy(buf, user_data, count * sizeof(element_t));  // writes far beyond allocation
```

**Ghidra detection:** Look for multiplication of two values where one is user-controlled, and the result is used as a malloc argument without overflow checking. Also look for int (signed 32-bit) cast to size_t (unsigned 64-bit) used for allocation: a negative signed value wraps to a huge unsigned value.

#### Use-After-Free

Pattern: allocate -> use -> free -> use again. Manual taint analysis in Ghidra:
1. Find all malloc/calloc/new call sites (xref search)
2. Trace the returned pointer through the function
3. Find the free/delete call
4. Check if the same pointer is used after the free call

For automated detection: CodeQL has built-in use-after-free queries for C/C++. Valgrind memcheck detects UAF at runtime. AddressSanitizer reports use-after-free with a shadow byte legend showing the freed region.

#### Format String Vulnerabilities

Vulnerable pattern: `printf(user_input)` where user_input is not a literal format string. Safe pattern: `printf("%s", user_input)`.

**Binary detection:** Find all printf/fprintf/sprintf/syslog call sites. For each: is the first argument a fixed string from .rodata, or a register loaded from user-controlled data? If the latter, it is a potential vulnerability.

---

### Code Coverage for Fuzzing

#### AFL++ Source Instrumentation

```bash
CC=afl-clang-fast CXX=afl-clang-fast++ AFL_USE_ASAN=1 ./configure && make
afl-fuzz -i corpus/ -o findings/ -- ./target_fuzz @@
```

The @@ token is replaced with the current input file path. Use -m none if the target has a large memory footprint. Review coverage statistics in the AFL++ dashboard to identify unexplored code paths.

#### Binary-Only Fuzzing (QEMU Mode)

```bash
afl-fuzz -Q -i corpus/ -o findings/ -- ./binary @@
```

2-5x slower than source instrumentation but works on closed-source binaries. Use AFL++ Unicorn mode for library functions or shellcode.

#### libFuzzer

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    ParseInput(data, size);
    return 0;
}
```

```bash
clang -fsanitize=fuzzer,address -g fuzz_target.cpp lib.a -o fuzz_target
./fuzz_target -max_len=65536 corpus/
```

libFuzzer is built into LLVM. Combine with AddressSanitizer (-fsanitize=address) for automatic crash detection and memory safety checks.

---

### Patch Diffing with BinDiff

BinDiff identifies changed functions between two binary versions. Essential for understanding what a security patch fixed without access to source code.

**Workflow:**
1. Obtain pre-patch and post-patch versions of the binary
2. Open both in IDA Pro and export as .i64 databases
3. In IDA Pro: BinDiff -> Diff Database -> select the second .i64
4. Review results:
   - Green: identical functions (unchanged)
   - Yellow: matched but modified functions (review these)
   - Red: unmatched functions (added or removed)
5. For each yellow function: use the function diff view to see exactly what changed

**Indicators of a security fix in the diff:**
- Added bounds check: `if (len >= sizeof(buf)) return ERROR;`
- Safe function substitution: strcpy replaced with strncpy or strlcpy
- Added null pointer check before dereference
- Allocation size changed from fixed to dynamic
- Added integer overflow check before multiplication used as size

---

### Variant Analysis

Once you identify a vulnerability pattern, search for the same pattern elsewhere.

**CodeQL (source-available software):**
```ql
import cpp
from FunctionCall call, Variable dest
where call.getTarget().getName() = "strcpy"
  and dest = call.getArgument(0).(AddressOfExpr).getOperand()
  and dest.getType().(ArrayType).getArraySize() < 512
select call, dest, "Potential stack overflow via strcpy to fixed-size buffer"
```

**Ghidra script for binary pattern search:**
```python
# Find functions containing both malloc and memcpy (potential size confusion)
malloc_addr = getSymbolAddress("malloc")
memcpy_addr = getSymbolAddress("memcpy")

for func in currentProgram.getFunctionManager().getFunctions(True):
    refs = set(r.getToAddress() for r in getReferencesFrom(func.getBody())
               if r.getReferenceType().isCall())
    if malloc_addr in refs and memcpy_addr in refs:
        print("Candidate:", func.getName(), hex(func.getEntryPoint().getOffset()))
```

---

### Manual Taint Analysis

Taint analysis tracks user-controlled data from input sources to dangerous sinks.

**Sources:**
- Network: recv, read, recvfrom, WSARecv, HttpQueryInfo
- File: fread, fgets, ReadFile
- Process: argv[], getenv(), shared memory
- IPC: named pipe reads, message queue receives

**Sinks:**
- memcpy(dest, src, size): tainted size -> overflow
- malloc(size): tainted size -> integer overflow
- system(cmd), popen(cmd): tainted cmd -> command injection
- printf(fmt): tainted fmt -> format string
- strcpy(dest, src): tainted src -> stack/heap overflow
- function pointer call: tainted pointer -> control flow hijack

**Procedure:** Starting from a source function call, trace the data variable through the decompiler. Note each transformation (arithmetic, string operations, comparisons). At each sink, assess whether user control persists and whether validation was sufficient.

---

### Crash Triage

#### AddressSanitizer

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x401234 in vulnerable_func input_parser.c:42
    #1 0x400f00 in LLVMFuzzerTestOneInput harness.c:10
```

Error types: heap-buffer-overflow, stack-buffer-overflow, heap-use-after-free, double-free. The shadow byte legend shows the memory state at the fault address.

#### Valgrind

```bash
valgrind --leak-check=full --track-origins=yes --error-exitcode=99 ./binary testinput
```

Reports: Invalid read/write of size N, Use of uninitialized value, Invalid free, Double free.

#### GDB Crash Assessment

After a segfault, check register values and crash address:
- RIP contains 0x4141414141414141: attacker controlled the instruction pointer (critical exploitability)
- RSP or RBP contain 0x41414141: stack overflow, attacker controls stack (high exploitability)
- Crash at NULL (0x0) or unmapped address: null pointer dereference (lower exploitability, depends on mappings)
- Crash inside free() with corrupted metadata: heap corruption, exploitability depends on allocator
---

## Section 10: Malware-Focused RE Workflow

### End-to-End Malware Analysis Workflow

This section describes a complete structured workflow for malware analysis: from initial sample receipt through technical deep-dive to final documented report. The phases build on each other and can be adapted based on available time and analysis depth required.

---

### Phase 1: Initial Triage (15 minutes)

Goal: identify what you have, check existing intelligence, decide analysis depth.

```bash
file malware.bin                            # format identification
sha256sum malware.bin && md5sum malware.bin  # compute hashes
```

VirusTotal lookup: `vt file report SHA256_HASH` (CLI) or paste hash at virustotal.com. Interpretation: 0-2 detections may be a novel sample or false positive; 3-10 suggests likely malware; >10 is confirmed malicious with probable family attribution.

```bash
die malware.exe          # Detect-It-Easy: packer, compiler, linker identification
pestudio malware.exe     # Imports, strings, entropy, VirusTotal integration (Windows GUI)
```

---

### Phase 2: Static Import Analysis

The import table reveals intended capabilities without executing the sample.

```python
import pefile

pe = pefile.PE("malware.exe")

suspicious = {
    "injection":   ["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
                    "NtCreateThreadEx","RtlCreateUserThread","QueueUserAPC",
                    "NtAllocateVirtualMemory","SetThreadContext"],
    "process":     ["OpenProcess","TerminateProcess","SuspendThread",
                    "CreateToolhelp32Snapshot","Process32First","Process32Next"],
    "persistence": ["RegSetValueEx","RegCreateKeyEx","CreateService",
                    "StartService","SHFileOperation"],
    "network":     ["WSAStartup","socket","connect","send","recv",
                    "WinHttpOpen","WinHttpConnect","InternetOpen","InternetConnect",
                    "URLDownloadToFile","HttpSendRequest"],
    "crypto":      ["CryptEncrypt","CryptDecrypt","CryptGenRandom",
                    "BCryptEncrypt","BCryptGenRandom"],
    "anti_debug":  ["IsDebuggerPresent","CheckRemoteDebuggerPresent",
                    "GetTickCount","QueryPerformanceCounter",
                    "NtQueryInformationProcess"],
    "evasion":     ["VirtualProtect","NtUnmapViewOfSection","MoveFileEx",
                    "DeleteFile","SetFileAttributes"]
}

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("utf-8","replace").lower()
    for imp in entry.imports:
        if imp.name:
            fn = imp.name.decode("utf-8","replace")
            for cat, fns in suspicious.items():
                if fn in fns:
                    print(f"[{cat.upper()}] {dll}!{fn}")
```

---

### Phase 3: Behavioral Sandbox Analysis

Run in an isolated sandbox before investing time in static deep-dive. Behavioral output guides where to focus.

| Sandbox | Strengths |
|---------|-----------|
| ANY.RUN | Interactive; real-time process tree; free tier available |
| CAPE Sandbox | Self-hosted; automated unpacking; YARA/config extraction |
| Hybrid Analysis | CrowdStrike backend; strong family attribution; free |
| Joe Sandbox | Most comprehensive report; Windows + Linux + Android |

**Collect from the report:**
- Process tree (spawned child processes indicate injection or dropper behavior)
- File modifications (dropped files, overwritten executables)
- Registry modifications (persistence keys, configuration storage)
- Network indicators (IPs, domains, URLs, protocols, DNS queries)
- Mutexes (anti-reinfection mechanism; unique per malware family)
- Loaded modules (unexpected DLLs suggest process injection)

---

### Phase 4: Unpacking

Detect packing indicators:
- Fewer than 5 non-standard imports (packed binary calls almost nothing before unpacking)
- Entry point section entropy > 7.0
- Decompiler at entry point shows tight loop with VirtualAlloc / WriteProcessMemory / CreateThread

**ESP trick for generic unpacking:** See Section 5 for detailed steps. Result: OEP found, process memory contains unpacked code, use Scylla to dump and fix IAT.

---

### Phase 5: FLOSS String Recovery

```bash
floss --no-static-strings malware.exe       # only decoded/stack strings
floss -o floss_output.json malware.exe      # JSON output for programmatic use
```

Look for:
- C2 domain names and IP addresses
- URL paths: /gate.php, /submit.php, /bot, /update, /check
- Registry key paths for persistence
- File paths (dropped file locations)
- Mutex names (unique per malware family; great YARA string candidates)
- User-agent strings
- Error message format strings (reveal internal function names even in stripped binaries)

---

### Phase 6: C2 Protocol Identification

**Extract hardcoded infrastructure:**
```bash
strings malware.exe | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
strings malware.exe | grep -E "[a-z0-9-]{3,50}\.(com|net|org|ru|cn|io|cc|biz)"
```

**DGA detection:** High-entropy domain strings, no recognizable English words, lengths of 10-20 characters, DNS logs show long sequences of NXDOMAIN responses. In disassembly: look for a date-seeded PRNG feeding a character selection loop.

**HTTP C2 patterns:**
- POST to /gate.php, /submit, /tasks, /upload (data exfiltration or check-in)
- GET to /config, /commands, /update (command retrieval)
- User-agent: hardcoded non-browser string or dynamically built from system info
- Data format: Base64 in POST body, JSON, RC4-encrypted blob

**Beacon interval:** Search for Sleep() in the main loop. Typical values: 30000-300000 ms (30 seconds to 5 minutes) for active C2; 86400000 ms (24 hours) for dormant implants.

---

### Phase 7: Persistence Analysis

**Registry Run keys (search xrefs to RegSetValueEx in Ghidra):**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon (Userinit, Shell)
```

**Scheduled tasks:**
- ITaskService COM object: CLSID {0f87369f-a4e5-4cfc-bd3e-73e6154572dd}
- Shell: CreateProcess with schtasks.exe /Create arguments
- Search for strings "schtasks" or "/SC DAILY" in decoded strings

**Service installation pattern:** OpenSCManager -> CreateService (with SERVICE_AUTO_START) -> StartService. The binary path argument to CreateService is the persistence location.

**DLL hijacking:** Binary running from a writable directory that loads a DLL by name. Search for LoadLibrary calls with non-absolute paths.

---

### Phase 8: Capa Capability Mapping

```bash
capa malware.exe                            # analyze capabilities
capa malware.exe -j > capa_output.json      # JSON output
```

Example output sections:
```
CAPABILITY                        | NAMESPACE
----------------------------------|----------------------------------------
inject dll via CreateRemoteThread | host-interaction/process/inject
persist via run key               | persistence/registry/run-key
communicate via HTTP              | communication/http/client
encrypt data using RC4            | data-manipulation/encryption/rc4
```

Capa maps capabilities to MITRE ATT&CK techniques and MBC (Malware Behavior Catalog). Use the JSON output to pre-populate the ATT&CK table in your final report.

---

### Phase 9: YARA Rule Generation

```yara
rule Malware_FamilyX_v2_Loader {
    meta:
        description   = "Detects FamilyX v2 loader by C2 check-in byte sequence"
        author        = "Analyst Name"
        date          = "2025-01"
        sha256        = "abc123def456..."
        report        = "MAR-2025-001"
        mitre_attack  = "T1071.001, T1547.001"

    strings:
        // Unique byte pattern from C2 beacon initialization routine
        $beacon_init  = { 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? }

        // Hardcoded C2 URL suffix
        $c2_path      = "/gate.php?id=" ascii

        // Anti-reinfection mutex
        $mutex        = "Global\{4A8B2C91-3D7F}" ascii wide

        // XOR decryption key preceding encrypted config blob
        $xor_key      = { DE AD BE EF 13 37 }

    condition:
        uint16(0) == 0x5A4D      // PE file (MZ magic)
        and filesize < 5MB
        and 2 of ($beacon_init, $c2_path, $mutex, $xor_key)
}
```

Test rules before submission: run against a clean file corpus (should produce zero matches) and against all known family variants (should produce matches for all).

---

### Phase 10: Malware Analysis Report (MAR)

**Executive Summary (one page)**
- Malware family and classification: RAT, ransomware, loader, infostealer, wiper
- Threat severity: Critical / High / Medium / Low with justification
- Capability summary: two to three sentences on what the malware does
- Recommended immediate actions: network blocks, host isolation, credential reset, patch

**Technical Analysis (main body)**
1. Triage findings: hash, file size, compile timestamp (if not zeroed), packer, detection rate
2. Static analysis: suspicious imports, encoded strings, anti-analysis indicators
3. Behavioral analysis: sandbox findings summarized
4. Dynamic/debug analysis: key functions analyzed, C2 protocol reconstructed
5. Unpacking methodology (if applicable)
6. C2 protocol specification

**Indicators of Compromise Table**

| Type | Value | Context |
|------|-------|---------|
| SHA-256 | abc123... | Primary sample hash |
| IP Address | 192.0.2.1 | C2 server |
| Domain | evil.example.com | C2 domain |
| URL | http://evil.example.com/gate.php | C2 check-in endpoint |
| Registry Key | HKCU\...\Run: MalwareSvc | Persistence |
| File Path | %APPDATA%\svchost32.exe | Dropped executable |
| Mutex | Global\{4A8B2C91-3D7F} | Anti-reinfection check |
| User-Agent | Mozilla/5.0 (compatible; MSIE 9.0) | C2 HTTP header |

**MITRE ATT&CK Technique Table**

| Tactic | Technique | Name | Evidence |
|--------|-----------|------|---------|
| Execution | T1059.003 | Windows Command Shell | CreateProcess with cmd.exe |
| Persistence | T1547.001 | Registry Run Keys | RegSetValueEx to HKCU Run |
| Defense Evasion | T1027 | Obfuscated Files/Info | XOR-encrypted string table |
| Command & Control | T1071.001 | Web Protocols | HTTP POST to /gate.php |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Collected data in beacon POST |

---

*Reference compiled for defensive security analysts. All techniques described are for authorized malware analysis, incident response, and vulnerability research in controlled environments with appropriate legal authorization.*
