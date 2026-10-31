# ARM Assembly

ARM assembly is the human-readable form of the machine instructions for processors built on the ARM architecture, a reduced-instruction-set (RISC) design from Arm Holdings that dates to 1985. Each statement maps closely to one machine instruction, giving direct control over registers and memory. ARM cores power most mobile phones, tablets, embedded devices, and a growing share of laptops and servers, so ARM assembly appears in boot and firmware code, device drivers, operating-system kernels, compiler output, reverse engineering, and exploit development.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, low-level, instruction-oriented |
| Typing | Untyped: values are bytes in registers and memory |
| First appeared | ARM architecture in 1985; AArch64 (ARMv8-A) in 2011 |
| Memory model | Manual: load/store architecture, weakly ordered memory |
| Reference implementation/assembler | [GNU as](https://sourceware.org/binutils/), LLVM, and Arm's own tools (armasm, Keil) |
| Typical uses | Mobile, embedded, firmware, drivers, kernels, reverse engineering, exploit development |
| Governance/standard | Arm defines the architecture in its reference manuals |

Related: [C](/languages/c.md), [x86-64 Assembly](/languages/assembly-x86.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

The ARM architecture began at Acorn Computers in the 1980s and is now licensed by Arm Holdings to many chip makers. Two generations of the instruction set are current: the 32-bit A32 and T32 (Thumb) encodings used by older and smaller cores, and the 64-bit AArch64 (the A64 instruction set) introduced with ARMv8-A in 2011, which most modern phones, Apple silicon, and ARM servers use. The architecture is defined by the Arm Architecture Reference Manual. This page centers on AArch64, noting A32 where it differs.

As with other assembly languages, ARM assembly today is used for targeted pieces: startup and firmware code, context switches, cryptographic routines, and reading disassembled code during reverse engineering, rather than whole applications.

## Paradigm and type system

ARM assembly is untyped: values are bytes in registers or memory, and the instruction determines their meaning. ARM is a load/store architecture, meaning arithmetic operates only on registers, and separate `ldr`/`str` instructions move data between registers and memory. Control flow is explicit through branch instructions, which can test condition flags set by a prior comparison.

AArch64 provides 31 general-purpose 64-bit registers, `x0` through `x30`, each with a 32-bit view (`w0` through `w30`). Register `x30` is the link register (the return address), `sp` is the stack pointer, and `pc` is the program counter (not generally writable as a normal register in AArch64). The `xzr`/`wzr` zero register reads as zero. There are 32 SIMD and floating-point registers (`v0` through `v31`). The 32-bit A32 instruction set instead exposes 16 registers, `r0` through `r15`, where `r13` is the stack pointer, `r14` the link register, and `r15` the program counter.

## Toolchain and ecosystem

- Assemblers: [GNU as](https://sourceware.org/binutils/) (through `gcc`) and the LLVM assembler use GNU syntax; Arm's `armasm` and the Keil toolchain are common in embedded work.
- Linkers and tools: `ld` links; `objdump` and `readelf` inspect binaries.
- Debuggers and disassemblers: [GDB](https://www.sourceware.org/gdb/), [Ghidra](https://ghidra-sre.org/), and [radare2](https://rada.re/).

```bash
aarch64-linux-gnu-as hello.s -o hello.o
aarch64-linux-gnu-ld hello.o -o hello
./hello
```

## Syntax tour

AArch64 (GNU assembler syntax), writing to standard output on Linux through the `write` and `exit` system calls:

```asm
.data
msg:    .ascii "hello, world\n"
len =   . - msg

.text
.global _start

_start:
    mov     x0, 1           // file descriptor 1 (stdout)
    ldr     x1, =msg        // pointer to the buffer
    mov     x2, len         // number of bytes
    mov     x8, 64          // syscall number for write
    svc     0               // supervisor call into the kernel

    mov     x0, 0           // status 0
    mov     x8, 93          // syscall number for exit
    svc     0
```

Instructions are fixed-width (4 bytes in A64) and generally take a destination register first, then source operands.

## Idioms and different approaches

- Use the zero register (`xzr`/`wzr`) to write a constant zero or discard a result.
- Combine a compare (`cmp`) with a conditional branch (`b.eq`, `b.lt`) rather than a flags-setting arithmetic instruction where clarity matters.
- Use `ldp`/`stp` to load and store a pair of registers in one instruction, common in function prologues and epilogues.
- Save and restore the link register (`x30`) and frame pointer (`x29`) on entry when a function calls others.
- Prefer compiler output as a baseline, then hand-tune only the critical routine.

## Design principles

ARM is a RISC design: a load/store model, fixed-width instructions (in A64), and a regular register set make instructions simpler to decode and pipeline than a complex-instruction-set design. The 32-bit Thumb encodings trade some regularity for smaller code size, which matters in embedded systems. The architecture targets a wide range from microcontrollers to servers, and Arm's manuals define the exact semantics, including the memory-ordering model.

## Calling conventions

The calling convention is a software agreement, specified for AArch64 by the [Arm Procedure Call Standard (AAPCS64)](https://github.com/ARM-software/abi-aa):

- Integer and pointer arguments go in `x0` through `x7`, then on the stack; the return value is in `x0` (and `x1` for 128-bit results).
- `x30` is the link register holding the return address; `x29` is the frame pointer.
- Registers `x19` through `x28` are callee-saved; `x0` through `x18` are caller-saved (with `x16`/`x17` reserved as intra-procedure-call scratch and `x18` sometimes platform-reserved).
- The stack pointer must be 16-byte aligned at a public interface.

Linux AArch64 system calls put the call number in `x8` and arguments in `x0` through `x5`, invoked with `svc 0`.

## Testing and packaging

ARM assembly is assembled and linked like other object code, with no package manager of its own. Routines are typically tested by linking them into a C or other-language harness that calls them through the procedure-call standard and checks results. Cross-assembling and running under an emulator such as QEMU is common when the development host is not an ARM machine.

## Performance and concurrency

Hand-written ARM assembly can use NEON SIMD or cryptographic-extension instructions a compiler might not emit, though optimizing compilers handle most code well. ARM has a weakly ordered memory model, so concurrent code must use explicit barriers (`dmb`, `dsb`, `isb`) and the load-exclusive/store-exclusive pair (`ldxr`/`stxr`) or the ARMv8.1 atomic instructions to implement locks and lock-free structures correctly. Omitting a barrier can produce data races that appear only under load.

## Common pitfalls

- Omitting memory barriers on the weakly ordered model, yielding races that pass on one core and fail on another.
- Not saving and restoring the link register before a nested call, so the function cannot return.
- Misaligning the stack pointer, which faults at a public interface that requires 16-byte alignment.
- Confusing the 32-bit (A32/Thumb) and 64-bit (A64) register sets and encodings.
- Sign- versus zero-extension when operating on `w` sub-registers, whose writes clear the upper 32 bits of the `x` register.

## Secure coding

ARM assembly offers no run-time checks, so memory and control-flow errors map directly to vulnerabilities:

- Out-of-bounds writes: validate lengths and indices before `str` operations; a stack buffer overflow can overwrite the saved link register and hijack control. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html) and relates to stack-based overflows, [CWE-121](https://cwe.mitre.org/data/definitions/121.html).
- Integer overflow in address or size arithmetic: check bounds before computing offsets. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Control-flow hijacking: indirect branches through attacker-influenced registers enable code reuse; use architecture mitigations such as pointer authentication (PAC) and branch target identification (BTI) on cores that support them, along with non-executable stacks.
- When assembly assembles command strings passed to the operating system, the injection risk is [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: disassemble and audit with [Ghidra](https://ghidra-sre.org/) or [radare2](https://rada.re/), run cross-built code under QEMU for testing, and keep the surrounding program's compiler mitigations enabled. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- Arm Architecture Reference Manual, the authoritative instruction reference.
- Arm's AArch64 instruction set documentation and developer guides.
- [The AArch64 procedure call standard (AAPCS64)](https://github.com/ARM-software/abi-aa), the calling-convention specification.

## Related pages

- [C](/languages/c.md)
- [x86-64 Assembly](/languages/assembly-x86.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
