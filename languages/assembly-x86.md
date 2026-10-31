# x86-64 Assembly

x86-64 assembly is the human-readable form of the machine instructions for the 64-bit extension of Intel's x86 architecture, introduced by AMD as AMD64 (also called x86-64, x64, or Intel 64) around 2003. Each assembly statement corresponds closely to one machine instruction, so the programmer controls registers, memory, and the processor directly. It is used for operating-system kernels, boot code, device drivers, compiler output, performance-critical routines, reverse engineering, and exploit development.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, low-level, instruction-oriented |
| Typing | Untyped: values are bytes in registers and memory |
| First appeared | x86 in 1978; 64-bit (AMD64) around 2003 |
| Memory model | Manual: flat virtual address space, explicit loads and stores |
| Reference implementation/assembler | [NASM](https://www.nasm.us/), [GNU as](https://sourceware.org/binutils/), and MASM |
| Typical uses | Kernels, boot code, drivers, compiler output, reverse engineering, exploit development |
| Governance/standard | Intel and AMD architecture manuals define the instruction set |

Related: [C](/languages/c.md), [ARM Assembly](/languages/assembly-arm.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

The x86 instruction set began with the Intel 8086 in 1978 and grew through the 32-bit era (IA-32). AMD defined the 64-bit extension, AMD64, which Intel adopted as Intel 64; the common name is x86-64. The architecture is defined by the vendor manuals: the Intel 64 and IA-32 Architectures Software Developer's Manuals and the equivalent AMD manuals. There is no single reference assembler; the syntax depends on the assembler, with two main conventions described below.

Assembly programming today is usually confined to small, targeted pieces of a larger program: boot and startup code, context switches, cryptographic kernels, and routines that a compiler cannot express, alongside reading disassembled code during reverse engineering.

## Paradigm and type system

Assembly has no types. Values are bytes held in registers or memory, and the meaning of a byte depends on the instruction that operates on it. The programmer tracks sizes and signedness by hand: instruction suffixes or operand-size prefixes select 8-, 16-, 32-, or 64-bit operations. Control flow is explicit, through conditional and unconditional jumps that test the flags register set by prior instructions.

x86-64 has sixteen general-purpose 64-bit registers: `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `rsp`, and `r8` through `r15`. The lower parts are addressable as 32-bit (`eax`), 16-bit (`ax`), and 8-bit (`al`) sub-registers. `rip` is the instruction pointer, `rsp` the stack pointer, and `rflags` holds condition flags. SIMD registers (`xmm`, `ymm`, `zmm`) hold vector and floating-point data.

## Toolchain and ecosystem

- Assemblers: [NASM](https://www.nasm.us/) uses Intel syntax; [GNU as](https://sourceware.org/binutils/) (invoked through `gcc`) defaults to AT&T syntax; MASM is the Microsoft assembler on Windows.
- Linkers and tools: `ld` links object files; `objdump` and `readelf` inspect binaries.
- Debuggers and disassemblers: [GDB](https://www.sourceware.org/gdb/), [radare2](https://rada.re/), and [Ghidra](https://ghidra-sre.org/) for reverse engineering.

```bash
nasm -f elf64 hello.asm -o hello.o
ld hello.o -o hello
./hello
```

## Syntax tour

Intel syntax (NASM), writing to standard output on Linux through the `write` and `exit` system calls:

```nasm
section .data
    msg db "hello, world", 10        ; the trailing 10 is a newline
    len equ $ - msg

section .text
    global _start

_start:
    mov rax, 1          ; syscall number for write
    mov rdi, 1          ; file descriptor 1 (stdout)
    mov rsi, msg        ; pointer to the buffer
    mov rdx, len        ; number of bytes
    syscall

    mov rax, 60         ; syscall number for exit
    xor rdi, rdi        ; status 0
    syscall
```

The two conventions differ in operand order: Intel writes `mov dest, src`, while AT&T writes `mov src, dest` and prefixes registers with `%` and immediates with `$`.

## Idioms and different approaches

- Zero a register with `xor rax, rax`, which is shorter and faster than `mov rax, 0`.
- Use `lea` for address arithmetic and some integer math without touching the flags.
- Preserve callee-saved registers (`rbx`, `rbp`, `r12` through `r15`) if you modify them, per the calling convention.
- Keep the stack 16-byte aligned before a `call`, as the System V and Windows conventions require.
- Prefer compiler-generated assembly as a starting point, then hand-tune only the hot section.

## Design principles

x86-64 is a complex-instruction-set architecture with a long compatibility chain: a modern processor still runs code written for its predecessors. The instruction set is dense and variable-length, with many addressing modes. The architecture favors backward compatibility and raw access over simplicity, so an assembly programmer must consult the vendor manual for exact instruction semantics and flag effects.

## Calling conventions

The calling convention is not part of the hardware; it is an agreement that lets separately compiled code interoperate. Two dominate x86-64:

- System V AMD64 ABI (Linux, macOS, most Unix): integer and pointer arguments go in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`, then the stack; the return value is in `rax`. Callee-saved registers are `rbx`, `rbp`, `rsp`, and `r12` through `r15`.
- Microsoft x64 (Windows): the first four arguments go in `rcx`, `rdx`, `r8`, `r9`, with 32 bytes of shadow space reserved on the stack by the caller; the return value is in `rax`.

Linux system calls use a separate convention: the call number in `rax` and arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`, invoked with the `syscall` instruction.

## Testing and packaging

Assembly is assembled into object files and linked into a program or library; there is no package manager for assembly itself. Routines are usually tested by linking them into a C or other-language harness that calls them through the calling convention and checks results. Disassemblers and debuggers verify that the emitted instructions match intent.

## Performance and concurrency

Hand-written assembly can exploit instructions a compiler may not emit, such as specific SIMD or cryptographic instructions, but modern optimizing compilers produce code that is hard to beat for general routines. Concurrency and memory ordering are controlled with atomic instructions (the `lock` prefix, `cmpxchg`, `xadd`) and memory-fence instructions (`mfence`, `lfence`, `sfence`), which enforce ordering on a weakly ordered memory system. Getting ordering wrong produces subtle data races.

## Common pitfalls

- Misaligned stack before a `call`, which crashes code that assumes 16-byte alignment.
- Clobbering a callee-saved register without restoring it, corrupting the caller.
- Confusing Intel and AT&T operand order when moving between assemblers.
- Sign-extension versus zero-extension when widening a value (`movsx` versus `movzx`).
- Forgetting that writing a 32-bit sub-register (`eax`) zeroes the upper 32 bits of the 64-bit register.

## Secure coding

Assembly has no safety net, so memory and control-flow errors map directly to vulnerabilities:

- Out-of-bounds writes: validate lengths and indices before loads and stores; a stack buffer overflow can overwrite a return address. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html) and relates to classic stack-based overflows, [CWE-121](https://cwe.mitre.org/data/definitions/121.html).
- Integer overflow in address or size arithmetic: check bounds before computing offsets, since there is no automatic check. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Use of untrusted data in control flow: indirect jumps and calls through attacker-influenced pointers enable control-flow hijacking; validate targets and use mitigations such as stack canaries, non-executable stacks, and control-flow-integrity instructions where available.
- When assembly builds command strings passed to the operating system, the injection risk is [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: disassemble and audit with [Ghidra](https://ghidra-sre.org/) or [radare2](https://rada.re/), and keep compiler mitigations (stack protector, ASLR-compatible position-independent code) in the surrounding program. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- Intel 64 and IA-32 Architectures Software Developer's Manuals, the authoritative instruction reference.
- [The NASM documentation](https://www.nasm.us/docs.php).
- [The System V AMD64 ABI](https://gitlab.com/x86-psABIs/x86-64-ABI), the calling-convention specification.

## Related pages

- [C](/languages/c.md)
- [ARM Assembly](/languages/assembly-arm.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
