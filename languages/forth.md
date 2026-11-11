# Forth

Forth is a stack-based, procedural language created by Charles H. Moore around 1970. It uses a data stack and postfix (reverse Polish) notation: words (Forth's name for procedures) take operands from the stack and leave results there. Forth is small, extensible, and close to the machine, and a programmer builds an application by defining new words in terms of existing ones. It is used in embedded systems, firmware, bootloaders, and other resource-constrained or low-level settings.

| Attribute | Value |
|---|---|
| Paradigm | Stack-based, procedural, concatenative; extensible by defining words |
| Typing | Typeless: the stack holds untyped cells |
| First appeared | 1970 |
| Memory model | Manual and direct: explicit fetch and store to addresses, no bounds checking |
| Reference implementation | No single reference; [Gforth](https://gforth.org/) is a common open-source system, many embedded and commercial Forths exist |
| Typical uses | Embedded systems, firmware, bootloaders (Open Firmware), instrument control |
| Governance/standard | [Forth 2012 standard](https://forth-standard.org/), after ANSI X3.215-1994 (ANS Forth) |

Related: [Smalltalk](/languages/smalltalk.md), [Logo](/languages/logo.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who write or maintain Forth code, and the reviewers and security engineers who assess it

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,445 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are writing or reviewing Forth code (typical uses: embedded systems, firmware, bootloaders (Open Firmware), instrument control), you need its common pitfalls and secure-coding rules before a review, or you are choosing its toolchain, tests and packages

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax tour](#syntax-tour), [Common pitfalls](#common-pitfalls), [Secure coding](#secure-coding)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Smalltalk](/languages/smalltalk.md), [Logo](/languages/logo.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Charles Moore developed Forth to control radio telescopes and other instruments, favoring a system small enough to fit tiny machines yet extensible enough to grow into a full application. The language blurs the line between program and language: the interactive interpreter and compiler are themselves Forth words, and new words extend the language. Forth was used widely in embedded control, and Open Firmware (used on SPARC and PowerPC systems) was built on it.

Standardization produced ANS Forth (ANSI X3.215-1994) and the community-maintained Forth 2012 standard. There is no single reference implementation: Gforth is a portable open-source system, and many commercial and embedded Forths target specific microcontrollers. Implementations vary in cell size, available words, and how they compile, so portable Forth sticks to the standard word set.

## Paradigm and type system

Forth is typeless and stack-oriented. The data stack holds machine-word-sized cells; a word pops its inputs and pushes its outputs. There are no declared types and no type checking: a cell can be an integer, an address, a boolean, or a character, and it is the programmer's responsibility to track what each stack item means. Programs are written as sequences of words, and new words are defined with `:` (colon) and end with `;`.

```forth
\ Stack comment shows the effect: ( before -- after )
: square ( n -- n*n ) dup * ;
: celsius>f ( c -- f ) 9 * 5 / 32 + ;
```

Control flow (`IF ... THEN`, `DO ... LOOP`, `BEGIN ... UNTIL`) is itself built from words, and metaprogramming through defining words and immediate words extends the compiler.

## Toolchain and ecosystem

- System: [Gforth](https://gforth.org/) provides an interactive interpreter and compiler; embedded Forths are often cross-compiled to target hardware.
- Interaction: development is interactive, defining and testing words at the prompt, then saving source files loaded with `include`.
- Libraries: capabilities depend on the system; portable code uses the standard word set, and systems add words for files, floating point, and hardware.

```bash
# Gforth: load a file, then interact
gforth temperature.fs
```

## Syntax tour

```forth
\ Define words; computation flows through the stack
: fib ( n -- fib ) 
  dup 2 < if exit then
  dup 1- recurse
  swap 2 - recurse + ;

\ Print the first terms
: fibs ( n -- )
  0 do i fib . loop ;

10 fibs   \ prints 0 1 1 2 3 5 8 13 21 34
```

## Idioms and different approaches

- Keep words short and factor aggressively: a word should do one clear thing and read as a phrase of smaller words.
- Document every word's stack effect with a `( before -- after )` comment, since nothing else records it.
- Minimize stack juggling (`dup`, `swap`, `rot`); if a definition needs heavy juggling, it is usually doing too much.
- Use the dictionary and defining words to build small domain vocabularies rather than large monolithic words.
- Prefer named constants and values over magic numbers left on the stack.

## Design principles

Forth's design favors extreme smallness and extensibility: a minimal core can bootstrap the rest of the language, and the programmer extends the language toward the problem rather than only writing in it. This suits tiny systems where a full toolchain will not fit, and it rewards factoring code into many small, composable words. The trade-off is that the typeless stack model offers little automatic checking, placing correctness on the programmer and on discipline.

## Standard library and notable packages

Forth standards define a core word set and optional word sets (for example floating point, file access, and the tools word set) rather than a large library. Each system provides the standard words plus its own extensions: Gforth adds words for operating-system interaction, networking, and more. There is no central package registry; reusable code is shared as source files that define words, loaded with `include` or `require`.

## Testing and packaging

Forth has no single standard test framework; the widely used convention is the Hayes test harness (`T{ ... -> ... }T`), which checks that a sequence of words leaves expected values on the stack. Code is distributed as source files of word definitions; an application is often a saved image or a cross-compiled binary for the target device.

```forth
\ Using the common test harness words
T{ 3 square -> 9 }T
T{ 100 celsius>f -> 212 }T
```

## Performance and concurrency

Forth compiles to compact threaded code or, in optimizing systems, to native code, and it runs with very little overhead, which is why it fits microcontrollers with tiny memories. Direct memory access and the absence of run-time checks keep it fast and small. Concurrency is not part of the core language; multitasking, where present, is a system-specific cooperative or preemptive scheduler, and embedded Forths often include a small multitasker. Shared state is coordinated manually.

## Common pitfalls

- Stack errors: leaving the wrong number of items on the stack, or in the wrong order, corrupts later computation with no warning.
- Stack underflow or overflow when a word consumes more or fewer items than expected.
- Uncommented stack effects making words hard to reuse or verify.
- Direct memory stores (`!`) to wrong addresses, which silently corrupt memory.
- Portability gaps: assuming a cell size or a nonstandard word that another system lacks.

## Security relevance

Forth reaches security practitioners as a low-level language found in firmware, bootloaders, and embedded devices, which are reverse-engineering and exploitation targets rather than a source of offensive tooling. This section is the threat-facing context; the defensive patterns that counter each class are in the Secure coding section that follows.

### Where it appears

- Firmware and bootloaders. Open Firmware (used on SPARC and PowerPC systems) is built on Forth, and boot and initialization code on various platforms is written in it, so firmware analysts encounter Forth when reversing a boot chain. See the [Reverse Engineering Reference](/REVERSE_ENGINEERING_REFERENCE.md) and the [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md).
- Embedded systems and instrument control. Forth fits microcontrollers with very little memory and is used for device and instrument control, where a memory bug is a direct path to a device compromise. See the [Exploit Development Reference](/EXPLOIT_DEVELOPMENT_REFERENCE.md).
- Interactive and extensible systems. Because the interpreter and compiler are themselves Forth words, a Forth prompt exposed on a device is also a control surface.

### Dominant weakness classes

Forth is memory-unsafe (it uses manual, direct memory access through explicit fetch and store with no bounds checking) and typeless, so the memory-corruption classes apply in full and nothing catches them automatically:

- Out-of-bounds read and write. The fetch and store words (`@`, `!`, `C@`, `C!`) access arbitrary addresses, so a wrong address or an unchecked index reads or corrupts memory. These map to [CWE-125](https://cwe.mitre.org/data/definitions/125.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Buffer overflow. Copying external data into a fixed buffer without a length check overflows it, which relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html).
- Integer and cell overflow. Arithmetic wraps silently at the cell size, so unchecked values can overflow, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Input validation. Data read from devices or input streams is unchecked until the program validates it, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).

### Why it matters

Reading Forth lets an analyst follow firmware or bootloader logic and spot memory stores to attacker-influenced addresses, the kind of flaw that turns a parsing bug into device code execution. There is no widely used static analyzer for Forth, so review relies on small, well-factored words with documented stack effects and careful inspection of every memory access, as the Secure coding section details.

## Secure coding

Forth offers no memory safety and no type checking, so it carries the memory-corruption risks of low-level code and depends entirely on programmer discipline:

- Out-of-bounds memory access: the fetch and store words (`@`, `!`, `C@`, `C!`) read and write arbitrary addresses with no bounds checking, so a wrong address or an unchecked index corrupts memory. Validate indices and buffer sizes before access. This maps to [CWE-125](https://cwe.mitre.org/data/definitions/125.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Buffer overflow: copying external data into a fixed buffer without a length check overflows it, which relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html).
- Integer and cell overflow: arithmetic wraps silently at the cell size; check ranges on untrusted values, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Input validation: data read from devices or input streams is unchecked until the program checks it, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).

Dedicated security tooling is scarce; there is no widely used static analyzer for Forth. Rely on small, well-factored words with documented stack effects, the test harness, and careful review of every memory access. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Starting Forth by Leo Brodie](https://www.forth.com/starting-forth/), a free introductory text.
- [Gforth manual](https://gforth.org/manual/), the reference for a common open-source system.
- [Forth Standard](https://forth-standard.org/), the current community standard and word reference.

## Related pages

- [Smalltalk](/languages/smalltalk.md)
- [Logo](/languages/logo.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
