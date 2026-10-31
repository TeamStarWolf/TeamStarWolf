# Mojo

Mojo is a language from Modular aimed at high-performance and AI (artificial intelligence) programming, designed to feel familiar to Python users while adding static types, an ownership model, and compilation to native code. It was first shown publicly in 2023 and is built on the MLIR compiler infrastructure. Mojo is pre-1.0 and under active development, so its syntax and features are changing; treat the specifics below as a snapshot that may differ from the current release, and consult the official documentation for exact, version-specific details.

| Attribute | Value |
|---|---|
| Paradigm | Imperative and systems programming, with value semantics and metaprogramming |
| Typing | Gradual: dynamic for Python-style code, static and strong for typed code |
| First appeared | 2023 (pre-1.0; evolving) |
| Memory model | Ownership and borrowing with value semantics; no tracing garbage collector |
| Reference implementation | The Mojo compiler by [Modular](https://www.modular.com/), built on [MLIR](https://mlir.llvm.org/) |
| Typical uses | AI and machine-learning kernels, high-performance numerical code |
| Governance | [Modular](https://www.modular.com/) (parts of the toolchain being opened over time) |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Mojo was announced by Modular in 2023, with Chris Lattner (known for LLVM, Clang, and Swift) among its creators. The stated motivation is the gap in AI software between Python, where models are written, and the C++ and specialized kernels that make them fast: Mojo aims to let one language span that range by keeping Python's approachability while adding the types, memory control, and compilation needed for hardware-level performance. It is built on MLIR, a compiler framework suited to targeting CPUs, GPUs, and accelerators.

Because the language is young and pre-1.0, it has been released in stages, with the toolchain and a subset of its code opened publicly over time and features added and revised between releases. A long-term goal is to be a superset of Python, but at the time of writing it is not a drop-in replacement, and compatibility is partial. Any detailed claim here should be checked against the current release.

## Paradigm and type system

Mojo offers a gradual type system: code can be written in a dynamic, Python-like style, or with static types for performance and checking. Two function-defining keywords have historically expressed this split, with one favoring Python-compatible dynamic behavior and another requiring typed, checked declarations; the exact keywords and their rules have changed across releases, so verify them against current docs.

The memory model is based on ownership and value semantics rather than a tracing garbage collector: values have an owner, can be borrowed immutably or mutably, and are destroyed deterministically when their owner goes out of scope, an approach in the same family as Rust's. Argument conventions express whether a function borrows, mutates, or takes ownership of a value. Static structural features and compile-time parameters support writing generic, high-performance code.

```mojo
# Illustrative only; syntax is evolving and version-specific
fn add(a: Int, b: Int) -> Int:
    return a + b
```

## Toolchain and ecosystem

- Toolchain: Modular distributes the Mojo compiler and command-line tools; historically these were installed through Modular's own package tooling, which has changed as the product evolved, so follow current installation instructions.
- Python interoperability: Mojo can call into Python libraries, which lets it reuse the existing ecosystem (NumPy and others) while performance-critical parts are written in Mojo.
- Platform context: Mojo is developed alongside Modular's AI inference platform, and much of its early use is in that setting.
- Editor support: an official extension provides editor features; tooling maturity tracks the language's pre-1.0 status.

```bash
# Commands have changed across releases; consult current documentation
mojo run hello.mojo
```

## Syntax tour

```mojo
# Illustrative, pre-1.0 syntax that may not match the current release
fn fib(n: Int) -> Int:
    if n < 2:
        return n
    var a = 0
    var b = 1
    for _ in range(n - 1):
        var next = a + b
        a = b
        b = next
    return b

fn main():
    print(fib(10))
```

Mojo's surface deliberately echoes Python (indentation, `def`-style definitions, `print`), while typed functions, `var` declarations, and compile-time features depart from it. Because details shift between releases, runnable code should be taken from the version of the documentation that matches your toolchain.

## Idioms and different approaches

- Start from working Python-style code and add types and ownership annotations to the hot paths, rather than typing everything at once; the gradual system is meant to support this progression.
- Call into Python for libraries that do not yet exist in Mojo, and rewrite only the performance-critical kernels in typed Mojo.
- Use value semantics and explicit borrowing to control copies in numerical code, where unnecessary allocation and copying dominate cost.
- Treat the language as a moving target: pin your toolchain version, and expect to update code as the language stabilizes toward 1.0.
- Prefer the official documentation and examples over third-party blog posts, which can describe outdated syntax given how fast the language is changing.

## Design principles

Mojo's design goal is to unify the AI software stack in one language: keep Python's readability and ecosystem, and add static typing, deterministic memory management through ownership, and ahead-of-time compilation so the same language can reach hardware-level performance. Building on MLIR reflects a bet on a compiler framework that targets heterogeneous hardware (CPUs, GPUs, accelerators). The pre-1.0 status is itself a stated position: the designers are prioritizing getting the model right over stability, so change is expected.

## Standard library and notable modules

Mojo ships a standard library that is growing alongside the language, covering core types, collections, and numerical primitives, with portions developed in the open. Because the library is incomplete relative to a mature language, much practical work relies on Python interoperability to reach established libraries such as NumPy. Given the pace of change, the set of modules and their APIs should be confirmed against the current release rather than assumed from older material.

## Testing and packaging

Testing and packaging conventions are still forming. Modular has provided a testing facility within the toolchain, and packaging and distribution mechanisms have evolved along with the installation tooling. Rather than state specifics that may be outdated, treat these areas as version-dependent and follow the current official documentation for how to structure tests and distribute code.

## Performance and concurrency

Performance is Mojo's reason for existing, so the evaluation model is built around it: typed code is compiled ahead of time through MLIR to native code, and the language exposes low-level control (value semantics, ownership, compile-time parameters, and SIMD and vectorization facilities) intended to let numerical kernels approach what hand-written C++ achieves. Dynamic, Python-like code trades that performance for flexibility.

- Compilation and static types remove much of the interpreter overhead that limits CPython on numeric loops.
- The ownership model avoids a tracing garbage collector, giving deterministic, pause-free memory behavior that suits latency-sensitive inference.
- Targeting accelerators (GPUs and other hardware) is a central goal through the MLIR foundation; the specifics of how parallel and device code are written are evolving and should be checked against the current release.

Because the language is young, performance characteristics and the concurrency model are still settling, so measured results depend on the toolchain version.

## Common pitfalls

- Assuming Python compatibility: Mojo is not yet a full Python superset, so not all Python code runs unchanged; check what the current release supports.
- Following outdated examples: syntax, keywords, and tooling have changed across releases, so code from an earlier version may not compile.
- Expecting a mature standard library and package ecosystem; both are still growing, and gaps are filled through Python interoperability.
- Overlooking the ownership rules when porting from garbage-collected languages; values are moved and borrowed, not implicitly shared.
- Treating pre-1.0 behavior as stable; pin the toolchain and expect churn.

## Secure coding

Mojo is pre-1.0, so its security guidance is necessarily provisional; the following apply the general principles while the language and its documentation settle:

- Memory safety is a work in progress: the ownership and borrowing model is intended to prevent use-after-free and related errors ([CWE-416](https://cwe.mitre.org/data/definitions/416.html)) in safe code, but Mojo also provides low-level and unsafe facilities for systems work, and any `unsafe`-style pointer code can reintroduce memory-corruption weaknesses such as out-of-bounds access ([CWE-787](https://cwe.mitre.org/data/definitions/787.html)). Keep unsafe code minimal and reviewed.
- Python interoperation inherits Python's risks: calling into Python means untrusted input flows into Python code, so the usual injection and deserialization concerns ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)) apply at that boundary; validate data crossing it.
- Hardcoded secrets ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): as in any language, keep keys and credentials out of source and in a secrets manager or environment supplied at run time.
- Supply chain: the toolchain and any libraries are young and evolving; obtain them from Modular's official channels, pin versions, and review dependencies, including Python packages reached through interoperability. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Because dedicated Mojo security analyzers are not yet established, rely on the compiler's checks, careful review of unsafe and interop code, and the language-agnostic practices in the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md); re-verify this guidance against the current release.

## Learning resources

- [Mojo documentation](https://docs.modular.com/mojo/), the official and authoritative reference for the current release.
- [Modular](https://www.modular.com/), for the platform and language announcements.
- [MLIR](https://mlir.llvm.org/), background on the compiler framework Mojo is built on.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
