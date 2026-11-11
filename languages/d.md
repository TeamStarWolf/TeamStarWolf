# D

D is a statically typed, compiled, multi-paradigm systems language created by Walter Bright, with a first release in 2001; Andrei Alexandrescu later shaped its second major version. It was designed as a redesign of C++ that keeps native performance while adding optional garbage collection, compile-time function execution, and a cleaner module system. It is used for systems and application programming, numerical work, and command-line tools.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: imperative, object-oriented, functional, generic |
| Typing | Static, strong, with inference |
| First appeared | 2001 (D2 from around 2007) |
| Memory model | Optional garbage collection, with manual and scoped options |
| Reference compiler | [DMD](https://github.com/dlang/dmd), the reference compiler (also GDC and LDC) |
| Typical uses | Systems and application code, numerical computing, CLI tools |
| Governance/standard | D Language Foundation; language specification, no ISO standard |

Related: [C++](/languages/cpp.md), [Rust](/languages/rust.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who write or maintain D code, and the reviewers and security engineers who assess it

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,163 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are writing or reviewing D code (typical uses: systems and application code, numerical computing, CLI tools), you need its common pitfalls and secure-coding rules before a review, or you are choosing its toolchain, tests and packages

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax tour](#syntax-tour), [Common pitfalls](#common-pitfalls), [Secure coding](#secure-coding)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[C++](/languages/cpp.md), [Rust](/languages/rust.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

D began as Walter Bright's attempt to keep what worked in C++ while removing accumulated complexity. The second major version, D2, stabilized the language around features such as immutability, ranges, and compile-time function execution. D offers a garbage collector by default but lets programmers opt out with manual memory management and the `@nogc` attribute for code that must not allocate on the collected heap. It interoperates with C directly and with C++ to a large degree.

Three compilers share one front end: DMD (the reference, fast to compile), GDC (a GCC back end), and LDC (an LLVM back end used for optimized builds). The language is specified in its official spec and governed by the D Language Foundation.

## Paradigm and type system

D is statically typed with inference (`auto`), and supports imperative, object-oriented, functional, and generic styles. Templates provide generics, and compile-time function execution (CTFE) runs ordinary functions during compilation. Type qualifiers `const` and `immutable` express read-only and deeply unchangeable data, which also aids safe concurrency. Ranges, a lazy iteration protocol, underpin much of the standard library.

```d
auto describe(T)(T value) {
    import std.conv : to;
    return "value: " ~ value.to!string;
}
```

The `@safe`, `@trusted`, and `@system` attributes mark how much memory safety the compiler checks for a function.

## Toolchain and ecosystem

- Compilers: `dmd` (reference), `ldc2` (LLVM, optimized), and `gdc` (GCC).
- Build and package manager: [DUB](https://dub.pm/) builds projects and fetches dependencies from the DUB registry.
- Formatting: [dfmt](https://github.com/dlang-community/dfmt) formats code; the compiler reports many warnings.

```bash
dub init app
cd app
dub add vibe-d
dub build --build=release
```

## Syntax tour

```d
import std.algorithm : map, sum;
import std.stdio : writefln;

struct Circle { double r; double area() const { return 3.14159265 * r * r; } }
struct Rect   { double w, h; double area() const { return w * h; } }

void main() {
    auto circles = [Circle(2.0), Circle(3.0)];

    // Ranges and uniform function call syntax
    auto total = circles.map!(c => c.area).sum;
    writefln("total area: %.2f", total);

    // Compile-time function execution
    enum compileTimeValue = factorial(5);
    writefln("5! = %d", compileTimeValue);
}

ulong factorial(ulong n) pure nothrow {
    return n <= 1 ? 1 : n * factorial(n - 1);
}
```

## Idioms and different approaches

- Use uniform function call syntax to chain operations: `data.filter!(...).map!(...).array`.
- Prefer ranges and `std.algorithm` over explicit index loops.
- Mark functions `pure` and `nothrow` where they qualify, and `@safe` to opt into checked memory safety.
- Use `immutable` for data shared across threads, which D's type system treats as safe to share.
- Reach for `@nogc` and manual allocation in code that must avoid the garbage collector.

## Design principles

D aims to combine the performance and control of a systems language with the productivity of a higher-level one. Its design favors practicality: a garbage collector by default for convenience, with escape hatches for code that cannot tolerate it; strong compile-time metaprogramming; and direct interoperability with C so existing libraries remain usable.

## Standard library and notable libraries

The standard library, Phobos, provides ranges and algorithms (`std.algorithm`, `std.range`), strings and conversion (`std.string`, `std.conv`), input and output (`std.stdio`, `std.file`), and concurrency (`std.concurrency`, `std.parallelism`). A widely used third-party framework is [vibe.d](https://vibed.org/) for asynchronous web and network services, installed through DUB.

## Testing and packaging

D has built-in `unittest` blocks that the compiler collects and runs when built with `-unittest`. DUB packages are described by a `dub.json` or `dub.sdl` file and published to the DUB registry.

```d
int add(int a, int b) { return a + b; }

unittest {
    assert(add(2, 3) == 5);
}
```

## Performance and concurrency

Compiled with LDC or GDC, D produces optimized native code comparable to C++. The default garbage collector simplifies memory management, and `@nogc` plus manual allocation serve latency-sensitive paths. Concurrency favors message passing through `std.concurrency` with isolated threads, and `std.parallelism` offers parallel loops and task pools. The `immutable` and `shared` type qualifiers let the compiler reason about what may be shared between threads.

## Common pitfalls

- Assuming the garbage collector never pauses; latency-sensitive code should use `@nogc` paths.
- Mixing `@safe`, `@trusted`, and `@system` without auditing the `@trusted` boundary, where safety is asserted by hand.
- Slice aliasing surprises: array slices share underlying memory, so a write through one can affect another.
- CTFE limitations: not every function can run at compile time, and the error can be obscure.
- Lingering confusion between D1 and D2 material online; target D2.

## Security relevance

D reaches security practitioners as a systems and application language that defenders audit, close to C++ in capability with an opt-in memory-safe subset. Offensive tooling written in it is uncommon. The defensive patterns that counter each class are in the Secure coding section that follows; this section is the threat-facing context.

### Where it appears

- Systems and application code. D is used for systems and application programming, numerical work, command-line tools, and [vibe.d](https://vibed.org/) network services, and because it interoperates directly with C and much C++, it sits next to native code with the same memory model.
- The `@system` and C-interop surface. `@system` code and C bindings are where manual memory management and its bugs live, while `@safe` marks the subset the compiler checks.
- Little offensive presence. D is not a common tool-building language, so the interest is reading and auditing D code, especially at its unsafe boundaries.

### Dominant weakness classes

D is memory-unsafe by default: `@system` is the default attribute and manual and `@nogc` memory management are available, so the memory-corruption classes apply except in code explicitly marked and checked `@safe`:

- Out-of-bounds writes. Array slices are bounds-checked only in non-release builds, so unchecked access on untrusted input can write past a buffer, which is [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Use-after-free. Manual and `@nogc` memory management can free data still referenced, which is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow. Arithmetic on untrusted sizes that wraps before allocation is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection. Using `std.process` with a shell command string rather than an argument array is [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

### Why it matters

Reading D lets an analyst find where code leaves the `@safe` subset and whether the `@trusted` boundary is sound, which is where memory-safety defects concentrate. [D-Scanner](https://github.com/dlang-community/D-Scanner) provides static analysis, and keeping bounds checks on for untrusted paths rather than building with `-release` preserves the run-time checks, as the Secure coding section details.

## Secure coding

D offers a checked memory-safety subset, but the `@system` default and C interop keep risks present:

- Out-of-bounds writes: array slices are bounds-checked in non-release builds; keep checks on and prefer `@safe` code for untrusted input. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Use-after-free: manual and `@nogc` memory management can free data still referenced; confine such code and audit `@trusted` functions. This is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow: validate arithmetic on untrusted sizes before allocation. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection: use `std.process.spawnProcess` with an argument array rather than a shell command string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: write security-sensitive code under `@safe`, avoid `-release` when it would disable bounds checks on untrusted paths, and use [D-Scanner](https://github.com/dlang-community/D-Scanner) for static analysis. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The D language specification](https://dlang.org/spec/spec.html) and [library reference](https://dlang.org/phobos/index.html).
- [Programming in D](http://ddili.org/ders/d.en/index.html), a free book by Ali Çehreli.
- [The D Blog](https://dlang.org/blog/), for design notes and tutorials.

## Related pages

- [C++](/languages/cpp.md)
- [Rust](/languages/rust.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
