# Nim

Nim is a statically typed, compiled language created by Andreas Rumpf, with a first public release in 2008. It combines Python-like indentation-based syntax with native compilation, a flexible macro system, and compile-time execution. Nim compiles through C, C++, or JavaScript back ends, which lets it reach many targets. It is used for systems and application programming, command-line tools, game development, and scripting that needs native speed.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: imperative, object-oriented, functional, metaprogramming |
| Typing | Static, strong, with inference |
| First appeared | 2008 (1.0 in 2019) |
| Memory model | Automatic: ORC (reference counting plus cycle collection) by default |
| Reference compiler | [The Nim compiler](https://github.com/nim-lang/Nim), emitting C, C++, or JavaScript |
| Typical uses | Systems and application code, CLI tools, games, scripting |
| Governance/standard | Nim core team; language manual, no ISO standard |

Related: [C](/languages/c.md), [Rust](/languages/rust.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Nim set out to pair readable, indentation-based syntax with the performance of native code and a macro system able to rewrite the abstract syntax tree at compile time. The compiler emits C (or C++ or JavaScript) and then uses a system compiler to produce a binary, so Nim programs can call C libraries directly and run anywhere a C compiler does. Version 1.0 arrived in 2019. Memory management moved over time from a tracing collector to ORC, a reference-counting scheme with a cycle collector, which is the default in recent releases.

The language is defined by its manual and implemented by a single compiler. Development is community-driven around the core team.

## Paradigm and type system

Nim is statically typed with type inference and supports imperative, object-oriented, and functional styles. It offers value and reference types, generics, and an effect system that can track exceptions. A distinctive feature is uniform function call syntax: `len(x)` and `x.len` mean the same thing. Macros and templates run at compile time and can generate code.

```nim
proc describe[T](value: T): string =
  "value: " & $value          # $ converts to string
```

Exceptions are the normal error-handling mechanism, and recent Nim can track which exceptions a routine may raise.

## Toolchain and ecosystem

- The `nim` command compiles; back ends are selected with `nim c` (C), `nim cpp` (C++), and `nim js` (JavaScript).
- [Nimble](https://github.com/nim-lang/nimble) is the package manager and build tool, reading a `.nimble` file.
- Formatting is handled by `nimpretty`; the compiler itself reports many lint-style warnings.

```bash
nimble init
nimble install jester
nim c -d:release src/app.nim
```

## Syntax tour

```nim
import std/[sequtils, strformat]

type
  Shape = object
    case kind: range[0..1]
    of 0: radius: float
    of 1: width, height: float

proc area(s: Shape): float =
  case s.kind
  of 0: 3.14159265 * s.radius * s.radius
  of 1: s.width * s.height

let shapes = @[
  Shape(kind: 0, radius: 2.0),
  Shape(kind: 1, width: 3.0, height: 4.0),
]

let total = shapes.mapIt(it.area).foldl(a + b, 0.0)
echo &"total area: {total:.2f}"
```

## Idioms and different approaches

- Use method-call syntax (`x.len`) freely; it is the same as `len(x)`.
- Prefer `seq[T]` for growable sequences and `array[N, T]` for fixed-size ones.
- Reach for templates for simple code substitution and macros only when you need to inspect or rewrite the syntax tree.
- Use `result` as the implicit return variable; it is pre-declared in every `proc`.
- Annotate routines with `{.raises: [].}` to assert they raise no exceptions where that matters.

## Design principles

Nim's manual states goals of efficiency, expressiveness, and elegance, in that order of emphasis for a systems language. The design favors readable syntax, zero-overhead abstractions where possible, and strong compile-time metaprogramming so that features can be built in libraries rather than baked into the compiler.

## Standard library and notable libraries

The standard library covers strings and formatting (`strutils`, `strformat`), collections (`tables`, `sets`, `sequtils`), input and output, JSON (`json`), and asynchronous I/O (`asyncdispatch`). Widely used third-party packages, installed through Nimble, include [Jester](https://github.com/dom96/jester) for web services, [Karax](https://github.com/karaxnim/karax) for front-end single-page applications, and [Arraymancer](https://github.com/mratsim/Arraymancer) for numerical computing.

## Testing and packaging

The standard library's `unittest` module provides a test framework with `suite` and `test` blocks, run through Nimble's `nimble test`. Packages are described by a `.nimble` file and published to the Nimble package directory.

```nim
import std/unittest

proc add(a, b: int): int = a + b

suite "math":
  test "add sums two integers":
    check add(2, 3) == 5
```

## Performance and concurrency

Because Nim compiles to C and then to native code, its performance is close to C for comparable code, and it can link against C libraries without a binding layer. Concurrency uses the `asyncdispatch` module for asynchronous I/O with `async`/`await`, and threads are available with `--threads:on`. The ORC memory manager is designed to be deterministic and suitable for real-time and embedded use.

## Common pitfalls

- Mixing tabs and spaces, which the compiler rejects, since indentation is significant.
- Confusing templates and macros, or reaching for a macro where a `proc` or `template` would do.
- Side effects in code that runs at compile time behaving differently from run time.
- Integer overflow, which is a defect unless the `--overflowChecks` setting is in effect.
- Assuming garbage collection semantics from older Nim versions that used a tracing collector.

## Secure coding

Nim is memory-managed by default, but it exposes unsafe operations and compiles to C, so risks remain:

- Out-of-bounds access: bounds checks are on by default and can be disabled with `-d:danger`; keep them on in security-sensitive builds. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Unsafe pointers and C interop: `ptr`, `cast`, and `addr` bypass safety and can reintroduce use-after-free. This is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow: overflow checks are on in debug builds but off under `-d:danger`; validate arithmetic on untrusted input. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection: use `osproc.startProcess` with an argument list rather than `execShellCmd` on an assembled string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: avoid `-d:danger` for code that handles untrusted input (it removes bounds and overflow checks), and build with `--mm:orc` and the default checks. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The Nim manual](https://nim-lang.org/docs/manual.html) and [standard library index](https://nim-lang.org/docs/lib.html).
- [Nim by Example](https://nim-by-example.github.io/), a tutorial.
- [Nim in Action](https://www.manning.com/books/nim-in-action), a book by Dominik Picheta.

## Related pages

- [C](/languages/c.md)
- [Rust](/languages/rust.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
