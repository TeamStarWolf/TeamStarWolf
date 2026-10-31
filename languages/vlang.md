# V

V is a statically typed, compiled language created by Alexander Medvednikov, first released publicly in 2019. It has a small, readable syntax influenced by Go, fast compilation, and a focus on simplicity and safety. V compiles through C by default, which lets it reach many targets and call C code directly. It is used for command-line tools, systems and application programming, and as the implementation language for related projects. The language is young and still changing; confirm behavior against the version you use.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, with struct methods |
| Typing | Static, strong, with inference |
| First appeared | 2019 (pre-1.0 as of 2026) |
| Memory model | Autofree option, optional garbage collector, and manual modes |
| Reference compiler | [The V compiler](https://github.com/vlang/v), emitting C by default |
| Typical uses | CLI tools, systems and application programming |
| Governance/standard | V core team and the [vlang project](https://vlang.io/); no formal standard |

Related: [Go](/languages/go.md), [C](/languages/c.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

V was announced in 2019 with goals of a small language, fast compilation, and safety by default. Its syntax resembles Go: no semicolons, short keywords, and simple structure. V compiles to C and then uses a C compiler to produce a binary, giving direct C interoperability. Its memory story has several modes: an experimental autofree scheme, an optional garbage collector (the default in many builds), and manual management. The language is pre-1.0 and its features and defaults have shifted across releases, so claims here should be checked against the current version.

The compiler is self-hosted and the project is community-driven around the core team.

## Paradigm and type system

V is statically typed with inference and is procedural with methods attached to structs rather than classes. It has no null by default: optional and result types (`?Type` and `!Type`) represent absence and failure, handled with `or` blocks. Immutability is the default: variables and function arguments are immutable unless marked `mut`. Sum types and generics are supported.

```v
fn first_even(numbers []int) ?int {
    for n in numbers {
        if n % 2 == 0 {
            return n
        }
    }
    return none
}
```

Error handling uses result types with the `!` suffix and propagation, rather than exceptions.

## Toolchain and ecosystem

- The `v` command compiles, runs, tests, and formats (`v fmt`) code in one tool.
- A package manager, `v install`, fetches modules from the V module registry and Git.
- The default back end emits C; V can also interoperate with C by importing headers directly.

```bash
v init
v fmt -w .
v -prod .
```

## Syntax tour

```v
struct Circle {
    r f64
}

struct Rect {
    w f64
    h f64
}

type Shape = Circle | Rect

fn area(s Shape) f64 {
    return match s {
        Circle { 3.14159265 * s.r * s.r }
        Rect { s.w * s.h }
    }
}

fn main() {
    shapes := [Shape(Circle{r: 2.0}), Shape(Rect{w: 3.0, h: 4.0})]
    mut total := 0.0
    for s in shapes {
        total += area(s)
    }
    println('total area: ${total:.2}')
}
```

## Idioms and different approaches

- Keep variables immutable; add `mut` only where mutation is needed, and the compiler enforces it.
- Return optionals (`?T`) or results (`!T`) and handle them with `or { ... }` blocks.
- Use `match` over sum types for exhaustive branching.
- Run `v fmt` so formatting is uniform, as in Go's `gofmt`.
- Import C libraries directly when a native library already exists rather than reimplementing it.

## Design principles

V's stated goals are a small and simple language that a programmer can learn quickly, fast compilation, safety defaults such as immutable variables and no null, and no hidden allocations or global state in the language's core. The design draws on Go's minimalism while adding option and result types and default immutability.

## Standard library and notable libraries

The standard library covers strings and formatting, collections, JSON encoding, file and operating-system access (`os`), networking, and a built-in testing facility. V also ships modules for building graphical and web applications in its distribution. Because the language is young, the third-party ecosystem is smaller than those of established languages; confirm that a module is maintained before depending on it.

## Testing and packaging

Testing is built in: functions named `test_*` in files ending `_test.v` run with `v test`. Modules are described by a `v.mod` file and can be installed from the V module registry or a Git repository.

```v
fn add(a int, b int) int {
    return a + b
}

fn test_add() {
    assert add(2, 3) == 5
}
```

## Performance and concurrency

Compiling through C, V produces native binaries whose performance tracks the C it generates. Concurrency uses the `go` keyword to start a coroutine and channels to communicate between them, a model similar to Go's. The memory-management mode (garbage collector, autofree, or manual) affects run-time behavior, so choose and test the mode that fits the workload. As a pre-1.0 language, some performance and concurrency features are still maturing.

## Common pitfalls

- Relying on documentation or tutorials written for an older version, since the language changes.
- Assuming autofree is complete; its coverage has been partial, so test memory behavior under the mode you choose.
- Expecting a large third-party ecosystem; many needs are met by binding to C libraries.
- Forgetting to handle the `none` or error branch of an optional or result, which the compiler requires.
- Overflow and conversion behavior between integer types on untrusted input.

## Secure coding

V aims for safety defaults, but it compiles to C and exposes unsafe operations, so systems risks remain:

- Out-of-bounds access: array indexing is bounds-checked by default; code inside `unsafe { }` blocks and raw pointer use can bypass this and cause out-of-bounds writes. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Use-after-free: manual memory management and C interop can free data still referenced; confine and audit `unsafe` code. This is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow: validate arithmetic on untrusted sizes before using it for allocation or indexing. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection: use `os.execute` and process APIs with controlled arguments rather than building a shell command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: keep untrusted-input code outside `unsafe` blocks, build with `-prod` for release checking, and track the official [V documentation](https://docs.vlang.io/) for current safety guidance since the language is pre-1.0. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The V documentation](https://docs.vlang.io/), the primary language reference.
- [The vlang GitHub repository](https://github.com/vlang/v), including the standard-library source.
- [vlang.io](https://vlang.io/), the project site with examples.

## Related pages

- [Go](/languages/go.md)
- [C](/languages/c.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
