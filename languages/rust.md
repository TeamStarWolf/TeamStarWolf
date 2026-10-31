# Rust

Rust is a statically typed, compiled, multi-paradigm language that began as a Mozilla project by Graydon Hoare and reached version 1.0 in 2015. It aims for memory safety and data-race freedom without a garbage collector, enforced at compile time by an ownership and borrowing system. It is used for systems software, command-line tools, WebAssembly, network services, embedded firmware, and security-sensitive code where both safety and performance matter.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: imperative, functional, generic |
| Typing | Static, strong, with inference |
| First appeared | 2010 (1.0 in 2015) |
| Memory model | Compile-time ownership and borrowing; no garbage collector |
| Reference compiler | [rustc](https://github.com/rust-lang/rust) with the LLVM back end |
| Typical uses | Systems software, CLI tools, WebAssembly, services, embedded |
| Governance/standard | [Rust RFC process](https://github.com/rust-lang/rfcs) under the Rust Foundation |

Related: [C](/languages/c.md), [C++](/languages/cpp.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Rust set out to let programmers write low-level code without the memory-safety hazards that come with manual memory management. The compiler's borrow checker verifies that references do not outlive the data they point to and that mutable and shared access do not overlap. After 1.0 in 2015, the language settled into a six-week release cadence with editions (2015, 2018, 2021, 2024) that group opt-in changes without breaking older code.

The reference compiler is `rustc`, which lowers to LLVM intermediate representation. Governance runs through an open RFC process and teams under the Rust Foundation. There is no ISO standard; the language is defined by the compiler and the [Rust Reference](https://doc.rust-lang.org/reference/).

## Paradigm and type system

Rust is statically typed with local type inference, algebraic data types (`enum`), pattern matching, and traits for shared behavior. Ownership is the central idea: each value has one owner, and borrowing lends temporary references that the compiler checks for validity. The `Option<T>` and `Result<T, E>` types make absence and failure explicit rather than using null or exceptions.

```rust
fn first_even(numbers: &[i32]) -> Option<i32> {
    numbers.iter().copied().find(|n| n % 2 == 0)
}
```

Traits provide generics and polymorphism; `impl Trait` and trait objects (`dyn Trait`) cover static and dynamic dispatch.

## Toolchain and ecosystem

- Toolchain manager: [rustup](https://rustup.rs/) installs `rustc`, `cargo`, and components.
- Build tool and package manager: [Cargo](https://doc.rust-lang.org/cargo/) builds projects and resolves dependencies from crates.io.
- Formatting and linting: `rustfmt` formats, and [Clippy](https://github.com/rust-lang/rust-clippy) lints for common mistakes and style.

```bash
cargo new app
cd app
cargo add serde
cargo build --release
```

## Syntax tour

```rust
use std::collections::HashMap;

#[derive(Debug)]
enum Shape {
    Circle { r: f64 },
    Rect { w: f64, h: f64 },
}

fn area(shape: &Shape) -> f64 {
    match shape {
        Shape::Circle { r } => std::f64::consts::PI * r * r,
        Shape::Rect { w, h } => w * h,
    }
}

fn main() {
    let shapes = vec![Shape::Circle { r: 2.0 }, Shape::Rect { w: 3.0, h: 4.0 }];
    let total: f64 = shapes.iter().map(area).sum();
    println!("total area: {total:.2}");

    let mut counts: HashMap<&str, i32> = HashMap::new();
    for word in "a b a c b a".split_whitespace() {
        *counts.entry(word).or_insert(0) += 1;
    }
    println!("{counts:?}");
}
```

## Idioms and different approaches

- Return `Result<T, E>` for recoverable errors and propagate with the `?` operator; reserve `panic!` for unrecoverable states.
- Prefer iterators and adapters (`map`, `filter`, `collect`) over index loops.
- Model invalid states out of existence with enums and the type system.
- Use `&str` for borrowed string slices and `String` for owned text; borrow rather than clone when you can.
- Isolate unavoidable low-level operations in small `unsafe` blocks and document their invariants.

## Design principles

Rust's design centers on safety without a run-time collector: ownership and borrowing move the cost of safety to compile time, so safe code has no data races and no use-after-free. The language also values zero-cost abstractions, explicit control flow, and clear error handling. The `unsafe` keyword marks the small boundary where the programmer, not the compiler, upholds the invariants.

## Standard library and notable crates

The standard library provides collections (`Vec`, `HashMap`, `BTreeMap`), `Option` and `Result`, threads and synchronization primitives, and formatting. Widely used crates include [serde](https://serde.rs/) for serialization, [tokio](https://tokio.rs/) for asynchronous runtime and networking, [clap](https://docs.rs/clap/) for command-line parsing, [reqwest](https://docs.rs/reqwest/) for HTTP, and [rayon](https://docs.rs/rayon/) for data parallelism.

## Testing and packaging

Rust has built-in testing: functions marked `#[test]` run with `cargo test`, and documentation examples are tested too. A crate is packaged by Cargo and published to crates.io with `cargo publish`.

```rust
fn add(a: i32, b: i32) -> i32 { a + b }

#[test]
fn adds_two_numbers() {
    assert_eq!(add(2, 3), 5);
}
```

## Performance and concurrency

Rust compiles to native code through LLVM and performs comparably to C and C++. Concurrency is backed by the `Send` and `Sync` marker traits, which the compiler uses to reject code that would share data unsafely across threads, giving what the project calls "fearless concurrency." The standard library offers threads, channels, `Mutex`, and `Arc`; asynchronous code uses `async`/`await` with a runtime such as tokio.

## Common pitfalls

- Fighting the borrow checker by cloning excessively instead of restructuring ownership.
- Overusing `.unwrap()` and `.expect()`, which turn recoverable errors into panics.
- Reaching for `unsafe` to silence the compiler rather than fixing the design.
- Lifetime annotations that grow complex; often a sign that an API should own its data.
- Blocking calls inside asynchronous code, which can stall the executor.

## Secure coding

Rust prevents many memory-safety bugs in safe code, but risks remain:

- `unsafe` blocks: raw pointer use can reintroduce out-of-bounds writes and use-after-free, mapping to [CWE-787](https://cwe.mitre.org/data/definitions/787.html) and [CWE-416](https://cwe.mitre.org/data/definitions/416.html). Keep `unsafe` small, audited, and documented.
- Integer overflow: arithmetic wraps in release builds unless checked; use `checked_add`, `saturating_add`, or `wrapping_add` deliberately. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection: build `std::process::Command` with separate arguments rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: audit crates and pin versions; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: run [Clippy](https://github.com/rust-lang/rust-clippy) for lints and [cargo-audit](https://github.com/rustsec/rustsec) to check dependencies against the RustSec advisory database. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The Rust Programming Language](https://doc.rust-lang.org/book/), the official book.
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/) and the [standard library docs](https://doc.rust-lang.org/std/).
- [The Rustonomicon](https://doc.rust-lang.org/nomicon/), the guide to `unsafe` Rust.

## Related pages

- [C](/languages/c.md)
- [C++](/languages/cpp.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
