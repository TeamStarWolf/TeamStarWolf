# Gleam

Gleam is a statically typed functional language for the Erlang virtual machine (the BEAM), with a second compile target to JavaScript. Created by Louis Pilfold and reaching version 1.0 in 2024, it pairs a type system with full inference and a small, explicit syntax with the BEAM's model of lightweight processes and fault tolerance. It is used for web back ends, services on the BEAM, and, through the JavaScript target, shared front-end and back-end code.

| Attribute | Value |
|---|---|
| Paradigm | Functional |
| Typing | Static, strong, fully inferred (no null, no exceptions) |
| First appeared | 2019 (version 1.0 in 2024) |
| Memory model | Automatic: per-process garbage collection on the BEAM (or the host runtime on the JavaScript target) |
| Reference implementation | [The Gleam compiler](https://github.com/gleam-lang/gleam), targeting Erlang and JavaScript |
| Typical uses | Web back ends, BEAM services, shared front-end and back-end code |
| Governance | Created and led by Louis Pilfold; development on GitHub |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Elixir](/languages/elixir.md), [languages index](/languages/README.md).

## Overview and history

Gleam set out to bring static types to the BEAM ecosystem with a syntax smaller and more explicit than that of its neighbors. The compiler emits Erlang source (and can emit JavaScript), so Gleam code runs on the same runtime as Erlang and Elixir and can call their libraries through typed bindings. The language reached version 1.0 in 2024, which committed it to a stable language and standard library within the 1.x line.

Gleam deliberately keeps the language small: there is no null, there are no exceptions in the usual sense, and there is one way to do most things. Errors are values, absence is modeled with the `Option` type, and failure is modeled with the `Result` type, so the type system forces the caller to handle both.

## Paradigm and type system

Gleam is purely functional in style: data is immutable, and functions transform values. Its type system has full inference, so most code needs no annotations, yet every expression is checked. There is no null and no implicit coercion. Custom types are algebraic data types, and pattern matching with `case` must be exhaustive, so the compiler rejects a match that omits a variant.

```gleam
pub type Shape {
  Circle(radius: Float)
  Rect(width: Float, height: Float)
}

pub fn area(shape: Shape) -> Float {
  case shape {
    Circle(r) -> 3.14159 *. r *. r
    Rect(w, h) -> w *. h
  }
}
```

Numeric operators are distinct for integers and floats (`+` versus `+.`), which keeps arithmetic unambiguous. Functions are first class, and the pipe operator `|>` threads a value through a sequence of calls.

## Toolchain and ecosystem

- Compiler and tool: the single `gleam` binary creates projects, builds, tests, formats, and manages dependencies.
- Build and dependencies: a project is described in `gleam.toml`; dependencies come from [Hex](https://hex.pm/), shared with Erlang and Elixir.
- Targets: `gleam build` compiles to Erlang by default, or to JavaScript with the `--target javascript` option.
- Formatting: `gleam format` applies the one canonical layout, so projects do not configure style.

```bash
gleam new my_app
cd my_app
gleam deps download
gleam test
gleam run
```

## Syntax tour

```gleam
import gleam/io
import gleam/list
import gleam/int

pub type Tree {
  Leaf
  Node(left: Tree, value: Int, right: Tree)
}

pub fn insert(x: Int, tree: Tree) -> Tree {
  case tree {
    Leaf -> Node(Leaf, x, Leaf)
    Node(l, v, r) ->
      case int.compare(x, v) {
        order.Lt -> Node(insert(x, l), v, r)
        order.Gt -> Node(l, v, insert(x, r))
        order.Eq -> tree
      }
  }
}

pub fn to_list(tree: Tree) -> List(Int) {
  case tree {
    Leaf -> []
    Node(l, v, r) -> list.flatten([to_list(l), [v], to_list(r)])
  }
}

pub fn main() {
  [5, 3, 8, 1, 4]
  |> list.fold(Leaf, fn(acc, x) { insert(x, acc) })
  |> to_list
  |> io.debug
}
```

## Idioms and different approaches

- Return `Result(value, error)` and `Option(value)` and handle both cases with `case`; there is no null and no exception to fall back on, so failure stays visible in the types.
- Thread data through transformations with the pipe operator `|>` and the functions in the `gleam/list` and `gleam/result` modules.
- Let the exhaustiveness check guide you: add a variant to a custom type and the compiler points to every `case` that must be updated.
- Use the `use` expression to flatten nested callbacks, for example sequencing `Result`-returning steps without deep indentation.

## Design principles

Gleam values a small language with one obvious way to do things, static types with full inference so safety does not cost verbosity, and clear error messages aimed at newcomers. Removing null and exceptions pushes error handling into the type system, where the compiler can check it. A single canonical formatter removes style debate. Running on the BEAM means the language inherits a mature concurrency and fault-tolerance model rather than inventing its own.

## Standard library and notable packages

The [standard library](https://hexdocs.pm/gleam_stdlib/) provides modules such as `gleam/list`, `gleam/dict`, `gleam/string`, `gleam/result`, `gleam/option`, and `gleam/int`, all with typed, total functions where possible. Packages on Hex include [gleam_otp](https://hexdocs.pm/gleam_otp/) for typed OTP actors and supervisors, [gleam_erlang](https://hexdocs.pm/gleam_erlang/) for runtime bindings, [wisp](https://hexdocs.pm/wisp/) and [mist](https://hexdocs.pm/mist/) for web serving, and [lustre](https://hexdocs.pm/lustre/) for building front ends on the JavaScript target.

## Testing and packaging

[gleeunit](https://hexdocs.pm/gleeunit/) is the common test library; `gleam test` discovers and runs the tests.

```gleam
import gleeunit/should

pub fn addition_test() {
  { 2 + 3 }
  |> should.equal(5)
}
```

A package declares its name, version, and dependencies in `gleam.toml`; `gleam publish` builds the package and uploads it to Hex along with generated documentation.

## Performance and concurrency

On the BEAM target, Gleam inherits the Erlang runtime's scheduler, lightweight processes, per-process garbage collection, and distribution, so concurrent and fault-tolerant systems use the same model as Erlang and Elixir, with types added on top through `gleam_otp`. Single-threaded arithmetic throughput matches the BEAM's, which is modest compared with native-compiled languages but strong for concurrent, I/O-bound workloads. On the JavaScript target, Gleam runs wherever JavaScript does (Node.js or the browser) and uses that runtime's event loop and garbage collector rather than BEAM processes, so the concurrency model differs by target.

## Common pitfalls

- Target differences: code that depends on BEAM-only or JavaScript-only libraries will not run on the other target; keep target-specific code isolated behind a shared interface.
- Integer and float operators are separate (`+` versus `+.`, `<` versus `<.`), so mixing them is a type error that newcomers hit often.
- Interop with Erlang and Elixir through external functions crosses out of Gleam's checked world; the `external` boundary must be given correct types by hand, and a wrong signature there defeats the guarantees.
- There is no exception-based control flow, so forgetting to propagate a `Result` leaves an error unhandled in the types until you address it; use `result.try` or the `use` expression.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Interop boundary: `external` functions that call Erlang, Elixir, or JavaScript are annotated with types the compiler trusts without checking the other side; an incorrect annotation lets unchecked or wrongly typed data into otherwise safe code, so review these declarations and validate values crossing the boundary. This relates to input validation, [CWE-20](https://cwe.mitre.org/data/definitions/20.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Atom and term risks on the BEAM: when Gleam code calls Erlang functions such as `binary_to_term` or atom-creating functions through interop, the BEAM risks apply, namely unsafe deserialization ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)) and atom-table exhaustion from untrusted input, a form of resource exhaustion ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)); use safe variants and validate against known sets. See [Erlang](/languages/erlang.md) for detail.
- Input validation at the boundary: parse external data into precise custom types and reject malformed values; the type system then enforces the parsed shape, but it does not validate content for you.
- Injection on the web: build database queries with parameterized APIs rather than string concatenation, and escape output; see [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Dependency supply chain: pin versions in `gleam.toml`, commit the lock file (`manifest.toml`), and review dependencies, which are shared with the wider Hex ecosystem; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: `gleam check` type-checks a project without building it and is the primary static-analysis gate, since the type system rejects null errors, non-exhaustive matches, and many interface mistakes at compile time; run it in continuous integration together with `gleam format --check`.

## Learning resources

- [The Gleam Language Tour](https://tour.gleam.run/), an interactive introduction that runs in the browser.
- [Gleam documentation](https://gleam.run/documentation/), the official guides and reference.
- [Gleam standard library docs](https://hexdocs.pm/gleam_stdlib/), the API reference.

## Related pages

- [Elixir](/languages/elixir.md)
- [Erlang](/languages/erlang.md)
- [OCaml](/languages/ocaml.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
