# OCaml

OCaml is a statically typed, multi-paradigm member of the ML family, first released in 1996 and developed at Inria in France. It combines functional, imperative, and object-oriented styles, infers types without annotations, and compiles to fast native code. It is used for compilers, program verification, static analysis, financial systems, and developer tooling.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: functional, imperative, object-oriented, modular |
| Typing | Static, strong, inferred (ML-style with modules and functors) |
| First appeared | 1996 (OCaml 5 added shared-memory parallelism in 2022) |
| Memory model | Automatic: generational garbage collection |
| Reference implementation | [The OCaml compiler](https://github.com/ocaml/ocaml) from Inria |
| Typical uses | Compilers, verification, static analysis, finance, tooling |
| Governance | Inria with community maintainers; no formal ISO standard |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Standard ML](/languages/standard-ml.md), [languages index](/languages/README.md).

## Overview and history

OCaml descends from the ML lineage through Caml and Caml Light, with the object-oriented layer added in the mid-1990s. It has been developed at Inria for its lifetime and is maintained today by Inria together with a broad community. The language has no formal standard document; the compiler and its manual define the language.

OCaml 5.0, released in 2022, introduced shared-memory parallelism through domains and a general effect-handler mechanism, which ended the long period in which an OCaml process ran on a single core. The reference compiler produces both native code and a portable bytecode, and the `utop` read-eval-print loop supports interactive use.

## Paradigm and type system

OCaml is strict (call-by-value) and lets you mix styles: pure functions and immutable values by default, with `ref` cells, mutable record fields, arrays, and loops available when imperative code is clearer. The type system is ML-style Hindley-Milner inference with several additions: a module system with functors (functions from modules to modules), polymorphic variants, generalized algebraic data types, and an object layer.

```ocaml
type shape =
  | Circle of float
  | Rect of float * float

let area = function
  | Circle r      -> Float.pi *. r *. r
  | Rect (w, h)   -> w *. h
```

Type inference means most code carries no annotations, yet the compiler still checks every expression. The module system is one of the language's distinguishing features: signatures describe interfaces, and functors let you parameterize whole modules over other modules.

## Toolchain and ecosystem

- Compiler: `ocamlopt` produces native code, `ocamlc` produces bytecode, and `utop` is the interactive top level.
- Build system: [Dune](https://dune.build/) is the common build tool, driven by small `dune` files.
- Package manager: [opam](https://opam.ocaml.org/) manages compilers, switches, and dependencies from the [opam repository](https://opam.ocaml.org/packages/).
- Editor support: the [OCaml language server](https://github.com/ocaml/ocaml-lsp) and [Merlin](https://github.com/ocaml/merlin) provide completion and type information.
- Formatting: [ocamlformat](https://github.com/ocaml-ppx/ocamlformat) applies a consistent layout.

```bash
opam switch create my-project 5.2.0
eval $(opam env)
dune build
dune exec ./main.exe
```

## Syntax tour

```ocaml
(* Records and variants *)
type point = { x : float; y : float }

type tree =
  | Leaf
  | Node of tree * int * tree

(* Recursive function with pattern matching *)
let rec insert x = function
  | Leaf -> Node (Leaf, x, Leaf)
  | Node (l, v, r) as t ->
      if x < v then Node (insert x l, v, r)
      else if x > v then Node (l, v, insert x r)
      else t

(* Immutable list processing with the pipe operator *)
let sum_of_squares xs =
  xs |> List.map (fun n -> n * n) |> List.fold_left ( + ) 0

(* Options express absence without null *)
let safe_div a b = if b = 0 then None else Some (a / b)

let () =
  Printf.printf "%d\n" (sum_of_squares [1; 2; 3])  (* 14 *)
```

## Idioms and different approaches

- Represent absence and failure with `option` and `result` rather than exceptions where the caller should handle the case; reserve exceptions for truly exceptional conditions.
- Use the pipe operator `|>` to write left-to-right data pipelines instead of deeply nested calls.
- Reach for the module system to enforce invariants: a type kept abstract in a signature can only be built through the functions you expose.
- Prefer immutable data by default, and introduce `ref`, mutable fields, or arrays locally when a measured performance need or a clearer algorithm justifies them.

## Design principles

OCaml values a type system that catches errors at compile time without forcing annotations, predictable strict evaluation, and a module system that scales from small programs to large codebases. The language stays pragmatic: it does not insist on purity, and it provides imperative constructs so that performance-sensitive or inherently stateful code can be written directly. The compiler is engineered for fast compilation and fast output, which supports its use in interactive tooling and long-running services.

## Standard library and notable packages

The standard library is intentionally small; many projects use an extended base such as [Base](https://opam.ocaml.org/packages/base/) or [Core](https://opam.ocaml.org/packages/core/) from Jane Street. Common packages include [Lwt](https://github.com/ocsigen/lwt) and [Eio](https://github.com/ocaml-multicore/eio) for concurrency and I/O, Dream for web services, [Yojson](https://github.com/ocaml-community/yojson) for JSON, and the [Menhir](http://gallium.inria.fr/~fpottier/menhir/) parser generator.

## Testing and packaging

[Alcotest](https://github.com/mirage/alcotest) is a common unit-test framework, and [QCheck](https://github.com/c-cube/qcheck) generates random inputs for property testing. Dune runs tests declared in `dune` files.

```ocaml
let test_add () =
  Alcotest.(check int) "2 + 3" 5 (2 + 3)

let () =
  Alcotest.run "math" [ ("add", [ Alcotest.test_case "simple" `Quick test_add ]) ]
```

A package describes itself in an `opam` file plus `dune-project` metadata; `dune build @install` prepares it, and it publishes to the opam repository through a pull request or `opam publish`.

## Performance and concurrency

Native-compiled OCaml performs close to other systems languages for many workloads, helped by an efficient garbage collector and, in some builds, the Flambda optimizer. Before OCaml 5, concurrency within a process was cooperative: libraries such as Lwt and Async interleaved I/O-bound tasks on a single core. OCaml 5 added domains for true shared-memory parallelism and effect handlers that libraries such as Eio use to express concurrency without monadic plumbing. A process still has a small number of domains, typically matched to cores, each with its own minor heap.

## Common pitfalls

- Polymorphic structural equality (`=`) and comparison can raise or behave unexpectedly on functions, cyclic values, or abstract types; use type-specific comparisons from `Base` or `Stdlib` where it matters.
- Floating-point operators are distinct (`+.`, `*.`) from integer operators (`+`, `*`); mixing them is a type error, which is a feature that surprises newcomers.
- The default `Stdlib` is minimal, so teams often adopt `Base` or `Core`, and mixing conventions across modules causes friction.
- Exceptions are untracked by the type system; a function can raise without its signature saying so, so document and handle them deliberately.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Input validation at the boundary: types describe parsed shape, not the validity of external content; validate decoded request and file data and reject malformed input early, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Unsafe deserialization: the `Marshal` module reconstructs arbitrary in-memory values and does not validate input, so feeding it attacker-controlled bytes can corrupt state or crash the process. Do not unmarshal untrusted data; use a schema-checked format such as JSON with explicit decoders. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Resource exhaustion: unbounded recursion or allocation driven by untrusted input can exhaust the stack or heap; bound sizes and recursion depth to address [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Escaping type safety: `Obj.magic` and unchecked C bindings defeat the type system; isolate and review them, and prefer typed bindings.
- Dependency supply chain: pin versions in the `opam` file and lock the switch; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: enable the compiler's warnings as errors (for example `-w +a-4` with `--profile release` disabled) to catch non-exhaustive matches and unused bindings, and [Semgrep](https://semgrep.dev/) ships rules that match OCaml source for common issues. The compiler's exhaustiveness checking is itself a static-analysis safeguard when warnings are not suppressed.

## Learning resources

- [The OCaml Manual](https://ocaml.org/manual/), the reference for the language and compiler.
- [Real World OCaml](https://dev.realworldocaml.org/), an applied book using Core and Dune.
- [OCaml.org tutorials](https://ocaml.org/docs), introductory and intermediate guides.

## Related pages

- [Standard ML](/languages/standard-ml.md)
- [Haskell](/languages/haskell.md)
- [Gleam](/languages/gleam.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
