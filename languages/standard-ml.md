# Standard ML

Standard ML is a statically typed functional language with a formal, mathematical definition, first standardized in 1990 and revised in 1997. It is known for sound type inference, a module system built on signatures and functors, and a precise semantics that makes it a common vehicle for teaching and for language and compiler research. It is used in education, theorem proving, compiler construction, and program analysis.

| Attribute | Value |
|---|---|
| Paradigm | Functional with imperative features; modular |
| Typing | Static, strong, inferred (Hindley-Milner with the ML module system) |
| First appeared | 1990 (revised as Standard ML '97) |
| Memory model | Automatic: garbage collection |
| Reference implementation | No single reference; [SML/NJ](https://www.smlnj.org/) and [MLton](http://mlton.org/) are the common compilers |
| Typical uses | Teaching, theorem proving, compilers, program analysis, research |
| Governance | Defined by The Definition of Standard ML (Revised); no active standards body |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [OCaml](/languages/ocaml.md), [languages index](/languages/README.md).

## Overview and history

Standard ML grew out of the metalanguage (ML) of the LCF theorem prover in the 1970s and was formalized into a standalone language in the 1980s. The first definition was published in 1990, followed by a 1997 revision commonly called Standard ML '97, together with a companion standard-library specification, the Standard ML Basis Library. The language is defined by a formal operational semantics rather than by a single reference compiler, which is unusual among general-purpose languages and makes it well suited to rigorous study.

There is no single reference implementation. [Standard ML of New Jersey (SML/NJ)](https://www.smlnj.org/) offers an interactive system and separate compilation; [MLton](http://mlton.org/) is a whole-program optimizing compiler that produces fast native code; [Poly/ML](https://www.polyml.org/) is used by the Isabelle proof assistant.

## Paradigm and type system

Standard ML is strict and primarily functional, with reference cells, arrays, and exceptions available for imperative programming. Its type system is Hindley-Milner inference, so functions are polymorphic and most types are inferred. The language is defined to be type-safe: a well-typed program does not go wrong in the sense fixed by its formal semantics.

The module system is a defining feature. Structures group definitions, signatures describe their interfaces and can hide implementation details, and functors are functions from structures to structures that support parameterized, reusable components.

```sml
signature STACK =
sig
  type 'a stack
  val empty : 'a stack
  val push  : 'a -> 'a stack -> 'a stack
  val pop   : 'a stack -> ('a * 'a stack) option
end

structure ListStack :> STACK =
struct
  type 'a stack = 'a list
  val empty = []
  fun push x s = x :: s
  fun pop []        = NONE
    | pop (x :: xs) = SOME (x, xs)
end
```

The `:>` opaque ascription above keeps `'a stack` abstract, so callers cannot treat a stack as an ordinary list.

## Toolchain and ecosystem

- Compilers and systems: SML/NJ provides an interactive top level and the Compilation Manager (`CM`); MLton compiles whole programs for speed; Poly/ML backs Isabelle.
- Build description: SML/NJ uses `.cm` files; MLton uses `.mlb` (ML Basis) files to describe a program's units.
- Standard library: the [SML Basis Library](https://smlfamily.github.io/Basis/) is the shared library specification across conforming implementations.
- Formatting: [smlfmt](https://github.com/shwestrick/smlfmt) applies a consistent layout to source files.

```bash
# MLton, whole-program compilation
mlton main.mlb
./main

# SML/NJ interactive session
sml
```

## Syntax tour

```sml
(* Datatypes and pattern matching *)
datatype 'a tree = Leaf | Node of 'a tree * 'a * 'a tree

fun insert (x, Leaf) = Node (Leaf, x, Leaf)
  | insert (x, t as Node (l, v, r)) =
      if x < v then Node (insert (x, l), v, r)
      else if x > v then Node (l, v, insert (x, r))
      else t

(* In-order traversal *)
fun toList Leaf = []
  | toList (Node (l, v, r)) = toList l @ [v] @ toList r

(* Higher-order functions *)
val sumSquares = foldl (fn (n, acc) => n * n + acc) 0

val () =
  let val t = foldl insert Leaf [5, 3, 8, 1, 4]
  in app (fn n => print (Int.toString n ^ " ")) (toList t)
  end
```

## Idioms and different approaches

- Use `datatype` and pattern matching to make illegal states unrepresentable; let the compiler's exhaustiveness check find missing cases.
- Express absence with the built-in `option` type (`NONE`, `SOME x`) rather than sentinel values.
- Hide representation behind opaque signatures so invariants hold by construction; this is the ML answer to encapsulation.
- Prefer immutable values and recursion; reach for `ref`, `Array`, and `while` only where an algorithm genuinely needs mutation.

## Design principles

Standard ML was designed around a formal definition: the language has a written mathematical semantics, and type safety is a proved property rather than a goal. The module system scales the type discipline from expressions to large program units. The emphasis on a precise, implementation-independent specification is why the language remains a reference point in programming-language research and teaching long after its last revision.

## Standard library and notable packages

The Basis Library specifies modules for numbers (`Int`, `Real`, `Word`), text (`String`, `Char`, `Substring`), collections (`List`, `Vector`, `Array`), and I/O (`TextIO`, `BinIO`). Because the ecosystem is smaller than that of newer languages, projects tend to depend on the Basis Library and implementation-provided libraries rather than a large third-party registry. MLton ships additional structures, and SML/NJ provides the SML/NJ Library with extra data structures and utilities.

## Testing and packaging

Standard ML has no single dominant test framework; projects commonly write small test structures that assert with the Basis Library and signal failure through exceptions or a nonzero exit, driven by the build system (`CM` or ML Basis files).

```sml
fun check (name, expected, actual) =
  if expected = actual then print (name ^ " ok\n")
  else raise Fail (name ^ " FAILED")

val () = check ("add", 5, 2 + 3)
```

Packaging is implementation-specific: MLton assembles a program from an `.mlb` file, and SML/NJ uses the Compilation Manager. There is no language-wide package registry comparable to those of newer ecosystems.

## Performance and concurrency

MLton performs whole-program optimization, including monomorphization and aggressive inlining, and produces native executables that are fast and compact; it is the usual choice when runtime speed matters. SML/NJ favors fast interactive development and separate compilation over peak runtime speed. The Definition does not specify a concurrency model, so parallelism and threading are implementation-specific; some systems provide threads or parallel extensions, but a portable, standard concurrency facility is not part of the language.

## Common pitfalls

- The value restriction limits polymorphism for expressions that are not syntactic values, so some definitions infer a less general type than expected; add an explicit function wrapper or annotation where needed.
- Equality types: `=` works only on types that admit equality, and attempting to compare functions or real numbers with `=` is a type error.
- Implementations differ in libraries and extensions beyond the Basis, so code that relies on SML/NJ specifics may not build under MLton and vice versa.
- Overflow on fixed-size integers raises an exception rather than wrapping, which is safer but must be anticipated.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Input validation at the boundary: type inference checks internal consistency, not the validity of external bytes or strings; validate parsed input and reject malformed data, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Deserialization of external data: Standard ML has no standard object-serialization facility, which avoids a whole class of unsafe-deserialization bugs, but implementation-specific pickling or foreign interfaces can reintroduce them; validate any reconstructed value and avoid rebuilding arbitrary types from untrusted bytes. This relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Resource exhaustion: recursion or allocation sized by untrusted input can exhaust the stack or heap; bound input sizes and recursion depth to address [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Foreign function interfaces: calling C from MLton or other systems crosses out of the type-safe core; keep such code small and reviewed.
- Dependency supply chain: because dependencies are often vendored or pinned to specific implementations, record exact versions and sources; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the primary static analysis is the type checker itself with exhaustiveness and redundancy warnings enabled; MLton's whole-program compilation additionally reports unused and unreachable code. Treat these warnings as errors in continuous integration.

## Learning resources

- The Definition of Standard ML (Revised), the formal language definition.
- [The Standard ML Basis Library](https://smlfamily.github.io/Basis/), the standard-library specification.
- [ML for the Working Programmer](https://www.cl.cam.ac.uk/~lp15/MLbook/), an applied introduction by Lawrence Paulson.

## Related pages

- [OCaml](/languages/ocaml.md)
- [Haskell](/languages/haskell.md)
- [Scheme](/languages/scheme.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
