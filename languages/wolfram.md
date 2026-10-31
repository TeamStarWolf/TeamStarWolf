# Wolfram Language

The Wolfram Language is a dynamically typed, symbolic programming language built on term rewriting, developed by Wolfram Research as the language of Mathematica, which first appeared in 1988. Everything in the language is a symbolic expression, and computation proceeds by applying transformation rules to those expressions. It is used for symbolic and numerical mathematics, technical computing, data analysis and visualization, and interactive notebooks.

| Attribute | Value |
|---|---|
| Paradigm | Symbolic, functional, rule-based term rewriting, with procedural support |
| Typing | Dynamic; one data structure, the symbolic expression |
| First appeared | 1988 (Mathematica); named the Wolfram Language in 2013 |
| Memory model | Automatic garbage collection |
| Reference implementation | [Wolfram Mathematica / Wolfram Engine](https://www.wolfram.com/language/) (proprietary) |
| Typical uses | Symbolic and numerical mathematics, technical computing, visualization |
| Governance | [Wolfram Research](https://www.wolfram.com/), proprietary |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Stephen Wolfram created Mathematica to unify symbolic mathematics, numerical computation, and visualization in one system, released in 1988. The underlying language was given the name "Wolfram Language" in 2013, emphasizing that the same language runs in Mathematica, in Wolfram Alpha, in the free-for-developers Wolfram Engine, and in the Wolfram Cloud. Its design centers on a very large set of built-in functions covering mathematics, data, and knowledge, all named in full words and sharing consistent conventions.

The system is proprietary and defined by Wolfram Research. Programs are usually developed in notebooks that mix code, results, and typeset mathematics, though the language also runs as scripts through the Wolfram Engine.

## Paradigm and type system

The language has one data structure: the symbolic expression, written `head[arg, arg, ...]`. A number, a list (`List[...]`), a function call, and an unevaluated formula are all expressions with a head. Computation is term rewriting: the evaluator repeatedly applies built-in and user-defined rules until the expression stops changing. There are no separate static types; a symbol can stand for an unassigned name, which is what makes symbolic algebra natural. Functions are defined as rewrite rules with pattern matching on structure.

```wolfram
total[prices_List, tax_: 0] := Total[prices] * (1 + tax)
total[{10, 20, 30}, 1/10]
```

Patterns such as `x_`, `x_Integer`, and `x : {__}` constrain which expressions a rule applies to, so dispatch is by structural pattern rather than by declared type.

## Toolchain and ecosystem

- Environments: the [Mathematica](https://www.wolfram.com/mathematica/) notebook front end, the command-line [Wolfram Engine](https://www.wolfram.com/engine/), and the [Wolfram Cloud](https://www.wolframcloud.com/).
- Distribution: reusable code is published as paclets through the Wolfram paclet system and functions through the [Wolfram Function Repository](https://resources.wolframcloud.com/FunctionRepository/).
- Knowledge: built-in curated data (`EntityValue`, `WolframAlpha`) and units are part of the language rather than add-ons.
- Interfacing: the Wolfram Symbolic Transfer Protocol (WSTP) connects the kernel to external programs, and `ExternalEvaluate` calls Python and other languages.

```wolfram
(* run a script with the Wolfram Engine *)
Print[Total[Range[4]^2]]   (* 30 *)
```

## Syntax tour

```wolfram
(* Everything is an expression; lists use curly braces *)
name = "world";
Print["hello, ", name]

(* Functional operations over lists *)
squares = Range[4]^2            (* {1, 4, 9, 16} *)
evens = Select[Range[10], EvenQ]

(* Map, Apply, and pure functions *)
doubled = Map[# * 2 &, {1, 2, 3}]   (* {2, 4, 6} *)
Fold[Plus, 0, {1, 2, 3}]            (* 6 *)

(* Associations are key-value structures *)
lookup = <| "a" -> 1, "b" -> 2 |>;
lookup["a"]

(* Rules and pattern-based definitions *)
area[r_] := Pi r^2
simplify = x^2 - 1 /. x -> 3        (* replacement rule -> 8 *)

(* Symbolic mathematics is built in *)
Solve[x^2 == 2, x]
Integrate[Sin[x], x]
```

## Idioms and different approaches

- Prefer functional operations (`Map`, `Apply`, `Fold`, `Select`, `Table`) and listable functions over procedural `Do` loops; vectorized operations are both idiomatic and faster.
- Use pure functions (`# &` with `Function`) and operator forms (`Select[crit]`) to compose pipelines, often with the postfix `//` and prefix `@` application operators.
- Define behavior with pattern-matched rules (`f[x_Integer] := ...`) rather than type checks inside one function body.
- Replace values and transform structure with rules and `ReplaceAll` (`/.`) rather than reassigning variables.
- Keep symbolic and numeric work distinct: use `N[...]` or machine-precision input when you want numbers, since exact arithmetic can be slow on large expressions.

## Design principles

The language is built on the idea that one uniform structure, the symbolic expression, plus term rewriting can express mathematics, data, and programs alike. Built-in functions are numerous, named in full English words, and share consistent argument conventions, so the language reads as a single coherent vocabulary. Exact arithmetic and symbolic manipulation are first-class, and the system bundles curated data and knowledge so that queries about the world are ordinary function calls. The trade-off is a large proprietary runtime rather than a small portable core.

## Standard library and notable packages

The built-in function set is the standard library, spanning algebra and calculus, linear algebra, statistics, differential equations, graph theory, image and signal processing, machine learning (`Classify`, `Predict`, `NetTrain`), visualization (`Plot`, `ListPlot`, `Graphics3D`), and curated knowledge entities. Additional functionality is distributed as paclets and through the Wolfram Function Repository rather than as third-party package registries in the usual sense.

## Testing and packaging

The language provides `VerificationTest` and the testing notebook workflow for unit tests, run with `TestReport`.

```wolfram
add[a_, b_] := a + b

report = TestReport[{
  VerificationTest[add[2, 3], 5]
}]
```

Reusable code is organized into packages (`.wl` files with `BeginPackage`/`EndPackage`) and distributed as paclets with a `PacletInfo.wl` manifest.

## Performance and concurrency

Term rewriting on large symbolic expressions can be slow, so numeric work should use machine or arbitrary-precision numbers (`N`, packed arrays) and listable functions that operate on whole arrays in compiled internal code. The `Compile` function turns a numeric function into byte code or C for tight loops. For parallelism, the language provides `ParallelMap`, `ParallelTable`, and `ParallelEvaluate`, which distribute work across local kernels or a cluster, and GPU computation through `CUDALink` and `OpenCLLink`.

## Common pitfalls

- Evaluation order: symbols evaluate eagerly, so holding or delaying evaluation (`Hold`, `:=` versus `=`, `Unevaluated`) matters when defining rules; the difference between `=` (immediate) and `:=` (delayed) assignment is a frequent trap.
- Exact versus approximate numbers: mixing exact rationals with machine reals, or doing exact arithmetic on large inputs, can be slow or surprising; convert with `N` when you want numbers.
- Pattern specificity: overlapping definitions apply in an order that depends on specificity, so an unexpectedly general rule can shadow a specific one.
- Global symbols leak between notebook cells and sessions; clear them with `Clear` or scope them with `Module` and `Block`.
- Large intermediate expressions can consume memory quickly; watch for symbolic results that grow without simplification.

## Secure coding

Wolfram Language code that imports data, evaluates strings, or calls the host system carries the main risks:

- Code injection: `ToExpression` on untrusted input parses and evaluates arbitrary Wolfram code; avoid evaluating input as code, and when you must parse, restrict it, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Operating-system command injection: `Run`, `RunProcess`, and `ExternalEvaluate` run external programs; pass arguments as a list to `RunProcess` rather than building a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Untrusted data files: `Import` and `Get` can execute code (`Get` evaluates a package; some import formats run converters); only `Get` and import files from trusted sources, which relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html). Validate the structure of imported data before use.
- Cloud deployments: an `APIFunction` or `FormFunction` deployed to the Wolfram Cloud should validate and constrain its inputs and set appropriate permissions, since it runs server-side code on request.
- Dependency provenance: review paclets before installing, and pin versions; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the built-in Code Analysis tools and the community [CodeInspector](https://github.com/WolframResearch/codeinspector) package perform static analysis and flag suspect constructs.

## Learning resources

- [Wolfram Language Documentation Center](https://reference.wolfram.com/language/), the official function reference and guides.
- [An Elementary Introduction to the Wolfram Language](https://www.wolfram.com/language/elementary-introduction/), a free book by Stephen Wolfram.
- [Wolfram Community](https://community.wolfram.com/), examples and discussion.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
